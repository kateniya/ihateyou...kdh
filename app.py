from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

KST = ZoneInfo("Asia/Seoul")
COLORS = ["#64748b", "#0284c7", "#0891b2", "#059669", "#65a30d", "#d97706", "#ea580c", "#dc2626"]
LOG = logging.getLogger("daynote")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_keys():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    key = ec.generate_private_key(ec.SECP256R1())
    print("VAPID_PRIVATE_KEY=" + b64(key.private_numbers().private_value.to_bytes(32, "big")))
    print("VAPID_PUBLIC_KEY=" + b64(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)))
    print("SESSION_SECRET=" + secrets.token_urlsafe(48))


def database(path):
    conn = sqlite3.connect(path, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with database(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, notes TEXT NOT NULL,
          location TEXT NOT NULL, start REAL NOT NULL, end REAL NOT NULL,
          all_day INTEGER NOT NULL, importance INTEGER NOT NULL CHECK(importance BETWEEN 1 AND 8),
          notify_at REAL, revision INTEGER NOT NULL DEFAULT 1,
          updated REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
          id TEXT PRIMARY KEY, data TEXT NOT NULL, created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS deliveries (
          event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
          subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
          revision INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0, next_try REAL NOT NULL DEFAULT 0,
          detail TEXT NOT NULL DEFAULT '',
          PRIMARY KEY(event_id, subscription_id, revision)
        );
        CREATE INDEX IF NOT EXISTS ix_events_notify ON events(notify_at);
        """)


def event_data(row):
    d = dict(row)
    for key in ("start", "end", "notify_at"):
        if d[key] is not None:
            d[key] = datetime.fromtimestamp(d[key], KST).isoformat()
    d["all_day"] = bool(d["all_day"])
    return d


def push_one(subscription, payload, cfg):
    from pywebpush import webpush
    webpush(subscription_info=subscription, data=json.dumps(payload, ensure_ascii=False),
            vapid_private_key=cfg["VAPID_PRIVATE_KEY"],
            vapid_claims={"sub": cfg["VAPID_SUBJECT"]}, ttl=86400,
            headers={"Urgency": "high"}, timeout=12)


def dispatch_due(cfg):
    now = time.time()
    path = cfg["DB_PATH"]
    with database(path) as db:
        db.execute("""INSERT OR IGNORE INTO deliveries(event_id,subscription_id,revision)
          SELECT e.id,s.id,e.revision FROM events e CROSS JOIN subscriptions s
          WHERE e.notify_at<=? AND e.notify_at>=?""", (now, now - 86400))
        jobs = db.execute("""SELECT d.*,e.title,e.importance,e.notify_at,s.data
          FROM deliveries d JOIN events e ON e.id=d.event_id AND e.revision=d.revision
          JOIN subscriptions s ON s.id=d.subscription_id
          WHERE d.status IN ('pending','retry','sending') AND d.next_try<=?
          AND e.notify_at<=? AND d.attempts<5 ORDER BY e.notify_at LIMIT 24""", (now, now)).fetchall()
        db.execute("""UPDATE deliveries SET status='failed',detail='최대 재시도 횟수 초과'
          WHERE status='sending' AND next_try<=? AND attempts>=5""", (now,))
    for job in jobs:
        key = (job["event_id"], job["subscription_id"], job["revision"])
        with database(path) as db:
            valid = db.execute("SELECT 1 FROM events WHERE id=? AND revision=?", (key[0], key[2])).fetchone()
            if not valid:
                continue
            if job["notify_at"] < time.time() - 86400:
                db.execute("UPDATE deliveries SET status='expired',detail='24시간 초과' WHERE event_id=? AND subscription_id=? AND revision=?", key)
                continue
            claimed = db.execute("""UPDATE deliveries SET status='sending',attempts=attempts+1,next_try=?
               WHERE event_id=? AND subscription_id=? AND revision=? AND next_try<=?
               AND status IN ('pending','retry','sending')""", (time.time() + 300, *key, time.time())).rowcount
        if not claimed:
            continue
        try:
            late = " · 지연 알림" if time.time() - job["notify_at"] > 300 else ""
            push_one(json.loads(job["data"]), {
                "title": job["title"], "body": f"중요도 {job['importance']}/8{late}",
                "tag": "event-" + job["event_id"], "url": "/?event=" + job["event_id"]}, cfg)
            status, detail = "accepted", "푸시 서비스 접수 완료 (기기 수신 확인 아님)"
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = getattr(response, "status_code", None)
            if code in (404, 410):
                with database(path) as db:
                    db.execute("DELETE FROM subscriptions WHERE id=?", (key[1],))
                continue
            status = "failed" if job["attempts"] + 1 >= 5 else "retry"
            detail = f"전송 오류 HTTP {code or '-'} ({type(exc).__name__})"
        with database(path) as db:
            db.execute("""UPDATE deliveries SET status=?,detail=?,next_try=?
                WHERE event_id=? AND subscription_id=? AND revision=?""",
                       (status, detail, time.time() + min(900, 30 * 2 ** job["attempts"]), *key))


SW = r"""
self.addEventListener('install', event => { self.skipWaiting(); });
self.addEventListener('activate', event => { event.waitUntil(self.clients.claim()); });
self.addEventListener('push', event => {
  let p = {title:'DAYNOTE', body:'일정을 확인하세요.', url:'/'};
  try { if(event.data) p = {...p, ...event.data.json()}; } catch(e) {}
  event.waitUntil(self.registration.showNotification(p.title, {
    body:p.body, icon:'/icon.png', badge:'/icon.png', tag:p.tag || 'daynote-test',
    data:{url:p.url || '/'}, timestamp:Date.now()
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || '/', self.location.origin);
  if(target.origin !== self.location.origin) return;
  event.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(async windows => {
    for(const w of windows) {
      if(new URL(w.url).origin === target.origin) { await w.navigate(target.href); return w.focus(); }
    }
    return self.clients.openWindow(target.href);
  }));
});
// 일정/비밀번호/개인 API 응답은 오프라인 캐시에 저장하지 않습니다.
self.addEventListener('fetch', event => {});
"""

MOBILE = r'''<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#155e52"><meta name="apple-mobile-web-app-capable" content="yes">
<link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/icon.png"><title>DAYNOTE · 나의 캘린더</title>
<style>
:root{--ink:#172b29;--muted:#546962;--green:#155e52;--line:#dde5df;--bg:#f5f7f2}*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,'Apple SD Gothic Neo',sans-serif}
button,input,textarea,select{font:inherit}button,a.button{cursor:pointer;border:1px solid var(--line);border-radius:12px;padding:10px 15px;background:white;color:var(--ink);text-decoration:none}
button:disabled{opacity:.5;cursor:wait}.primary{background:var(--green);color:white;border-color:var(--green)}.danger{color:#b91c1c}.muted{color:var(--muted);font-size:13px}
main{max-width:1180px;margin:auto;padding:28px 20px 80px}.brand{letter-spacing:.16em;font-weight:850;font-size:20px}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:24px}
h1{font-size:30px;letter-spacing:-1px;margin:4px 0}h2{font-size:19px;margin:0 0 14px}.layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:20px}.card{background:white;border:1px solid var(--line);border-radius:20px;padding:20px}
.toolbar,.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.toolbar{justify-content:space-between;margin-bottom:18px}.week,.grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr))}.week{text-align:center;color:var(--muted);font-size:12px;margin-bottom:8px}.grid{border-top:1px solid var(--line);border-left:1px solid var(--line)}
.day{min-height:100px;border:0;border-bottom:1px solid var(--line);border-right:1px solid var(--line);border-radius:0;padding:6px;text-align:left;overflow:hidden;cursor:pointer}.day.other{background:#f7f8f6;color:#8a9690}.day.selected{background:#e7f3ed}.num{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;font-size:12px}.today .num{background:var(--green);color:white}.day:nth-child(7n+1) .num{color:#b91c1c}.today:nth-child(7n+1) .num{color:white}
.chip{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-left:3px solid var(--green);background:#f1f5f3;font-size:11px;padding:2px 3px;margin-top:3px;border-radius:4px}.entry{border:1px solid var(--line);border-left:5px solid var(--green);border-radius:12px;padding:13px;margin:10px 0;cursor:pointer}.entry strong{display:block;overflow-wrap:anywhere}.entry small{color:var(--muted)}
input,textarea,select{width:100%;border:1px solid #b7c5bd;background:white;color:var(--ink);border-radius:9px;padding:11px;min-width:0}input[type=checkbox]{width:auto}label{display:block;font-size:13px;font-weight:600;margin:12px 0 5px}textarea{resize:vertical;min-height:80px}.fields{display:grid;grid-template-columns:1fr 1fr;gap:12px}.notice{font-size:13px;padding:12px;background:#edf5f0;border-radius:12px;margin:14px 0}.auth{max-width:420px;margin:12vh auto}aside .card{margin-bottom:16px}.stack{display:grid;gap:8px}
#message{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#172b29;color:white;border-radius:12px;padding:12px 20px;z-index:20;max-width:90vw;box-shadow:0 5px 30px #0002}dialog{border:1px solid var(--line);border-radius:20px;max-width:560px;width:calc(100% - 24px);max-height:90dvh;overflow:auto;padding:24px}dialog::backdrop{background:#10241b77}.hidden,[hidden]{display:none!important}.stats{display:flex;gap:16px;margin-bottom:18px}.stats b{font-size:24px;display:block}.empty{padding:20px 0;color:var(--muted)}:focus-visible{outline:3px solid #d97706;outline-offset:2px}
@media(max-width:850px){.layout{grid-template-columns:1fr}aside{display:grid;grid-template-columns:1fr 1fr;gap:12px}.day{min-height:85px}}
@media(max-width:520px){main{padding:18px 10px 60px}.card{padding:13px;border-radius:15px}.top{align-items:flex-start}.brand{font-size:17px}h1{font-size:24px}.day{min-height:76px;padding:3px}.chip{font-size:9px;padding:1px}.fields{grid-template-columns:1fr}aside{display:block}button{padding:9px 11px}.toolbar{gap:12px}}
</style></head><body><main>
<section id="login" class="card auth"><div class="brand">DAYNOTE</div><h1>나의 하루를<br>차분하게 정리하세요.</h1><p class="muted">개인 캘린더 · 중요도 1–8 · 예약 웹 푸시</p>
<form id="loginForm"><label for="password">개인 비밀번호</label><input id="password" type="password" autocomplete="current-password" required><p><button class="primary" type="submit">내 캘린더 열기</button></p></form><p id="loginError" role="alert" class="danger"></p></section>
<section id="app" hidden><header class="top"><div><div class="brand">DAYNOTE</div><p class="muted" style="margin:4px 0">작은 계획이 만드는, 좋은 하루 · 한국 시간</p></div><div class="row"><button id="new" class="primary">＋ 일정</button><button id="logout">로그아웃</button></div></header>
<div class="layout"><section class="card"><div class="toolbar"><h1 id="monthTitle"></h1><div class="row"><button id="prev" aria-label="이전 달">‹</button><button id="today">오늘</button><button id="next" aria-label="다음 달">›</button></div></div>
<div class="row" style="margin-bottom:16px"><input id="search" placeholder="제목 · 장소 · 메모 검색" aria-label="일정 검색" style="flex:1"><select id="minImportance" aria-label="중요도 필터" style="width:auto"><option value="1">모든 중요도</option><option value="5">중요도 5 이상</option><option value="8">중요도 8</option></select></div>
<div class="week"><span>일</span><span>월</span><span>화</span><span>수</span><span>목</span><span>금</span><span>토</span></div><div class="grid" id="grid"></div>
<div class="toolbar" style="margin-top:22px"><h2 id="selectedTitle"></h2><span class="muted">일정을 눌러 수정</span></div><div id="agenda"></div>
</section><aside><section class="card"><h2>이번 달 한눈에</h2><div class="stats"><div><b id="count">0</b><span class="muted">일정</span></div><div><b id="importantCount">0</b><span class="muted">중요도 7–8</span></div></div><p class="muted">1은 낮음, 8은 가장 높음.<br>여러 날 일정은 해당 날짜마다 표시됩니다.</p><button id="backup">전체 일정 JSON 백업</button></section>
<section class="card"><h2>내 스마트폰 알림</h2><p id="pushState" class="muted">확인 중…</p><div class="stack"><button id="enablePush" class="primary">이 기기 알림 켜기</button><button id="testPush">테스트 알림</button><button id="disablePush">이 기기 알림 끄기</button><button id="revokeAll" class="danger">모든 기기 해제</button></div><div class="notice">iPhone: Safari → 공유 → 홈 화면에 추가 → 추가한 아이콘으로 열고 알림을 켜세요.</div><p class="muted">앱을 닫아도 서버가 전송합니다. 기기의 알림 권한·집중 모드·인터넷 상태에 따라 도착이 지연될 수 있습니다. 잠금 화면에 일정 제목이 표시됩니다.</p><p id="serverState" class="muted"></p><details><summary>최근 전송 기록</summary><div id="deliveryLog" class="muted"></div></details></section></aside></div></section>
<dialog id="editor"><form id="eventForm"><h2 id="editorTitle">새 일정</h2><input id="eventId" type="hidden"><input id="revision" type="hidden"><label for="title">일정 제목 *</label><input id="title" required maxlength="120" placeholder="예: 인공지능 프로젝트 발표"><div class="fields"><div><label for="start">시작 (한국 시간) *</label><input id="start" type="datetime-local" required></div><div><label for="end">종료 (한국 시간) *</label><input id="end" type="datetime-local" required></div></div>
<label><input id="allDay" type="checkbox"> 종일 일정 (종료 날짜까지 포함)</label><div class="fields"><div><label for="importance">중요도 *</label><select id="importance"></select></div><div><label for="location">장소</label><input id="location" maxlength="200" placeholder="예: 도서관"></div></div><label for="notes">메모</label><textarea id="notes" maxlength="4000"></textarea><label><input id="notifyEnabled" type="checkbox"> 지정한 시각에 푸시 알림</label><input id="notifyAt" type="datetime-local" aria-label="알림 날짜와 시각"><p class="muted">한국 시간 기준. 과거 알림은 새로 예약할 수 없습니다.<br>종일 일정의 시간은 저장할 때 00:00~다음 날 00:00으로 정리됩니다.</p>
<div class="row" style="justify-content:space-between;margin-top:20px"><button id="delete" type="button" class="danger">삭제</button><div class="row"><button id="cancel" type="button">닫기</button><button class="primary" id="save" type="submit">저장</button></div></div></form></dialog><div id="message" role="status" hidden></div>
</main><script>
const $=id=>document.getElementById(id), colors=['#64748b','#0284c7','#0891b2','#059669','#65a30d','#d97706','#ea580c','#dc2626'];
let events=[], selected=kdate(new Date()), month=selected.slice(0,7), config={}, toastTimer;
function kdate(d){return new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(d)}
function localInput(iso){return iso?iso.slice(0,16):''}
function shiftDay(s,n){return new Date(Date.parse(s+'T00:00:00Z')+n*86400000).toISOString().slice(0,10)}
function toast(s){$('message').textContent=s;$('message').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('message').hidden=true,6000)}
async function api(path,method='GET',body){const r=await fetch('/api'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});let d;try{d=await r.json()}catch{throw Error('서버 응답을 읽지 못했습니다.')};if(!r.ok){if(r.status===401){$('app').hidden=true;$('login').hidden=false;}throw Error(typeof d.detail==='string'?d.detail:'입력 값을 확인하세요.')}return d}
function safe(handler){return async e=>{try{await handler(e)}catch(err){toast(err.message)}}}
function filtered(){const q=$('search').value.toLowerCase(), m=+$('minImportance').value;return events.filter(e=>e.importance>=m&&[e.title,e.notes,e.location].join(' ').toLowerCase().includes(q))}
function onDay(e,date){const a=Date.parse(date+'T00:00:00+09:00'), b=a+86400000;return Date.parse(e.start)<b&&Date.parse(e.end)>a}
function render(){let [y,m]=month.split('-').map(Number);$('monthTitle').textContent=`${y}년 ${m}월`;$('selectedTitle').textContent=selected+' 일정';const list=filtered();$('grid').replaceChildren();let first=month+'-01', start=shiftDay(first,-new Date(first+'T00:00:00+09:00').getUTCDay());
// getUTCDay at KST midnight would be the previous UTC day; use UTC noon for weekday.
start=shiftDay(first,-new Date(first+'T12:00:00Z').getUTCDay());
for(let i=0;i<42;i++){let date=shiftDay(start,i), cell=document.createElement('button');cell.className='day'+(date.slice(0,7)!==month?' other':'')+(date===selected?' selected':'')+(date===kdate(new Date())?' today':'');cell.setAttribute('aria-label',date+' 일정 보기');let n=document.createElement('span');n.className='num';n.textContent=Number(date.slice(-2));cell.append(n);const dayEvents=list.filter(e=>onDay(e,date));dayEvents.slice(0,3).forEach(e=>{let s=document.createElement('span');s.className='chip';s.style.borderColor=colors[e.importance-1];s.textContent=e.title;cell.append(s)});if(dayEvents.length>3){let s=document.createElement('span');s.className='muted';s.textContent='+'+(dayEvents.length-3);cell.append(s)}cell.onclick=()=>{selected=date;render()};$('grid').append(cell)}
$('agenda').replaceChildren();let daily=list.filter(e=>onDay(e,selected));if(!daily.length){let p=document.createElement('p');p.className='empty';p.textContent='등록된 일정이 없습니다. ＋ 일정으로 하루를 채워보세요.';$('agenda').append(p)}daily.forEach(e=>{let box=document.createElement('div');box.className='entry';box.tabIndex=0;box.setAttribute('role','button');box.style.borderColor=colors[e.importance-1];let t=document.createElement('strong');t.textContent=e.title;let s=document.createElement('small');s.textContent=(e.all_day?'종일':e.start.slice(11,16)+'–'+e.end.slice(11,16))+' · 중요도 '+e.importance+(e.location?' · '+e.location:'');box.append(t,s);if(e.notify_at){let p=document.createElement('div');p.className='muted';p.textContent='알림 '+e.notify_at.slice(0,16).replace('T',' ');box.append(p)}box.onclick=()=>edit(e);box.onkeydown=ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();edit(e)}};$('agenda').append(box)});
const nextMonth=new Date(Date.UTC(y,m,1)).toISOString().slice(0,10), ms=Date.parse(first+'T00:00:00+09:00'),me=Date.parse(nextMonth+'T00:00:00+09:00');let all=events.filter(e=>Date.parse(e.start)<me&&Date.parse(e.end)>ms);$('count').textContent=all.length;$('importantCount').textContent=all.filter(e=>e.importance>=7).length}
async function refresh(){events=await api('/events');render();let s=await api('/status');$('serverState').textContent=`등록 기기 ${s.devices}개 · 최근 전송 접수 ${s.accepted}건 · 실패 ${s.failed}건`;$('deliveryLog').replaceChildren();s.recent.forEach(r=>{let p=document.createElement('p');p.textContent=r.title+' · '+r.status+' · '+r.detail;$('deliveryLog').append(p)});await pushState()}
async function enter(){config=await api('/config');$('login').hidden=true;$('app').hidden=false;await refresh();let id=new URLSearchParams(location.search).get('event');let e=events.find(x=>x.id===id);if(e){selected=e.start.slice(0,10);month=selected.slice(0,7);render();edit(e);history.replaceState(null,'','/')}}
$('loginForm').onsubmit=async ev=>{ev.preventDefault();try{await api('/login','POST',{password:$('password').value});$('password').value='';$('loginError').textContent='';await enter()}catch(e){$('loginError').textContent=e.message}};
$('logout').onclick=safe(async()=>{await api('/logout','POST',{});location.reload()});
for(let i=1;i<=8;i++){let o=document.createElement('option');o.value=i;o.textContent=i+(i===1?' · 낮음':i===8?' · 가장 높음':'');$('importance').append(o)}
function edit(e){$('eventForm').reset();$('eventId').value=e?.id||'';$('revision').value=e?.revision||'';$('editorTitle').textContent=e?'일정 수정':'새 일정';$('title').value=e?.title||'';$('start').value=e?localInput(e.start):selected+'T09:00';$('end').value=e?(e.all_day?shiftDay(e.end.slice(0,10),-1)+'T23:59':localInput(e.end)):selected+'T10:00';$('allDay').checked=e?.all_day||false;$('importance').value=e?.importance||4;$('location').value=e?.location||'';$('notes').value=e?.notes||'';$('notifyEnabled').checked=!!e?.notify_at;$('notifyAt').value=e?.notify_at?localInput(e.notify_at):selected+'T08:50';$('notifyAt').disabled=!$('notifyEnabled').checked;$('delete').hidden=!e;$('editor').showModal()}
$('new').onclick=()=>edit(null);$('cancel').onclick=()=>$('editor').close();$('notifyEnabled').onchange=()=>$('notifyAt').disabled=!$('notifyEnabled').checked;
$('eventForm').onsubmit=safe(async ev=>{ev.preventDefault();const id=$('eventId').value;let start=$('start').value,end=$('end').value;if($('allDay').checked){start=start.slice(0,10)+'T00:00';end=shiftDay(end.slice(0,10),1)+'T00:00'}const body={title:$('title').value,notes:$('notes').value,location:$('location').value,start:start+':00+09:00',end:end+':00+09:00',all_day:$('allDay').checked,importance:+$('importance').value,notify_at:$('notifyEnabled').checked?($('notifyAt').value?$('notifyAt').value+':00+09:00':null):null,revision:id?+$('revision').value:null};if($('notifyEnabled').checked&&!body.notify_at)throw Error('알림 시각을 입력하세요.');$('save').disabled=true;try{await api('/events'+(id?'/'+id:''),id?'PUT':'POST',body);$('editor').close();selected=start.slice(0,10);month=selected.slice(0,7);await refresh();toast('일정을 저장했습니다.')}finally{$('save').disabled=false}});
$('delete').onclick=safe(async()=>{if(!confirm('이 일정을 삭제할까요?'))return;await api('/events/'+$('eventId').value,'DELETE');$('editor').close();await refresh();toast('삭제했습니다.')});
function move(n){let [y,m]=month.split('-').map(Number);month=new Date(Date.UTC(y,m-1+n,1)).toISOString().slice(0,7);selected=month+'-01';render()}
$('prev').onclick=()=>move(-1);$('next').onclick=()=>move(1);$('today').onclick=()=>{selected=kdate(new Date());month=selected.slice(0,7);render()};$('search').oninput=render;$('minImportance').onchange=render;
function supported(){return window.isSecureContext&&'serviceWorker'in navigator&&'PushManager'in window&&'Notification'in window}
async function pushState(){if(!supported()){$('pushState').textContent='웹 푸시를 지원하는 HTTPS 브라우저 / 홈 화면 앱으로 열어주세요.';return}let reg=await navigator.serviceWorker.register('/sw.js',{scope:'/'});let sub=await reg.pushManager.getSubscription();let registered=sub?await api('/subscription-status','POST',{endpoint:sub.endpoint}):{registered:false};$('pushState').textContent=Notification.permission==='denied'?'알림이 차단되었습니다. 기기/브라우저 설정에서 허용하세요.':registered.registered?'이 기기의 알림이 켜져 있습니다.':'이 기기는 아직 등록되지 않았습니다.'}
function keyBytes(s){s=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}
$('enablePush').onclick=safe(async()=>{if(!supported())throw Error('iPhone은 홈 화면에 추가한 앱에서 열어주세요. 지원 브라우저와 HTTPS가 필요합니다.');const permission=await Notification.requestPermission();if(permission!=='granted')throw Error('알림 권한을 허용해야 합니다.');await navigator.serviceWorker.register('/sw.js',{scope:'/'});const reg=await navigator.serviceWorker.ready;let sub=await reg.pushManager.getSubscription();if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:keyBytes(config.public_key)});await api('/subscriptions','POST',sub.toJSON());await refresh();toast('이 기기를 등록했습니다. 테스트 알림을 확인하세요.')});
$('disablePush').onclick=safe(async()=>{if(!supported())return;const reg=await navigator.serviceWorker.getRegistration();const sub=await reg?.pushManager.getSubscription();if(sub){await api('/subscriptions','DELETE',{endpoint:sub.endpoint});await sub.unsubscribe()}await refresh();toast('이 기기의 알림을 껐습니다.')});
$('testPush').onclick=safe(async()=>{if(!supported())throw Error('웹 푸시를 지원하지 않습니다.');const reg=await navigator.serviceWorker.getRegistration();const sub=await reg?.pushManager.getSubscription();if(!sub)throw Error('먼저 이 기기 알림을 켜세요.');await api('/test','POST',{endpoint:sub.endpoint});toast('푸시 서비스에 접수했습니다. 기기 알림을 확인하세요.')});
$('revokeAll').onclick=safe(async()=>{if(!confirm('모든 기기의 알림 등록을 해제할까요? 필요한 기기는 다시 켜야 합니다.'))return;await api('/subscriptions/all','DELETE');await refresh();toast('모든 기기 등록을 해제했습니다.')});
$('backup').onclick=()=>{const b=new Blob([JSON.stringify({format:'daynote-v1',timezone:'Asia/Seoul',events},null,2)],{type:'application/json'}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='daynote-backup.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)};
setInterval(()=>{if(!$('app').hidden&&!document.hidden&&!$('editor').open)refresh().catch(e=>toast(e.message))},60000);
enter().catch(e=>{if(e.message!=='로그인이 필요합니다.')$('loginError').textContent=e.message});
</script></body></html>'''


def create_app():
    from contextlib import asynccontextmanager
    from fastapi import FastAPI, Request, HTTPException, Depends
    from fastapi.responses import HTMLResponse, Response, JSONResponse
    from itsdangerous import URLSafeTimedSerializer, BadSignature
    from pydantic import BaseModel, Field, ConfigDict
    # FastAPI resolves endpoint annotations against module globals.
    globals().update(Request=Request)
    required = ["PUBLIC_BASE_URL", "APP_PASSWORD", "SESSION_SECRET", "VAPID_PRIVATE_KEY", "VAPID_PUBLIC_KEY", "VAPID_SUBJECT", "DB_PATH"]
    cfg = {k: os.environ.get(k, "").strip() for k in required}
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        raise RuntimeError("필수 환경변수 누락: " + ", ".join(missing) + ". app.py 맨 위 배포 안내를 읽어주세요.")
    cfg["PUBLIC_BASE_URL"] = cfg["PUBLIC_BASE_URL"].rstrip("/")
    base = urlparse(cfg["PUBLIC_BASE_URL"])
    if base.scheme != "https" or not base.netloc or base.path or base.query or base.fragment or base.username:
        raise RuntimeError("PUBLIC_BASE_URL은 경로 없는 HTTPS 원본 주소여야 합니다.")
    if len(cfg["APP_PASSWORD"]) < 16 or len(cfg["SESSION_SECRET"]) < 32:
        raise RuntimeError("APP_PASSWORD는 16자 이상, SESSION_SECRET은 32자 이상이어야 합니다.")
    if not cfg["VAPID_SUBJECT"].startswith("mailto:"):
        raise RuntimeError("VAPID_SUBJECT에는 mailto:실제이메일주소를 지정하세요.")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    try:
        raw = base64.urlsafe_b64decode(cfg["VAPID_PRIVATE_KEY"] + "=" * (-len(cfg["VAPID_PRIVATE_KEY"]) % 4))
        key = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
        public = b64(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        if public != cfg["VAPID_PUBLIC_KEY"]:
            raise ValueError()
    except Exception:
        raise RuntimeError("VAPID 키 쌍이 올바르지 않습니다. --generate-keys로 생성한 한 쌍을 사용하세요.") from None
    init_db(cfg["DB_PATH"])
    signer = URLSafeTimedSerializer(cfg["SESSION_SECRET"], salt="daynote-auth-v1")
    # Password changes invalidate previously issued browser cookies and Streamlit tokens.
    auth_id = hmac.new(cfg["SESSION_SECRET"].encode(), cfg["APP_PASSWORD"].encode(), hashlib.sha256).hexdigest()
    stop = threading.Event()
    state = {"tick": 0.0, "error": False}

    def worker():
        while not stop.is_set():
            try:
                dispatch_due(cfg)
                state.update(tick=time.time(), error=False)
            except Exception as exc:
                LOG.error("알림 루프 오류: %s", type(exc).__name__)
                state["error"] = True
            stop.wait(15)

    @asynccontextmanager
    async def lifespan(app):
        thread = threading.Thread(target=worker, name="daynote-scheduler", daemon=True)
        thread.start()
        yield
        stop.set()
        thread.join(timeout=20)

    app = FastAPI(title="DAYNOTE", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    limits = {}
    rate_lock = threading.Lock()

    def rate(request, purpose, count, window):
        # Do not trust arbitrary X-Forwarded-For headers. Proxy IP aggregation is conservative.
        ip = request.client.host if request.client else "unknown"
        key = (ip, purpose)
        with rate_lock:
            now = time.monotonic()
            if len(limits) > 2000:
                for k in list(limits):
                    if limits[k][1] < now:
                        limits.pop(k, None)
                if len(limits) > 2000:
                    raise HTTPException(429, "잠시 후 다시 시도하세요.")
            n, until = limits.get(key, (0, now + window))
            if now > until:
                n, until = 0, now + window
            if n >= count:
                raise HTTPException(429, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
            limits[key] = (n + 1, until)

    def auth(request: Request):
        header = request.headers.get("authorization", "")
        bearer = header.startswith("Bearer ")
        token = header[7:] if bearer else request.cookies.get("daynote", "")
        try:
            data = signer.loads(token, max_age=30 * 86400)
            if not hmac.compare_digest(str(data.get("owner", "")), auth_id):
                raise BadSignature("invalid")
        except BadSignature:
            raise HTTPException(401, "로그인이 필요합니다.") from None
        if not bearer and request.method not in ("GET", "HEAD"):
            if request.headers.get("origin") != cfg["PUBLIC_BASE_URL"]:
                raise HTTPException(403, "허용되지 않은 요청 출처입니다.")
        return True

    @app.middleware("http")
    async def secure_headers(request, call_next):
        if request.method in ("POST", "PUT", "DELETE"):
            # Stop oversized chunked as well as Content-Length requests before parsing.
            body = bytearray()
            async for part in request.stream():
                body.extend(part)
                if len(body) > 32768:
                    return JSONResponse({"detail": "요청 크기 초과"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        # Inline app code is fixed; all user text is inserted with textContent, never innerHTML.
        js = MOBILE.split("<script>", 1)[1].split("</script>", 1)[0]
        digest = base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'sha256-" + digest + "'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
            "worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return response

    class EventInput(BaseModel):
        model_config = ConfigDict(extra="forbid")
        title: str = Field(min_length=1, max_length=120)
        notes: str = Field(default="", max_length=4000)
        location: str = Field(default="", max_length=200)
        start: datetime
        end: datetime
        all_day: bool = False
        importance: int = Field(ge=1, le=8, strict=True)
        notify_at: datetime | None = None
        revision: int | None = None
    globals()["EventInput"] = EventInput

    @app.get("/", response_class=HTMLResponse)
    def home():
        return MOBILE

    @app.get("/sw.js")
    def service_worker():
        return Response(SW, media_type="application/javascript", headers={"Service-Worker-Allowed": "/"})

    @app.get("/manifest.webmanifest")
    def manifest():
        return JSONResponse({"id": "/", "name": "DAYNOTE 나의 캘린더", "short_name": "DAYNOTE", "lang": "ko",
            "start_url": "/", "scope": "/", "display": "standalone", "background_color": "#f5f7f2", "theme_color": "#155e52",
            "icons": [{"src": "/icon.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
                      {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"}]}, media_type="application/manifest+json")

    def icon(size):
        from PIL import Image, ImageDraw
        im = Image.new("RGB", (size, size), "#155e52")
        d = ImageDraw.Draw(im)
        d.rounded_rectangle((size*.22,size*.25,size*.78,size*.78),radius=size*.06,fill="#f5f7f2")
        d.line((size*.22,size*.40,size*.78,size*.40),fill="#155e52",width=max(2,size//30))
        for x in (.35,.65):
            d.line((size*x,size*.2,size*x,size*.32),fill="#d2df8a",width=size//20)
        d.ellipse((size*.4,size*.5,size*.6,size*.7),fill="#155e52")
        b = io.BytesIO(); im.save(b, format="PNG")
        return Response(b.getvalue(), media_type="image/png")

    @app.get("/icon.png")
    def small_icon():
        return icon(192)

    @app.get("/icon-512.png")
    def big_icon():
        return icon(512)

    @app.get("/health")
    def health():
        healthy = state["tick"] > time.time() - 600 and not state["error"]
        return JSONResponse({"ok": healthy}, status_code=200 if healthy else 503)

    @app.post("/api/login")
    def login(body: dict, request: Request):
        rate(request, "login", 10, 600)
        origin = request.headers.get("origin")
        if origin and origin != cfg["PUBLIC_BASE_URL"]:
            raise HTTPException(403, "허용되지 않은 요청 출처입니다.")
        password = body.get("password", "")
        if not isinstance(password, str) or not hmac.compare_digest(password.encode(), cfg["APP_PASSWORD"].encode()):
            raise HTTPException(401, "비밀번호가 일치하지 않습니다.")
        token = signer.dumps({"owner": auth_id})
        response = JSONResponse({"token": token})
        response.set_cookie("daynote", token, max_age=30 * 86400, httponly=True, secure=True, samesite="strict", path="/")
        return response

    @app.post("/api/logout", dependencies=[Depends(auth)])
    def logout():
        r = JSONResponse({"ok": True}); r.delete_cookie("daynote", path="/")
        return r

    @app.get("/api/config", dependencies=[Depends(auth)])
    def config():
        return {"public_key": cfg["VAPID_PUBLIC_KEY"], "timezone": "Asia/Seoul"}

    @app.get("/api/events", dependencies=[Depends(auth)])
    def events():
        with database(cfg["DB_PATH"]) as db:
            return [event_data(r) for r in db.execute("SELECT * FROM events ORDER BY start,importance DESC")]

    def save_event(body, event_id=None):
        values = body.model_dump()
        title = values["title"].strip()
        if not title:
            raise HTTPException(422, "일정 제목을 입력하세요.")
        for k in ("start", "end", "notify_at"):
            dt = values[k]
            if dt is not None:
                if dt.utcoffset() is None:
                    raise HTTPException(422, "날짜에는 시간대가 필요합니다.")
                if not 1970 <= dt.year <= 2100:
                    raise HTTPException(422, "날짜 범위는 1970~2100년입니다.")
                values[k] = dt.timestamp()
        if values["end"] <= values["start"]:
            raise HTTPException(422, "종료 시각은 시작 시각보다 뒤여야 합니다.")
        if values["all_day"]:
            for k in ("start", "end"):
                dt = datetime.fromtimestamp(values[k], KST)
                if (dt.hour, dt.minute, dt.second, dt.microsecond) != (0, 0, 0, 0):
                    raise HTTPException(422, "종일 일정은 00:00~마지막 날짜 다음 날 00:00으로 저장하세요.")
        with database(cfg["DB_PATH"]) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone() if event_id else None
            if event_id and not old:
                raise HTTPException(404, "일정을 찾을 수 없습니다.")
            if old and values["revision"] != old["revision"]:
                raise HTTPException(409, "다른 화면에서 수정되었습니다. 새로고침 후 다시 수정하세요.")
            notify = values["notify_at"]
            if notify is not None and notify <= time.time():
                raise HTTPException(422, "알림은 미래 시각으로 설정하거나 알림 체크를 해제하세요.")
            event_id = event_id or secrets.token_hex(16)
            revision = old["revision"] + 1 if old else 1
            db.execute("""INSERT INTO events(id,title,notes,location,start,end,all_day,importance,notify_at,revision,updated)
               VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
               title=excluded.title,notes=excluded.notes,location=excluded.location,start=excluded.start,
               end=excluded.end,all_day=excluded.all_day,importance=excluded.importance,
               notify_at=excluded.notify_at,revision=excluded.revision,updated=excluded.updated""",
               (event_id,title,values["notes"],values["location"],values["start"],values["end"],int(values["all_day"]),values["importance"],notify,revision,time.time()))
            db.execute("DELETE FROM deliveries WHERE event_id=?", (event_id,))
        return {"id": event_id}

    @app.post("/api/events", dependencies=[Depends(auth)])
    def add_event(body: EventInput):
        return save_event(body)

    @app.put("/api/events/{event_id}", dependencies=[Depends(auth)])
    def update_event(event_id: str, body: EventInput):
        return save_event(body, event_id)

    @app.delete("/api/events/{event_id}", dependencies=[Depends(auth)])
    def delete_event(event_id: str):
        with database(cfg["DB_PATH"]) as db:
            if not db.execute("DELETE FROM events WHERE id=?", (event_id,)).rowcount:
                raise HTTPException(404, "일정을 찾을 수 없습니다.")
        return {"ok": True}

    def endpoint_id(body):
        endpoint = body.get("endpoint", "")
        if not isinstance(endpoint, str) or len(endpoint) > 4096:
            raise HTTPException(422, "유효하지 않은 푸시 주소입니다.")
        try:
            parsed = urlparse(endpoint); host = (parsed.hostname or "").lower()
            allowed = host == "fcm.googleapis.com" or any(host == suffix or host.endswith("." + suffix)
                for suffix in ("push.services.mozilla.com", "push.apple.com", "notify.windows.com"))
            valid = parsed.scheme == "https" and parsed.port in (None, 443) and not parsed.username and not parsed.password and allowed
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(422, "지원하지 않는 푸시 서비스 주소입니다. Chrome/Safari/Firefox/Edge를 사용하세요.")
        return hashlib.sha256(endpoint.encode()).hexdigest()

    @app.post("/api/subscriptions", dependencies=[Depends(auth)])
    def subscribe(body: dict):
        sid = endpoint_id(body)
        keys = body.get("keys", {})
        if not isinstance(keys, dict):
            raise HTTPException(422, "푸시 암호화 키가 없습니다.")
        for k, length in (("p256dh", 65), ("auth", 16)):
            try:
                value = keys[k]
                if not isinstance(value, str) or len(value) > 200:
                    raise ValueError()
                raw_key = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                if len(raw_key) != length:
                    raise ValueError()
                if k == "p256dh":
                    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_key)
            except Exception:
                raise HTTPException(422, "푸시 암호화 키가 올바르지 않습니다.") from None
        clean = {"endpoint": body["endpoint"], "keys": {k: keys[k] for k in ("p256dh", "auth")}}
        with database(cfg["DB_PATH"]) as db:
            exists = db.execute("SELECT 1 FROM subscriptions WHERE id=?", (sid,)).fetchone()
            if not exists and db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] >= 20:
                raise HTTPException(422, "개인 기기는 최대 20개까지 등록할 수 있습니다.")
            db.execute("INSERT INTO subscriptions VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (sid, json.dumps(clean), time.time()))
        return {"ok": True}

    @app.post("/api/subscription-status", dependencies=[Depends(auth)])
    def subscription_status(body: dict):
        sid = endpoint_id(body)
        with database(cfg["DB_PATH"]) as db:
            return {"registered": bool(db.execute("SELECT 1 FROM subscriptions WHERE id=?", (sid,)).fetchone())}

    @app.delete("/api/subscriptions", dependencies=[Depends(auth)])
    def unsubscribe(body: dict):
        sid = endpoint_id(body)
        with database(cfg["DB_PATH"]) as db:
            db.execute("DELETE FROM subscriptions WHERE id=?", (sid,))
        return {"ok": True}

    @app.delete("/api/subscriptions/all", dependencies=[Depends(auth)])
    def unsubscribe_all():
        with database(cfg["DB_PATH"]) as db:
            db.execute("DELETE FROM subscriptions")
        return {"ok": True}

    @app.post("/api/test", dependencies=[Depends(auth)])
    def test_push(body: dict, request: Request):
        rate(request, "test", 6, 60)
        sid = endpoint_id(body)
        with database(cfg["DB_PATH"]) as db:
            sub = db.execute("SELECT data FROM subscriptions WHERE id=?", (sid,)).fetchone()
        if not sub:
            raise HTTPException(404, "먼저 이 기기의 알림을 켜세요.")
        try:
            push_one(json.loads(sub["data"]), {"title": "DAYNOTE 테스트", "body": "이 기기의 웹 푸시 연결을 확인했습니다.", "tag": "daynote-test", "url": "/"}, cfg)
        except Exception as exc:
            code = getattr(getattr(exc, "response", None), "status_code", None)
            if code in (404, 410):
                with database(cfg["DB_PATH"]) as db:
                    db.execute("DELETE FROM subscriptions WHERE id=?", (sid,))
            raise HTTPException(502, f"테스트 전송 실패 (HTTP {code or '-'}). 알림을 껐다 켜고 서버 VAPID 설정을 확인하세요.") from None
        return {"ok": True, "status": "accepted"}

    @app.get("/api/status", dependencies=[Depends(auth)])
    def status():
        with database(cfg["DB_PATH"]) as db:
            counts = dict(db.execute("SELECT status,COUNT(*) FROM deliveries GROUP BY status").fetchall())
            recent = [dict(r) for r in db.execute("""SELECT e.title,d.status,d.detail FROM deliveries d
                JOIN events e ON e.id=d.event_id ORDER BY e.notify_at DESC LIMIT 12""")]
            return {"devices": db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0],
                    "accepted": counts.get("accepted", 0), "failed": counts.get("failed", 0),
                    "recent": recent, "last_tick": state["tick"], "scheduler_error": state["error"]}
    return app


def run_streamlit():
    import requests
    import streamlit as st
    from streamlit_calendar import calendar
    import qrcode
    st.set_page_config(page_title="DAYNOTE · 개인 캘린더", page_icon="📅", layout="wide")
    st.markdown("""<style>.stApp{background:#f5f7f2}h1,h2,h3{color:#155e52}
    div[data-testid=stMetric]{background:white;border:1px solid #dde5df;border-radius:16px;padding:15px}
    .block-container{max-width:1300px;padding-top:2rem}</style>""", unsafe_allow_html=True)
    st.title("DAYNOTE · 나의 캘린더")
    st.caption("작은 계획이 만드는, 좋은 하루 · 한국 시간 · 중요도 1–8")
    with st.expander("처음 배포하시나요? 설치·GitHub·서버·스마트폰 설정 안내"):
        st.code(__doc__, language="text")
    try:
        base = st.secrets.get("BACKEND_URL", os.environ.get("BACKEND_URL", ""))
    except Exception:
        base = os.environ.get("BACKEND_URL", "")
    base = str(base).strip().rstrip("/")
    if not base:
        st.info('먼저 푸시 서버를 배포한 후 Streamlit Secrets에 BACKEND_URL = "https://서버주소"를 입력하세요.')
        st.stop()
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
        st.error("BACKEND_URL은 경로 없는 HTTPS 서버 주소여야 합니다."); st.stop()

    def call(path, method="GET", body=None):
        headers = {"Authorization": "Bearer " + st.session_state.get("token", "")}
        try:
            r = requests.request(method, base + "/api" + path, json=body, headers=headers, timeout=25)
            data = r.json()
        except (requests.RequestException, ValueError):
            raise RuntimeError("서버 연결에 실패했습니다. BACKEND_URL과 서버 상태를 확인하세요.") from None
        if r.status_code == 401:
            st.session_state.pop("token", None)
        if not r.ok:
            detail = data.get("detail", "요청 실패")
            raise RuntimeError(detail if isinstance(detail, str) else "날짜와 입력 값을 확인하세요.")
        return data

    if "token" not in st.session_state:
        with st.form("login"):
            password = st.text_input("개인 비밀번호", type="password")
            if st.form_submit_button("내 캘린더 열기", type="primary"):
                try:
                    st.session_state.token = call("/login", "POST", {"password": password})["token"]
                    st.rerun()
                except RuntimeError as exc:
                    st.error(str(exc))
        st.stop()
    try:
        data = call("/events")
        status = call("/status")
    except RuntimeError as exc:
        st.error(str(exc))
        if st.button("다시 연결 / 로그인"):
            st.rerun()
        st.stop()
    with st.sidebar:
        st.subheader("스마트폰에서 열기")
        image = qrcode.make(base)
        buf = io.BytesIO(); image.save(buf, format="PNG")
        st.image(buf.getvalue(), width=220)
        st.link_button("스마트폰용 캘린더 / 알림 설정", base)
        st.caption("QR에는 주소만 포함됩니다. 비밀번호나 일정은 포함되지 않습니다.")
        st.info("QR로 접속 → 로그인 → 이 기기 알림 켜기. iPhone은 홈 화면에 추가한 아이콘으로 실행하세요.")
        st.caption("Streamlit 화면/iframe에서는 알림을 등록하지 않습니다. 반드시 위 서버 주소를 직접 여세요.")
        st.write(f"등록 기기 **{status['devices']}개**")
        if not status["devices"]:
            st.warning("등록된 기기가 없습니다. 일정 저장만으로 스마트폰 알림이 켜지지 않습니다.")
        if status["scheduler_error"] or status["last_tick"] < time.time() - 600:
            st.error("예약 알림 서버 상태를 확인하세요.")
        if st.button("새로고침"):
            st.rerun()
        if st.button("로그아웃"):
            st.session_state.clear(); st.rerun()
        st.download_button("전체 일정 JSON 백업", json.dumps({"format": "daynote-v1", "timezone": "Asia/Seoul", "events": data}, ensure_ascii=False, indent=2), file_name="daynote-backup.json", mime="application/json")
    now = datetime.now(KST)
    upcoming = [e for e in data if datetime.fromisoformat(e["end"]) > now]
    cols = st.columns(3)
    cols[0].metric("앞으로의 일정", len(upcoming))
    cols[1].metric("중요도 7–8", sum(e["importance"] >= 7 for e in upcoming))
    cols[2].metric("예약 알림", sum(bool(e["notify_at"]) and datetime.fromisoformat(e["notify_at"]) > now for e in data))
    left, right = st.columns([3, 1])
    query = left.text_input("일정 검색", placeholder="제목 · 장소 · 메모")
    minimum = right.selectbox("최소 중요도", list(range(1, 9)), index=0)
    shown = [e for e in data if e["importance"] >= minimum and query.lower() in " ".join((e["title"], e["notes"], e["location"])).lower()]
    cal_events = []
    for e in shown:
        # Floating KST wall-clock values prevent browser-local timezone conversion.
        cal_events.append({"id": e["id"], "title": f"[{e['importance']}] {e['title']}",
            "start": e["start"][:10] if e["all_day"] else e["start"][:19],
            "end": e["end"][:10] if e["all_day"] else e["end"][:19], "allDay": e["all_day"],
            "backgroundColor": COLORS[e["importance"]-1], "borderColor": COLORS[e["importance"]-1]})
    event_result = calendar(events=cal_events, options={"locale": "ko", "initialView": "dayGridMonth", "timeZone": "local",
        "headerToolbar": {"left": "prev,next today", "center": "title", "right": "dayGridMonth,timeGridWeek,listMonth"},
        "buttonText": {"today": "오늘", "month": "월", "week": "주", "list": "목록"},
        "height": 650, "editable": False, "selectable": True, "dayMaxEvents": 3},
        callbacks=["eventClick", "dateClick"], key="daynote-calendar")
    if event_result.get("callback") == "eventClick":
        st.caption("선택한 일정: " + event_result["eventClick"]["event"]["title"] + " — 아래 편집 목록에서 선택하세요.")
    st.subheader("일정 만들기 / 수정")
    labels = {e["id"]: f"{e['start'][:10]} · {e['title']} (중요도 {e['importance']})" for e in data}
    selected_id = st.selectbox("편집할 일정", [""] + list(labels), format_func=lambda x: labels.get(x, "＋ 새 일정"))
    old = next((e for e in data if e["id"] == selected_id), None)
    start = datetime.fromisoformat(old["start"]) if old else now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    end = datetime.fromisoformat(old["end"]) if old else start + timedelta(hours=1)
    if old and old["all_day"]:
        end -= timedelta(minutes=1)
    notify = datetime.fromisoformat(old["notify_at"]) if old and old["notify_at"] else start - timedelta(minutes=10)
    form_key = f"edit-{selected_id}-{old['revision'] if old else st.session_state.get('new_revision', 0)}"
    with st.form(form_key):
        title = st.text_input("제목 *", value=old["title"] if old else "", max_chars=120)
        a,b,c,d = st.columns(4)
        sd = a.date_input("시작 날짜", start.date(), min_value=datetime(1970,1,1).date(), max_value=datetime(2100,12,30).date())
        stime = b.time_input("시작 시각", start.time().replace(tzinfo=None), step=60)
        ed = c.date_input("종료 날짜 (종일: 마지막 날)", end.date(), min_value=datetime(1970,1,1).date(), max_value=datetime(2100,12,30).date())
        etime = d.time_input("종료 시각", end.time().replace(tzinfo=None), step=60)
        all_day = st.checkbox("종일 일정", value=old["all_day"] if old else False)
        a,b = st.columns(2)
        importance = a.selectbox("중요도 · 1 낮음 / 8 가장 높음", list(range(1,9)), index=(old["importance"]-1) if old else 3)
        location = b.text_input("장소", value=old["location"] if old else "", max_chars=200)
        notes = st.text_area("메모", value=old["notes"] if old else "", max_chars=4000)
        enabled = st.checkbox("지정 시각에 푸시 알림", value=bool(old and old["notify_at"]))
        a,b = st.columns(2)
        nd = a.date_input("알림 날짜", notify.date(), min_value=datetime(1970,1,1).date(), max_value=datetime(2100,12,31).date())
        nt = b.time_input("알림 시각 (한국 시간)", notify.time().replace(tzinfo=None), step=60)
        st.caption("알림은 미래 시각으로 설정하세요. 종일 일정은 시작 날짜부터 종료 날짜까지 포함합니다.")
        if st.form_submit_button("일정 저장", type="primary"):
            begin = datetime.combine(sd, datetime.min.time() if all_day else stime, KST)
            finish = datetime.combine(ed + timedelta(days=1) if all_day else ed, datetime.min.time() if all_day else etime, KST)
            payload = {"title": title, "notes": notes, "location": location, "start": begin.isoformat(), "end": finish.isoformat(),
                       "all_day": all_day, "importance": importance, "notify_at": datetime.combine(nd,nt,KST).isoformat() if enabled else None,
                       "revision": old["revision"] if old else None}
            try:
                call("/events" + ("/" + selected_id if old else ""), "PUT" if old else "POST", payload)
                st.session_state.new_revision = st.session_state.get("new_revision", 0) + 1
                st.session_state.saved_message = "일정을 저장했습니다."
                st.rerun()
            except RuntimeError as exc:
                st.error(str(exc))
    if st.session_state.pop("saved_message", None):
        st.success("일정을 저장했습니다.")
    if old:
        confirm = st.checkbox("이 일정을 삭제하겠습니다", key="delete-confirm-"+selected_id)
        if st.button("선택 일정 삭제", disabled=not confirm):
            try:
                call("/events/" + selected_id, "DELETE"); st.rerun()
            except RuntimeError as exc:
                st.error(str(exc))
    with st.expander("최근 알림 전송 기록"):
        st.caption("accepted = 푸시 서비스 접수. 기기 표시/열람 확인이 아닙니다. pending=대기, retry=재시도, failed=실패, expired=만료.")
        if status["recent"]:
            st.dataframe(status["recent"], use_container_width=True, hide_index=True)
        else:
            st.write("아직 전송 기록이 없습니다.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DAYNOTE: streamlit run app.py 또는 python app.py --server")
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--generate-keys", action="store_true")
    args, _ = parser.parse_known_args()
    if args.generate_keys:
        generate_keys()
    elif args.server:
        import uvicorn
        logging.basicConfig(level=logging.INFO)
        uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), workers=1,
                    proxy_headers=False, access_log=False)
    else:
        run_streamlit()
