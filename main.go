package main

import (

	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"

	"net/url"
	"os"

	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// ─── Constants & Embedded HTML ───────────────────────────────────────────────

const AllowedSNIs = "play.google.com,www.google.com,google.com,gemini.google.com,aistudio.google.com,notebooklm.google.com,labs.google.com,meet.google.com,accounts.google.com,ogs.google.com,mail.google.com,calendar.google.com,drive.google.com,docs.google.com,chat.google.com,maps.google.com,translate.google.com,assistant.google.com,lens.google.com,safebrowsing.google.com"
const SessionCookie = "rg_session"
const SessionTTL = 7 * 24 * time.Hour

var DefaultFingerprints = []string{"chrome", "firefox", "safari", "edge", "random"}

const LoginHTML = `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>ورود · Null Detected API</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css"><style>*{margin:0;padding:0;box-sizing:border-box}:root{--bg:#0a0e1a;--card:#111827;--border:#1e2d45;--accent:#7c3aed;--accent2:#6d28d9;--green:#22c55e;--text:#e2e8f0;--muted:#64748b;--danger:#ef4444;}html,body{height:100%}body{font-family:'Vazirmatn',sans-serif;background:var(--bg);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:36px 32px;width:100%;max-width:380px;box-shadow:0 25px 60px rgba(0,0,0,.5)}.logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}.logo-icon{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,var(--accent),#a855f7);display:flex;align-items:center;justify-content:center;font-size:22px;color:#fff}.logo-name{color:var(--text);font-size:16px;font-weight:700}.logo-sub{color:var(--muted);font-size:11px;margin-top:2px}h2{color:var(--text);font-size:18px;font-weight:700;margin-bottom:6px}p.sub{color:var(--muted);font-size:12.5px;margin-bottom:24px}label{display:block;font-size:11.5px;color:#94a3b8;font-weight:600;margin-bottom:7px}input{width:100%;padding:12px 14px;background:#0d1526;border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:.15s}input:focus{border-color:var(--accent)}.form-group{margin-bottom:18px}button{width:100%;padding:13px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:10px;font-family:inherit;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:.15s;margin-top:4px}button:hover{filter:brightness(1.1)}button:disabled{opacity:.5;cursor:not-allowed}.err{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.25);border-radius:9px;padding:10px 13px;font-size:12.5px;margin-bottom:16px;display:none;align-items:center;gap:8px}.err.show{display:flex}</style></head><body><div class="card"><div class="logo"><div class="logo-icon"><i class="ti ti-shield-bolt"></i></div><div><div class="logo-name">Null Detected API</div><div class="logo-sub">Null Detected API v1.0</div></div></div><h2>ورود به پنل مدیریت</h2><p class="sub">رمز عبور را برای دسترسی به داشبورد وارد کنید</p><div class="err" id="err"><i class="ti ti-alert-circle"></i><span id="err-text"></span></div><form id="form"><div class="form-group"><label>رمز عبور</label><input type="password" id="pw" placeholder="••••••••" autofocus required></div><button type="submit" id="btn"><i class="ti ti-login-2"></i> ورود</button></form></div><script>
function toast(msg, type='ok'){
  const t=document.getElementById('toast');
  t.innerHTML=` + "`" + `<i class="ti ti-${type==='err'?'x':'check'}"></i> ${msg}` + "`" + `;
  t.className=` + "`" + `toast show ${type}` + "`" + `;
  setTimeout(()=>t.classList.remove('show'),2400);
}
function escH(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&','<':'<','>':'>','"':'"',"'":'\''}[c])); }
function fmtBytes(b){
  if(!b||b===0) return '0 B';
  if(b<1024) return b+' B';
  if(b<1024**2) return (b/1024).toFixed(1)+' KB';
  if(b<1024**3) return (b/1024**2).toFixed(2)+' MB';
  return (b/1024**3).toFixed(2)+' GB';
}
function toFa(n){ return String(n).replace(/\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d]); }
function copyStr(s){
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(s).then(()=>toast('کپی شد')).catch(()=>{
      const ta=document.createElement('textarea');
      ta.value=s;ta.style.cssText='position:fixed;left:-9999px';
      document.body.appendChild(ta);ta.select();
      document.execCommand('copy');document.body.removeChild(ta);
      toast('کپی شد');
    });
  }else{
    const ta=document.createElement('textarea');
    ta.value=s;ta.style.cssText='position:fixed;left:-9999px';
    document.body.appendChild(ta);ta.select();
    document.execCommand('copy');document.body.removeChild(ta);
    toast('کپی شد');
  }
}

async function checkAuth(){
  const r=await fetch('/api/me'); const d=await r.json();
  if(!d.authenticated) location.href='/login';
}
document.getElementById('logout-btn').addEventListener('click',async()=>{
  await fetch('/api/logout',{method:'POST'}); location.href='/login';
});

const sb=document.getElementById('sidebar'), ov=document.getElementById('overlay');
document.getElementById('open-sb').addEventListener('click',()=>{ sb.classList.add('open'); ov.classList.add('show'); });
document.getElementById('close-sb').addEventListener('click',()=>{ sb.classList.remove('open'); ov.classList.remove('show'); });
ov.addEventListener('click',()=>{ sb.classList.remove('open'); ov.classList.remove('show'); });

function switchPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name));
  if(name==='links') loadLinks();
  if(name==='sub') loadSubSettings();
  sb.classList.remove('open'); ov.classList.remove('show');
  window.scrollTo({top:0,behavior:'smooth'});
}
document.querySelectorAll('.nav-item').forEach(i=>i.addEventListener('click',()=>switchPage(i.dataset.page)));

async function af(url,opts){
  const r=await fetch(url,opts);
  if(r.status===401){ location.href='/login'; throw new Error('unauth'); }
  return r;
}

async function fetchStats(){
  try{
    const r=await af('/stats'); const d=await r.json();
    document.getElementById('links-badge').textContent=d.links_count;
    document.getElementById('last-update').textContent=` + "`" + `آخرین بروزرسانی: ${new Date().toLocaleTimeString('fa-IR')}` + "`" + `;
  }catch(e){ console.error(e); }
}

async function fetchOverviewVless(){
  try{
    const r=await af('/api/links'); const d=await r.json();
    const links=d.links||[];
    const def=links[0];
    if(document.getElementById('vless-overview')) document.getElementById('vless-overview').textContent=def?def.vless_link:'لینکی وجود ندارد. از صفحه لینک‌ها یکی بسازید.';
  }catch(e){ console.error(e); }
}

function copyVlessEl(id){ copyStr(document.getElementById(id).textContent); }
function qrForEl(id){
  const txt=document.getElementById(id).textContent;
  if(!txt||txt.includes('دریافت')||txt.includes('وجود')){ toast('لینک آماده نیست','err'); return; }
  showQR(txt);
}
function showQR(text){
  if(document.getElementById('qr-img')) document.getElementById('qr-img').src=` + "`" + `https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=${encodeURIComponent(text)}` + "`" + `;
  if(document.getElementById('qr-link-text')) document.getElementById('qr-link-text').textContent=text;
  if(document.getElementById('qr-modal')) document.getElementById('qr-modal').classList.add('show');
}

async function loadLinks(){
  try{
    const r=await af('/api/links'); const d=await r.json();
    const links=d.links||[];
    const b1 = document.getElementById('links-badge'); if(b1) b1.textContent=links.length;
    const b2 = document.getElementById('links-page-badge'); if(b2) b2.textContent=` + "`" + `${toFa(links.length)} لینک` + "`" + `;
    const tbody=document.getElementById('links-tbody');
    const empty=document.getElementById('links-empty');
    if(!links.length){ if(tbody) tbody.innerHTML=''; if(empty) empty.style.display='block'; return; }
    if(empty) empty.style.display='none';
    if(tbody) {
      const rows = links.map(l=>{
        const tr=document.createElement('tr');
        tr.dataset.uuid=l.uuid;
        tr.dataset.vless=l.vless_link;
        tr.dataset.active=l.active?'1':'0';
        tr.innerHTML=` + "`" + `
          <td><b style="font-size:13px">${escH(l.label)}</b><div style="font-size:10px;color:var(--muted);margin-top:3px">${new Date(l.created_at).toLocaleString('fa-IR')}</div></td>
          <td><span class="uuid-chip" title="${escH(l.uuid)}" data-action="copy-uuid">${escH(l.uuid)}</span></td>
          <td><button class="toggle ${l.active?'on':''}" data-action="toggle"></button></td>
          <td style="white-space:nowrap;display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-sm btn-ghost" data-action="copy-vless" title="کپی VLESS"><i class="ti ti-link"></i></button>
            <button class="btn btn-sm btn-outline" style="color: #a855f7; border-color: rgba(168,85,247,0.4);" data-action="copy-sub" title="لینک اشتراک"><i class="ti ti-rss"></i> ساب</button>
            <button class="btn btn-sm btn-ghost" data-action="qr-vless" title="QR کد"><i class="ti ti-qrcode"></i></button>
            <button class="btn btn-sm btn-danger" data-action="delete" title="حذف"><i class="ti ti-trash"></i></button>
          </td>` + "`" + `;
        return tr;
      });
      tbody.innerHTML='';
      rows.forEach(tr=>tbody.appendChild(tr));
    }
  }catch(e){ console.error(e); }
}

document.addEventListener('click', function(e){
  const btn = e.target.closest('[data-action]');
  if(!btn) return;
  const tr = btn.closest('tr[data-uuid]');
  if(!tr) return;
  const uuid = tr.dataset.uuid;
  const vless = tr.dataset.vless;
  const active = tr.dataset.active === '1';
  const action = btn.dataset.action;
  
  if(action==='copy-uuid') copyStr(uuid);
  else if(action==='copy-vless') copyStr(vless);
  else if(action==='copy-sub') {
      const subUrl = ` + "`" + `${window.location.origin}/sub/${uuid}` + "`" + `;
      copyStr(subUrl);
  }
  else if(action==='qr-vless') showQR(vless);
  else if(action==='toggle') toggleLink(uuid, !active);
  else if(action==='delete') deleteLink(uuid);
});

async function createLink(){
  const nl = document.getElementById('nl-label');
  const label=nl ? nl.value.trim()||'New' : 'New';
  try{
    const r=await af('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label})});
    if(!r.ok) throw new Error('failed');
    if(nl) nl.value='';
    toast('لینک جدید ساخته شد');
    loadLinks();
  }catch(e){ toast('خطا در ساخت لینک','err'); }
}

async function toggleLink(uuid,state){
  await af(` + "`" + `/api/links/${uuid}` + "`" + `,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:state})});
  toast(state?'لینک فعال شد':'لینک غیرفعال شد');
  loadLinks();
}

async function deleteLink(uuid){
  if(!confirm('آیا مطمئن هستید؟')) return;
  await af(` + "`" + `/api/links/${uuid}` + "`" + `,{method:'DELETE'});
  toast('لینک حذف شد');
  loadLinks();
}

async function loadSubSettings() {
    try {
        const r = await af('/api/sub-settings');
        const d = await r.json();
        
        if(document.getElementById('ws-toggle')) {
            if (d.ws && d.ws.enabled !== false) document.getElementById('ws-toggle').classList.add('on');
            else document.getElementById('ws-toggle').classList.remove('on');
            if(document.getElementById('ws-ips')) document.getElementById('ws-ips').value = (d.ws.ips || []).join('\n');
            if(document.getElementById('ws-snis')) document.getElementById('ws-snis').value = (d.ws.snis || []).join('\n');
            if(document.getElementById('ws-fps')) document.getElementById('ws-fps').value = (d.ws.fingerprints || []).join('\n');
            if(document.getElementById('ws-n')) document.getElementById('ws-n').value = d.ws.n;
        }
    } catch(e) {}
}

async function saveSubSettings() {
    const payload = {
        ws: {
            enabled: document.getElementById('ws-toggle') ? document.getElementById('ws-toggle').classList.contains('on') : true,
            ips: document.getElementById('ws-ips') ? document.getElementById('ws-ips').value.split('\n') : [],
            snis: document.getElementById('ws-snis') ? document.getElementById('ws-snis').value.split('\n') : [],
            fingerprints: document.getElementById('ws-fps') ? document.getElementById('ws-fps').value.split('\n') : [],
            n: document.getElementById('ws-n') ? (parseInt(document.getElementById('ws-n').value, 10) || 0) : 0
        }
    };
    try {
        const r = await af('/api/sub-settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(r.ok) toast('تنظیمات اشتراک ذخیره شد');
    } catch(e) { 
        toast('خطا در ذخیره', 'err'); 
    }
}

async function changePassword(){
  const cur=document.getElementById('cp-cur').value;
  const nw=document.getElementById('cp-new').value;
  const cf=document.getElementById('cp-cf').value;
  if(!cur||!nw||!cf){ toast('همه فیلدها را پر کنید','err'); return; }
  if(nw!==cf){ toast('رمز جدید و تکرار آن یکسان نیستند','err'); return; }
  const r=await af('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
  if(r.ok){ toast('رمز تغییر کرد'); document.getElementById('cp-cur').value=''; document.getElementById('cp-new').value=''; document.getElementById('cp-cf').value=''; }
  else{ const d=await r.json().catch(()=>({})); toast(d.detail||'خطا','err'); }
}

function refreshAll(){ fetchStats(); fetchOverviewVless(); loadLinks(); toast('در حال رفرش...'); }

document.addEventListener('DOMContentLoaded',async()=>{
  await checkAuth();
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  setInterval(fetchStats, 30000);
  setInterval(()=>{ if(document.getElementById('page-links') && document.getElementById('page-links').classList.contains('active')) loadLinks(); }, 15000);
});
</script></body></html>`

const DashboardHTML = `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Null API · Panel</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css"><style>*{margin:0;padding:0;box-sizing:border-box}:root{--bg:#080c18;--sidebar:#0b1020;--card:#0f172a;--border:#1e2d45;--accent:#7c3aed;--accent2:#a855f7;--accent-glow:rgba(124,58,237,.25);--green:#22c55e;--green-bg:rgba(34,197,94,.1);--green-border:rgba(34,197,94,.2);--red:#ef4444;--red-bg:rgba(239,68,68,.1);--red-border:rgba(239,68,68,.2);--amber:#f59e0b;--amber-bg:rgba(245,158,11,.1);--amber-border:rgba(245,158,11,.2);--blue:#3b82f6;--blue-bg:rgba(59,130,246,.1);--text:#e2e8f0;--muted:#64748b;--muted2:#94a3b8;--subtle:#1e2d45;--shadow:0 4px 24px rgba(0,0,0,.4);}html,body{height:100%;background:var(--bg)}body{font-family:'Vazirmatn',sans-serif;color:var(--text);display:flex;font-size:14px;min-height:100vh}::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}.sidebar{width:230px;min-height:100vh;background:var(--sidebar);border-left:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:200;transition:transform .25s}.logo{display:flex;align-items:center;gap:12px;padding:22px 18px 18px;border-bottom:1px solid var(--border)}.logo-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:19px;color:#fff;flex-shrink:0}.logo-name{color:var(--text);font-size:14px;font-weight:700}.logo-sub{color:var(--muted);font-size:10.5px;margin-top:2px}.nav-scroll{flex:1;overflow-y:auto;padding:10px 0 10px}.nav-label{color:var(--muted);font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:14px 18px 6px;font-weight:600}.nav-item{display:flex;align-items:center;gap:10px;padding:10px 18px;color:var(--muted2);font-size:13px;cursor:pointer;border-right:3px solid transparent;transition:.15s;position:relative}.nav-item i{font-size:17px;width:20px;text-align:center}.nav-item:hover{background:rgba(255,255,255,.03);color:var(--text)}.nav-item.active{background:linear-gradient(90deg,var(--accent-glow),transparent);color:var(--text);border-right-color:var(--accent)}.nav-badge{margin-right:auto;background:rgba(124,58,237,.2);color:var(--accent2);font-size:10px;padding:2px 7px;border-radius:20px;font-weight:600}.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border)}.logout-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--red-bg);color:#fca5a5;border:1px solid var(--red-border);border-radius:10px;padding:10px;font-size:12.5px;font-weight:500;font-family:inherit;cursor:pointer;width:100%;transition:.15s}.logout-btn:hover{background:rgba(239,68,68,.2)}.mob-bar{display:none;position:fixed;top:0;right:0;left:0;height:54px;background:var(--sidebar);border-bottom:1px solid var(--border);z-index:150;align-items:center;justify-content:space-between;padding:0 14px}.mob-bar .ml{display:flex;align-items:center;gap:10px}.mob-bar .ml .logo-icon{width:32px;height:32px;font-size:15px;border-radius:9px}.mob-title{color:var(--text);font-size:14px;font-weight:700}.menu-btn{background:rgba(255,255,255,.06);border:none;color:var(--text);width:36px;height:36px;border-radius:9px;font-size:18px;display:flex;align-items:center;justify-content:center;cursor:pointer}.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:190;backdrop-filter:blur(2px)}.overlay.show{display:block}.sidebar-close{display:none;position:absolute;left:14px;top:20px;background:rgba(255,255,255,.06);border:none;color:var(--text);width:32px;height:32px;border-radius:8px;font-size:16px;align-items:center;justify-content:center;cursor:pointer}.main{margin-right:230px;flex:1;padding:26px 28px 60px;max-width:calc(100% - 230px)}.page{display:none}.page.active{display:block;animation:fadeIn .2s ease}@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}.topbar{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}.topbar-title{font-size:19px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:9px}.topbar-title i{color:var(--accent2);font-size:21px}.topbar-sub{font-size:12px;color:var(--muted);margin-top:4px}.topbar-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.badge{font-size:11px;padding:5px 11px;border-radius:20px;font-weight:600;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}.badge-green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}.badge-red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}.badge-amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}.badge-purple{background:rgba(124,58,237,.15);color:var(--accent2);border:1px solid rgba(124,58,237,.25)}.badge-blue{background:var(--blue-bg);color:var(--blue);border:1px solid rgba(59,130,246,.2)}.dot{width:7px;height:7px;border-radius:50%;display:inline-block}.dot-green{background:var(--green)}.dot-red{background:var(--red)}.pulse{animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px 22px;box-shadow:var(--shadow)}.card-title{font-size:13px;font-weight:700;color:var(--muted2);margin-bottom:16px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:.04em}.card-title i{font-size:17px;color:var(--accent2)}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:20px}.metric{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow);transition:.15s}.metric:hover{border-color:rgba(124,58,237,.3);transform:translateY(-1px)}.m-label{font-size:10.5px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;display:flex;align-items:center;gap:6px}.m-label i{font-size:15px;color:var(--accent2)}.m-val{font-size:26px;font-weight:700;color:var(--text);line-height:1}.m-val .unit{font-size:13px;font-weight:500;color:var(--muted);margin-right:3px}.m-sub{font-size:11px;color:var(--muted);margin-top:7px}.vless-box{background:linear-gradient(135deg,#0e0f2e,#0f1535);border:1px solid rgba(124,58,237,.3);border-radius:16px;padding:20px 22px;margin-bottom:20px;position:relative;overflow:hidden}.vless-box::before{content:'';position:absolute;top:-40px;left:-40px;width:200px;height:200px;background:radial-gradient(circle,var(--accent-glow),transparent 70%);pointer-events:none}.vless-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px}.vless-title{color:var(--accent2);font-size:12.5px;display:flex;align-items:center;gap:7px;font-weight:600}.vless-link-wrap{background:rgba(0,0,0,.3);border:1px solid rgba(124,58,237,.2);border-radius:10px;padding:13px 15px}.vless-link{color:#a5b4fc;font-size:11px;font-family:ui-monospace,monospace;word-break:break-all;line-height:1.75;letter-spacing:.01em}.vless-actions{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}.btn{font-family:inherit;font-size:12.5px;font-weight:600;border-radius:9px;padding:9px 15px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;white-space:nowrap}.btn i{font-size:14px}.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 2px 10px var(--accent-glow)}.btn-primary:hover{filter:brightness(1.1)}.btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted2)}.btn-outline:hover{background:rgba(255,255,255,.04);color:var(--text)}.btn-ghost{background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--muted2)}.btn-ghost:hover{background:rgba(255,255,255,.08)}.btn-danger{background:var(--red-bg);color:#fca5a5;border:1px solid var(--red-border)}.btn-danger:hover{background:rgba(239,68,68,.2)}.btn-amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}.btn-sm{padding:6px 10px;font-size:11.5px;border-radius:7px}.btn:disabled{opacity:.4;cursor:not-allowed}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}.grid3{display:grid;grid-template-columns:repeat(3, 1fr);gap:14px;margin-bottom:20px}.status-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);font-size:12.5px}.status-row:last-child{border-bottom:none}.status-key{color:var(--muted2);display:flex;align-items:center;gap:7px}.status-key i{font-size:15px;color:var(--muted)}.status-val{color:var(--text);font-weight:600;font-family:ui-monospace,monospace;font-size:12px}.status-val.green{color:var(--green);font-family:inherit}.status-val.red{color:var(--red);font-family:inherit}.mono{font-family:ui-monospace,monospace;font-size:11.5px}.reality-panel{background:linear-gradient(135deg,#0a0f20,#0d1325);border:1px solid rgba(124,58,237,.25);border-radius:14px;padding:20px 22px;margin-bottom:20px}.key-box{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:9px;padding:12px 15px;font-family:ui-monospace,monospace;font-size:11px;color:#a5b4fc;word-break:break-all;line-height:1.7;margin-top:8px}.key-label{font-size:10.5px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.07em;display:flex;align-items:center;justify-content:space-between}.tbl{width:100%;border-collapse:collapse}.tbl th{text-align:right;font-size:10.5px;color:var(--muted);font-weight:600;padding:10px 8px;border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}.tbl td{padding:13px 8px;border-bottom:1px solid rgba(30,45,69,.5);font-size:12.5px;vertical-align:middle}.tbl tr:last-child td{border-bottom:none}.tbl tr:hover td{background:rgba(255,255,255,.015)}.uuid-chip{font-family:ui-monospace,monospace;font-size:10px;color:#a5b4fc;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.2);padding:3px 8px;border-radius:6px;display:inline-block;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}.usage-bar-wrap{min-width:110px}.usage-bar{height:5px;border-radius:3px;background:rgba(255,255,255,.07);overflow:hidden;margin-bottom:5px}.usage-fill{height:100%;border-radius:3px;transition:width .3s}.usage-text{font-size:10px;color:var(--muted)}.empty-state{text-align:center;padding:50px 20px;color:var(--muted)}.empty-state i{font-size:38px;color:var(--border);margin-bottom:12px;display:block}.toggle{width:38px;height:21px;border-radius:20px;background:rgba(255,255,255,.1);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none;outline:none}.toggle::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;background:#fff;top:3px;right:3px;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.3)}.toggle.on{background:var(--green)}.toggle.on::after{right:20px}.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}.form-group{display:flex;flex-direction:column;gap:6px}.form-label{font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em}.form-input,.form-select{padding:10px 12px;border-radius:9px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:none;color:var(--text);background:#0a0f20;min-width:110px;transition:.15s}.form-input:focus,.form-select:focus{border-color:var(--accent)}.form-select option{background:#0a0f20}.callout{background:var(--amber-bg);border:1px solid var(--amber-border);border-radius:11px;padding:13px 15px;font-size:12px;color:var(--amber);display:flex;gap:10px;align-items:flex-start;line-height:1.8;margin-top:14px}.callout i{font-size:17px;flex-shrink:0;margin-top:1px}.callout.blue{background:var(--blue-bg);border-color:rgba(59,130,246,.25);color:#93c5fd}.callout.blue i{color:var(--blue)}.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(40px);background:#1e2d45;color:var(--text);border-radius:10px;padding:11px 22px;font-size:13px;opacity:0;transition:all .3s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:0 8px 30px rgba(0,0,0,.4);border:1px solid var(--border)}.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}.toast.err{background:var(--red-bg);border-color:var(--red-border);color:#fca5a5}.toast.ok{background:var(--green-bg);border-color:var(--green-border);color:var(--green)}.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;backdrop-filter:blur(4px);align-items:center;justify-content:center}.modal-backdrop.show{display:flex}.modal{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:28px;max-width:340px;width:100%;text-align:center;box-shadow:0 30px 80px rgba(0,0,0,.6)}.modal h3{font-size:16px;margin-bottom:16px;color:var(--text)}.modal img{border-radius:10px;max-width:260px;width:100%;margin-bottom:16px;background:#fff;padding:8px}.modal .close-btn{font-family:inherit;font-size:13px;background:var(--border);border:none;color:var(--muted2);border-radius:9px;padding:9px 20px;cursor:pointer}@media(max-width:960px){.sidebar{transform:translateX(100%)}.sidebar.open{transform:translateX(0);box-shadow:-10px 0 40px rgba(0,0,0,.5)}.sidebar-close{display:flex}.main{margin-right:0;max-width:100%;padding-top:68px}.mob-bar{display:flex}.metrics{grid-template-columns:1fr 1fr}.grid2,.grid3{grid-template-columns:1fr}}@media(max-width:480px){.metrics{grid-template-columns:1fr}.main{padding-left:14px;padding-right:14px}}</style></head><body><div class="toast" id="toast"></div><div class="modal-backdrop" id="qr-modal"><div class="modal"><h3><i class="ti ti-qrcode" style="color:var(--accent2)"></i> QR کد</h3><img id="qr-img" src="" alt="QR Code"><div id="qr-link-text" style="font-size:10.5px;color:var(--muted);word-break:break-all;font-family:monospace;margin-bottom:16px;line-height:1.7;background:rgba(0,0,0,.3);padding:10px;border-radius:8px;text-align:left;direction:ltr"></div><button class="close-btn" onclick="document.getElementById('qr-modal').classList.remove('show')">بستن</button></div></div><div class="mob-bar"><div class="ml"><div class="logo-icon"><i class="ti ti-shield-bolt"></i></div><span class="mob-title">Null Detected API</span></div><button class="menu-btn" id="open-sb"><i class="ti ti-menu-2"></i></button></div><div class="overlay" id="overlay"></div><aside class="sidebar" id="sidebar"><button class="sidebar-close" id="close-sb"><i class="ti ti-x"></i></button><div class="logo"><div class="logo-icon"><i class="ti ti-shield-bolt"></i></div><div><div class="logo-name">Null Detected API</div><div class="logo-sub">VLESS · WebSocket</div></div></div><div class="nav-scroll"><div class="nav-label">پنل</div><div class="nav-item active" data-page="overview"><i class="ti ti-layout-dashboard"></i> داشبورد</div><div class="nav-item" data-page="links"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها <span class="nav-badge" id="links-badge">0</span></div><div class="nav-label">سیستم</div><div class="nav-item" data-page="sub"><i class="ti ti-rss"></i> تنظیمات اشتراک (Sub)</div><div class="nav-item" data-page="security"><i class="ti ti-shield-check"></i> امنیت</div><div class="nav-item" data-page="errors"><i class="ti ti-alert-triangle"></i> خطاها <span class="nav-badge" id="err-badge">0</span></div><div class="nav-item" data-page="settings"><i class="ti ti-settings"></i> تنظیمات پنل</div></div><div class="sidebar-footer"><button class="logout-btn" id="logout-btn"><i class="ti ti-logout"></i> خروج</button></div></aside><main class="main"><section class="page active" id="page-overview"><div class="topbar"><div><div class="topbar-title"><i class="ti ti-layout-dashboard"></i> داشبورد</div><div class="topbar-sub" id="last-update">در حال بارگذاری...</div></div><div class="topbar-right"><span class="badge badge-green"><span class="dot dot-green pulse"></span> سرور فعال</span><button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button></div></div><div class="vless-box"><div class="vless-header"><div class="vless-title"><i class="ti ti-link"></i> MainLink — VLESS (Multi Protocol)</div><span class="badge badge-purple">WebSocket Only</span></div><div class="vless-link-wrap"><div class="vless-link" id="vless-overview">در حال دریافت...</div></div><div class="vless-actions"><button class="btn btn-primary" onclick="copyVlessEl('vless-overview')"><i class="ti ti-copy"></i> کپی VLESS</button><button class="btn btn-ghost" onclick="switchPage('links')"><i class="ti ti-link-plus"></i> ساخت لینک جدید</button></div></div></section>

  <section class="page" id="page-sub">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-rss"></i> تنظیمات لینک اشتراک (Subscription)</div>
        <div class="topbar-sub">مدیریت لیست SNI و Fingerprint برای تولید کانفیگ</div>
      </div>
      <div class="topbar-right">
        <button class="btn btn-primary" onclick="saveSubSettings()"><i class="ti ti-device-floppy"></i> ذخیره تنظیمات</button>
      </div>
    </div>
    
    

    <div class="card" style="border-color:rgba(59,130,246,.4)">
      <div class="card-title" style="color:var(--blue);font-size:14px; display:flex; justify-content:space-between; width:100%"><span><i class="ti ti-cloud"></i> تنظیمات VLESS WebSocket (TLS)</span><button class="toggle on" id="ws-toggle" onclick="this.classList.toggle('on')"></button></div>
      <div class="grid3">
        <div class="form-group"><label class="form-label">لیست IP/DOMAIN/CIDR (هر کدام در یک خط)</label><textarea id="ws-ips" class="form-input" style="height:120px;direction:ltr;font-family:monospace"></textarea></div>
        <div class="form-group"><label class="form-label">لیست SNI / Host (هر کدام در یک خط)</label><textarea id="ws-snis" class="form-input" style="height:120px;direction:ltr;font-family:monospace"></textarea></div>
        <div class="form-group"><label class="form-label">لیست Fingerprint (اختیاری)</label><textarea id="ws-fps" class="form-input" style="height:120px;direction:ltr;font-family:monospace"></textarea></div>
      </div>
      <div class="form-group" style="max-width:250px; margin-top:10px">
        <label class="form-label">تعداد کانفیگ تصادفی (0 = تمامی ترکیبات ممکن)</label>
        <input type="number" id="ws-n" class="form-input" placeholder="مثلاً 15" min="0">
      </div>
    </div>

    
  </section>

  <section class="page" id="page-links">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها</div>
        <div class="topbar-sub">ساخت لینک‌های VLESS با UUID یکتا و سهمیه ترافیک</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-purple" id="links-page-badge">۰ لینک</span>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px">
      <div class="card-title"><i class="ti ti-plus"></i> ساخت لینک جدید</div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:160px">
          <label class="form-label">عنوان</label>
          <input class="form-input" id="nl-label" placeholder="مثلاً: برای علی" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="createLink()"><i class="ti ti-plus"></i> ساخت</button>
      </div>
      <div class="callout blue" style="margin-top:14px">
        <i class="ti ti-info-circle"></i>
        <span>هر لینک یک UUID کاملاً رندوم دارد. Xray بلافاصله ری‌لود می‌شود.</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> لینک‌های ساخته‌شده</div>
      <div style="overflow-x:auto">
        <table class="tbl">
          <thead><tr>
            <th>عنوان</th>
            <th>UUID</th>
            <th>وضعیت</th>
            <th>عملیات</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="empty-state" id="links-empty" style="display:none">
        <i class="ti ti-link-off"></i>
        هنوز لینکی ساخته نشده.
      </div>
    </div>
  </section>

  

  <section class="page" id="page-security">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-shield-check"></i> امنیت</div>
        <div class="topbar-sub">وضعیت امنیتی سرویس</div>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-lock"></i> پروتکل و رمزنگاری</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-shield-lock"></i> پروتکل</span><span class="status-val green">VLESS + WS</span></div>
        
        <div class="status-row"><span class="status-key"><i class="ti ti-certificate"></i> رمزنگاری کلید</span><span class="status-val green">X25519</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-fingerprint"></i> TLS Fingerprint</span><span class="status-val">Chrome (مخفی‌سازی)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-eye-off"></i> پوشش ترافیک</span><span class="status-val green">available on sub settings</span></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-shield-check"></i> کنترل دسترسی</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-toggle-right"></i> فعال/غیرفعال UUID</span><span class="status-val green">پشتیبانی</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-gauge"></i> سهمیه ترافیک</span><span class="status-val green">پشتیبانی</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-reload"></i> ریلود بدون قطعی</span><span class="status-val green">SIGHUP</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-clock"></i> سشن پنل</span><span class="status-val">۷ روز، HttpOnly</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-ban"></i> بلوک IP خصوصی</span><span class="status-val green">فعال</span></div>
      </div>
    </div>
  </section>

  <section class="page" id="page-errors">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-alert-triangle"></i> خطاها</div>
        <div class="topbar-sub">آخرین خطاهای ثبت‌شده</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-red" id="errs-badge-full">۰ خطا</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><i class="ti ti-bug"></i> لاگ خطاها</div>
      <div id="errors-list">در حال بارگذاری...</div>
    </div>
  </section>

  <section class="page" id="page-settings">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-settings"></i> تنظیمات پنل</div>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-server"></i> اطلاعات سرور</div>
        
        
        <div class="status-row"><span class="status-key"><i class="ti ti-versions"></i> نسخه</span><span class="status-val">Null API v1.5 (Pro)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-brand-python"></i> فریم‌ورک</span><span class="status-val">Go 1.22 + Native WS</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-cloud"></i> پلتفرم</span><span class="status-val">Orkestr</span></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-key"></i> تغییر رمز عبور</div>
        <div class="form-group" style="margin-bottom:12px">
          <label class="form-label">رمز فعلی</label>
          <input class="form-input" type="password" id="cp-cur" placeholder="••••••" style="width:100%">
        </div>
        <div class="form-group" style="margin-bottom:12px">
          <label class="form-label">رمز جدید</label>
          <input class="form-input" type="password" id="cp-new" placeholder="حداقل ۴ کاراکتر" style="width:100%">
        </div>
        <div class="form-group" style="margin-bottom:16px">
          <label class="form-label">تکرار رمز جدید</label>
          <input class="form-input" type="password" id="cp-cf" placeholder="تکرار" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="changePassword()" style="width:100%;justify-content:center"><i class="ti ti-key"></i> تغییر رمز</button>
      </div>
    </div>
  </section>

</main>

<script>
function toast(msg, type='ok'){
  const t=document.getElementById('toast');
  t.innerHTML=` + "`" + `<i class="ti ti-${type==='err'?'x':'check'}"></i> ${msg}` + "`" + `;
  t.className=` + "`" + `toast show ${type}` + "`" + `;
  setTimeout(()=>t.classList.remove('show'),2400);
}
function escH(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&','<':'<','>':'>','"':'"',"'":'\''}[c])); }
function fmtBytes(b){
  if(!b||b===0) return '0 B';
  if(b<1024) return b+' B';
  if(b<1024**2) return (b/1024).toFixed(1)+' KB';
  if(b<1024**3) return (b/1024**2).toFixed(2)+' MB';
  return (b/1024**3).toFixed(2)+' GB';
}
function toFa(n){ return String(n).replace(/\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d]); }
function copyStr(s){
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(s).then(()=>toast('کپی شد')).catch(()=>{
      const ta=document.createElement('textarea');
      ta.value=s;ta.style.cssText='position:fixed;left:-9999px';
      document.body.appendChild(ta);ta.select();
      document.execCommand('copy');document.body.removeChild(ta);
      toast('کپی شد');
    });
  }else{
    const ta=document.createElement('textarea');
    ta.value=s;ta.style.cssText='position:fixed;left:-9999px';
    document.body.appendChild(ta);ta.select();
    document.execCommand('copy');document.body.removeChild(ta);
    toast('کپی شد');
  }
}

async function checkAuth(){
  const r=await fetch('/api/me'); const d=await r.json();
  if(!d.authenticated) location.href='/login';
}
document.getElementById('logout-btn').addEventListener('click',async()=>{
  await fetch('/api/logout',{method:'POST'}); location.href='/login';
});

const sb=document.getElementById('sidebar'), ov=document.getElementById('overlay');
document.getElementById('open-sb').addEventListener('click',()=>{ sb.classList.add('open'); ov.classList.add('show'); });
document.getElementById('close-sb').addEventListener('click',()=>{ sb.classList.remove('open'); ov.classList.remove('show'); });
ov.addEventListener('click',()=>{ sb.classList.remove('open'); ov.classList.remove('show'); });

function switchPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name));
  if(name==='links') loadLinks();

  if(name==='sub') loadSubSettings();
  sb.classList.remove('open'); ov.classList.remove('show');
  window.scrollTo({top:0,behavior:'smooth'});
}
document.querySelectorAll('.nav-item').forEach(i=>i.addEventListener('click',()=>switchPage(i.dataset.page)));

async function af(url,opts){
  const r=await fetch(url,opts);
  if(r.status===401){ location.href='/login'; throw new Error('unauth'); }
  return r;
}

async function fetchStats(){
  try{
    const r=await af('/stats'); const d=await r.json();
    
    document.getElementById('links-badge').textContent=d.links_count;
    document.getElementById('last-update').textContent=` + "`" + `آخرین بروزرسانی: ${new Date().toLocaleTimeString('fa-IR')}` + "`" + `;
    
  }catch(e){ console.error(e); }
}

async function fetchOverviewVless(){
  try{
    const r=await af('/api/links'); const d=await r.json();
    const links=d.links||[];
    const def=links[0];
    document.getElementById('vless-overview').textContent=def?def.vless_link:'لینکی وجود ندارد. از صفحه لینک‌ها یکی بسازید.';


  }catch(e){ console.error(e); }
}

function copyVlessEl(id){ copyStr(document.getElementById(id).textContent); }
function qrForEl(id){
  const txt=document.getElementById(id).textContent;
  if(!txt||txt.includes('دریافت')||txt.includes('وجود')){ toast('لینک آماده نیست','err'); return; }
  showQR(txt);
}
function showQR(text){
  document.getElementById('qr-img').src=` + "`" + `https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=${encodeURIComponent(text)}` + "`" + `;
  document.getElementById('qr-link-text').textContent=text;
  document.getElementById('qr-modal').classList.add('show');
}

async function loadLinks(){
  try{
    const r=await af('/api/links'); const d=await r.json();
    const links=d.links||[];
    document.getElementById('links-badge').textContent=links.length;
    document.getElementById('links-page-badge').textContent=` + "`" + `${toFa(links.length)} لینک` + "`" + `;
    const tbody=document.getElementById('links-tbody');
    const empty=document.getElementById('links-empty');
    if(!links.length){ tbody.innerHTML=''; empty.style.display='block'; return; }
    empty.style.display='none';
    const rows = links.map(l=>{
      const tr=document.createElement('tr');
      tr.dataset.uuid=l.uuid;
      tr.dataset.vless=l.vless_link;


      tr.dataset.active=l.active?'1':'0';
      tr.innerHTML=` + "`" + `
        <td><b style="font-size:13px">${escH(l.label)}</b><div style="font-size:10px;color:var(--muted);margin-top:3px">${new Date(l.created_at).toLocaleString('fa-IR')}</div></td>
        <td><span class="uuid-chip" title="${escH(l.uuid)}" data-action="copy-uuid">${escH(l.uuid)}</span></td>
        <td><button class="toggle ${l.active?'on':''}" data-action="toggle"></button></td>
        <td style="white-space:nowrap;display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-sm btn-ghost" data-action="copy-vless" title="کپی VLESS"><i class="ti ti-link"></i></button>
          <button class="btn btn-sm btn-ghost" style="color:var(--blue)" data-action="copy-ws" title="کپی WebSocket"><i class="ti ti-cloud"></i></button>
          
          <button class="btn btn-sm btn-outline" style="color: #a855f7; border-color: rgba(168,85,247,0.4);" data-action="copy-sub" title="لینک اشتراک"><i class="ti ti-rss"></i> ساب</button>
          <button class="btn btn-sm btn-ghost" data-action="qr-vless" title="QR کد"><i class="ti ti-qrcode"></i></button>
          <button class="btn btn-sm btn-danger" data-action="delete" title="حذف"><i class="ti ti-trash"></i></button>
        </td>` + "`" + `;
      return tr;
    });
    tbody.innerHTML='';
    rows.forEach(tr=>tbody.appendChild(tr));
  }catch(e){ console.error(e); }
}

document.addEventListener('click', function(e){
  const btn = e.target.closest('[data-action]');
  if(!btn) return;
  const tr = btn.closest('tr[data-uuid]');
  if(!tr) return;
  const uuid = tr.dataset.uuid;
  const vless = tr.dataset.vless;

  const active = tr.dataset.active === '1';
  const action = btn.dataset.action;
  
  if(action==='copy-uuid') copyStr(uuid);
  else if(action==='copy-vless') copyStr(vless);

  else if(action==='copy-sub') {
      const subUrl = ` + "`" + `${window.location.origin}/sub/${uuid}` + "`" + `;
      copyStr(subUrl);
  }
  else if(action==='qr-vless') showQR(vless);
  else if(action==='toggle') toggleLink(uuid, !active);
  else if(action==='delete') deleteLink(uuid);
});

async function createLink(){
  const label=document.getElementById('nl-label').value.trim()||'New';
  try{
    const r=await af('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label})});
    if(!r.ok) throw new Error('failed');
    document.getElementById('nl-label').value='';
    toast('لینک جدید ساخته شد');
    loadLinks();
  }catch(e){ toast('خطا در ساخت لینک','err'); }
}

async function toggleLink(uuid,state){
  await af(` + "`" + `/api/links/${uuid}` + "`" + `,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:state})});
  toast(state?'لینک فعال شد':'لینک غیرفعال شد');
  loadLinks();
}

async function deleteLink(uuid){
  if(!confirm('آیا مطمئن هستید؟')) return;
  await af(` + "`" + `/api/links/${uuid}` + "`" + `,{method:'DELETE'});
  toast('لینک حذف شد');
  loadLinks();
}

let privVisible=false;
}

  } catch(e) { toast('خطا در ذخیره', 'err'); }
}

async function loadSubSettings() {
    try {
        const r = await af('/api/sub-settings');
        const d = await r.json();
        
        if (d.reality && d.reality.enabled !== false) document.getElementById('real-toggle').classList.add('on');
        else document.getElementById('real-toggle').classList.remove('on');
        document.getElementById('real-snis').value = (d.reality.snis || []).join('\n');
        document.getElementById('real-fps').value = (d.reality.fingerprints || []).join('\n');
        document.getElementById('real-n').value = d.reality.n;

        if (d.ws && d.ws.enabled !== false) document.getElementById('ws-toggle').classList.add('on');
        else document.getElementById('ws-toggle').classList.remove('on');
        document.getElementById('ws-ips').value = (d.ws.ips || []).join('\n');
        document.getElementById('ws-snis').value = (d.ws.snis || []).join('\n');
        document.getElementById('ws-fps').value = (d.ws.fingerprints || []).join('\n');
        document.getElementById('ws-n').value = d.ws.n;

        if (d.xhttp && d.xhttp.enabled) document.getElementById('xhttp-toggle').classList.add('on');
        else document.getElementById('xhttp-toggle').classList.remove('on');
        document.getElementById('xhttp-ips').value = (d.xhttp.ips || []).join('\n');
        document.getElementById('xhttp-snis').value = (d.xhttp.snis || []).join('\n');
        document.getElementById('xhttp-fps').value = (d.xhttp.fingerprints || []).join('\n');
        document.getElementById('xhttp-n').value = d.xhttp.n;
    } catch(e) {}
}

async function saveSubSettings() {
    const payload = {
        reality: {
            enabled: document.getElementById('real-toggle').classList.contains('on'),
            snis: document.getElementById('real-snis').value.split('\n'),
            fingerprints: document.getElementById('real-fps').value.split('\n'),
            n: parseInt(document.getElementById('real-n').value, 10) || 0
        },
        ws: {
            enabled: document.getElementById('ws-toggle').classList.contains('on'),
            ips: document.getElementById('ws-ips').value.split('\n'),
            snis: document.getElementById('ws-snis').value.split('\n'),
            fingerprints: document.getElementById('ws-fps').value.split('\n'),
            n: parseInt(document.getElementById('ws-n').value, 10) || 0
        },
        xhttp: {
            enabled: document.getElementById('xhttp-toggle').classList.contains('on'),
            ips: document.getElementById('xhttp-ips').value.split('\n'),
            snis: document.getElementById('xhttp-snis').value.split('\n'),
            fingerprints: document.getElementById('xhttp-fps').value.split('\n'),
            n: parseInt(document.getElementById('xhttp-n').value, 10) || 0
        }
    };
    try {
        const r = await af('/api/sub-settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(r.ok) toast('تنظیمات اشتراک ذخیره شد');
    } catch(e) { 
        toast('خطا در ذخیره', 'err'); 
    }
}

async function togglePrivKey(){
  privVisible=!privVisible;
  if(privVisible){
    const el=document.getElementById('rk-priv');
    if(el.textContent==='••••••••••••••••'){
      try{
        const r=await af('/api/reality-private-key');
        const d=await r.json();
        el.textContent=d.private_key||'—';
      }catch(e){ toast('خطا در دریافت کلید خصوصی','err'); privVisible=false; return; }
    }
  }
  document.getElementById('rk-priv').style.filter=privVisible?'none':'blur(5px)';
  document.getElementById('priv-eye').className=privVisible?'ti ti-eye-off':'ti ti-eye';
}

async function regenKeys(){
  if(!confirm('تولید کلید جدید باعث می‌شود تمام لینک‌های کلاینت باطل شوند. ادامه می‌دهید؟')) return;
  const r=await af('/api/regenerate-keys',{method:'POST'});
  const d=await r.json();
  toast('کلیدهای جدید تولید شد — لینک‌ها را دوباره به کلاینت‌ها بدهید');
  loadRealityInfo(); fetchOverviewVless(); loadLinks();
}

function renderErrors(errors){
  const el=document.getElementById('errors-list');
  if(!el) return;
  if(!errors.length){ el.innerHTML='<div style="color:var(--green);padding:12px 0;display:flex;align-items:center;gap:8px"><i class="ti ti-circle-check"></i> هیچ خطایی ثبت نشده</div>'; return; }
  el.innerHTML=errors.slice().reverse().map(e=>` + "`" + `
    <div style="padding:10px 0;border-bottom:1px solid var(--border)">
      <div style="color:var(--muted);font-size:10px;margin-bottom:4px;display:flex;align-items:center;gap:5px"><i class="ti ti-clock" style="font-size:11px"></i> ${new Date(e.time).toLocaleString('fa-IR')}</div>
      <div style="color:#fca5a5;font-family:ui-monospace,monospace;background:var(--red-bg);padding:8px 11px;border-radius:8px;font-size:11.5px;word-break:break-all">${escH(e.error)}${e.url?' — '+escH(e.url):''}</div>
    </div>` + "`" + `).join('');
}

async function loadErrors(){
  const r=await af('/stats'); const d=await r.json();
  renderErrors(d.recent_errors||[]);
}

async function changePassword(){
  const cur=document.getElementById('cp-cur').value;
  const nw=document.getElementById('cp-new').value;
  const cf=document.getElementById('cp-cf').value;
  if(!cur||!nw||!cf){ toast('همه فیلدها را پر کنید','err'); return; }
  if(nw!==cf){ toast('رمز جدید و تکرار آن یکسان نیستند','err'); return; }
  const r=await af('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
  if(r.ok){ toast('رمز تغییر کرد'); document.getElementById('cp-cur').value=''; document.getElementById('cp-new').value=''; document.getElementById('cp-cf').value=''; }
  else{ const d=await r.json().catch(()=>({})); toast(d.detail||'خطا','err'); }
}

function refreshAll(){ fetchStats(); fetchOverviewVless(); loadLinks(); toast('در حال رفرش...'); }

document.addEventListener('DOMContentLoaded',async()=>{
  await checkAuth();
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  loadRealityInfo();
  setInterval(fetchStats, 30000);
  setInterval(()=>{ if(document.getElementById('page-links').classList.contains('active')) loadLinks(); }, 15000);
});
</script>
</body>
</html>`

// ─── Structs ─────────────────────────────────────────────────────────────────

type ConfigStruct struct {
	Port               int
	Secret             string
	Host               string
	WsPath             string
}

type Link struct {
	Label     string `json:"label"`
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
}

type SubSettings struct {
	Enabled      bool     `json:"enabled"`
	SNIs         []string `json:"snis"`
	IPs          []string `json:"ips"`
	Fingerprints []string `json:"fingerprints"`
	N            int      `json:"n"`
}


// ─── Global State & Synchronization ──────────────────────────────────────────

var (
	config         ConfigStruct
	adminPassword  string
	hashedPassword string

	links      = make(map[string]*Link)
	linksMutex sync.RWMutex

	wsSettings      SubSettings
	subMutex        sync.RWMutex

	rcMutex              sync.RWMutex

	sessions     = make(map[string]time.Time)
	sessionMutex sync.RWMutex

	loginAttempts = make(map[string][]time.Time)
	loginMutex    sync.Mutex


	dataDir        string
	linksFile      string
	rSetFile       string
	wSetFile       string
	xSetFile       string
	rcFile         string
	xrayBinPath    = "/usr/local/bin/xray"
	xrayConfigPath string

	configMutex sync.Mutex
	reloadChan  = make(chan struct{}, 1)

	wsUpgrader = websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}
)

// ─── Core Helpers ────────────────────────────────────────────────────────────

func getRandomIP(val string) string {
	if !strings.Contains(val, "/") {
		return val
	}
	_, ipNet, err := net.ParseCIDR(val)
	if err != nil {
		return val
	}
	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		ones, _ := ipNet.Mask.Size()
		hostBits := 32 - ones
		if hostBits > 0 && hostBits < 31 {
			offset := mathrand.Int31n(1 << hostBits)
			ipInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
			ipInt = (ipInt & ^(uint32(1<<hostBits) - 1)) | uint32(offset)
			return fmt.Sprintf("%d.%d.%d.%d", byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt))
		}
	}
	return val
}

func getAllIPs(val string) []string {
	if !strings.Contains(val, "/") {
		return []string{val}
	}
	_, ipNet, err := net.ParseCIDR(val)
	if err != nil {
		return []string{val}
	}
	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		ones, _ := ipNet.Mask.Size()
		hostBits := 32 - ones
		if hostBits > 0 && hostBits <= 8 {
			var ips []string
			baseInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
			baseInt = baseInt & ^(uint32(1<<hostBits) - 1)
			count := 1 << hostBits
			for i := 0; i < count; i++ {
				ipInt := baseInt + uint32(i)
				ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt)))
			}
			return ips
		} else if hostBits > 8 {
			var ips []string
			baseInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
			baseInt = baseInt & ^(uint32(1<<hostBits) - 1)
			for i := 0; i < 256; i++ {
				ipInt := baseInt + uint32(i)
				ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt)))
			}
			return ips
		}
	}
	return []string{val}
}

func atomicWriteJSON(filename string, data interface{}) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	configMutex.Lock()
	defer configMutex.Unlock()
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, b, 0644); err != nil {
		return fmt.Errorf("write temp file failed: %w", err)
	}
	if err := os.Rename(tmpFile, filename); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if valStr, ok := os.LookupEnv(key); ok {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
	}
	return fallback
}

func secureRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("CRITICAL: crypto/rand failed: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("CRITICAL: crypto/rand failed: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func hashPassword(pw string) string {
	h := sha256.New()
	h.Write([]byte(pw + config.Secret))
	return hex.EncodeToString(h.Sum(nil))
}

func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, status int, message string) {
	sendJSON(w, status, map[string]string{"detail": message})
}

func getPublicHost() string {
	return "asdasd.orkestr.run"
}


// ─── Initialization ──────────────────────────────────────────────────────────

func initConfig() {
	config.Port = 8000
	config.Secret = "orkestr_static_secret"
	config.Host = "asdasd.orkestr.run"
	config.WsPath = "/ws"
	adminPassword = "771177"
	hashedPassword = hashPassword(adminPassword)
	log.Println("=================================================================")
	log.Printf(" ⚠️ ADMIN_PASSWORD HARDCODED TO: %s\n", adminPassword)
	log.Println("=================================================================")
}

func initDataDir() {
	dataDir = "/data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		dataDir = "/tmp"
		log.Printf("⚠️ /data is not writable (%v). Using /tmp. DATA WILL BE LOST ON RESTART!", err)
	}

	linksFile = filepath.Join(dataDir, "links.json")
	wSetFile = filepath.Join(dataDir, "ws_settings.json")

	if b, err := os.ReadFile(linksFile); err == nil {
		_ = json.Unmarshal(b, &links)
	}
	if b, err := os.ReadFile(wSetFile); err == nil {
		_ = json.Unmarshal(b, &wsSettings)
	}

	if len(links) == 0 {
		uid := generateUUID()
		links[uid] = &Link{
			Label:     "MainLink",
			CreatedAt: time.Now().Format(time.RFC3339),
			Active:    true,
		}
		_ = atomicWriteJSON(linksFile, links)
		log.Printf("Created default link UUID: %s", uid)
	}
}

func generateLinks(uid, label string, sub SubSettings) []string {
	ips := sub.IPs
	if len(ips) == 0 {
		ips = []string{getPublicHost()}
	}
	snis := sub.SNIs
	if len(snis) == 0 {
		snis = []string{getPublicHost()}
	}
	fps := sub.Fingerprints
	if len(fps) == 0 {
		fps = DefaultFingerprints
	}
	ip := ips[0]
	sni := snis[0]
	fp := fps[0]

	q := url.Values{}
	q.Set("type", "ws")
	q.Set("security", "tls")
	q.Set("path", config.WsPath)
	q.Set("encryption", "none")
	q.Set("insecure", "0")
	q.Set("allowInsecure", "0")
	q.Set("host", sni)
	q.Set("sni", sni)
	q.Set("fp", fp)
	
	fragment := url.PathEscape(label + " | WS")
	return []string{fmt.Sprintf("vless://%s@%s:443?%s#%s", uid, ip, q.Encode(), fragment)}
}

// ─── Background Polling & Maintenance ────────────────────────────────────────

func sessionCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			sessionMutex.Lock()
			for k, exp := range sessions {
				if now.After(exp) {
					delete(sessions, k)
				}
			}
			sessionMutex.Unlock()
			cutoff := now.Add(-2 * time.Minute)
			loginMutex.Lock()
			for ip, attempts := range loginAttempts {
				hasRecent := false
				for _, t := range attempts {
					if t.After(cutoff) {
						hasRecent = true
						break
					}
				}
				if !hasRecent {
					delete(loginAttempts, ip)
				}
			}
			loginMutex.Unlock()
		}
	}
}

// ─── Native VLESS WS Implementation ──────────────────────────────────────────

// wsRelayBufPool reuses 32 KB read buffers across relay goroutines to avoid
// per-connection heap allocations that would pressure the GC under high load.
var wsRelayBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

func parseVlessHeader(chunk []byte) (uuid string, command byte, address string, port uint16, payload []byte, err error) {
	if len(chunk) < 24 {
		return "", 0, "", 0, nil, errors.New("chunk too small for VLESS header")
	}

	u := chunk[1:17]
	uuid = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])

	pos := 17
	addonLen := int(chunk[pos])
	pos += 1 + addonLen
	if pos >= len(chunk) {
		return "", 0, "", 0, nil, errors.New("invalid addon length")
	}

	command = chunk[pos]
	pos++

	if pos+2 > len(chunk) {
		return "", 0, "", 0, nil, errors.New("buffer overflow reading port")
	}
	port = binary.BigEndian.Uint16(chunk[pos : pos+2])
	pos += 2

	addrType := chunk[pos]
	pos++

	switch addrType {
	case 1: // IPv4
		if pos+4 > len(chunk) {
			return "", 0, "", 0, nil, errors.New("buffer overflow IPv4")
		}
		address = net.IP(chunk[pos : pos+4]).String()
		pos += 4
	case 2: // Domain
		if pos >= len(chunk) {
			return "", 0, "", 0, nil, errors.New("buffer overflow domain length")
		}
		dLen := int(chunk[pos])
		pos++
		if pos+dLen > len(chunk) {
			return "", 0, "", 0, nil, errors.New("buffer overflow domain")
		}
		address = string(chunk[pos : pos+dLen])
		pos += dLen
	case 3: // IPv6
		if pos+16 > len(chunk) {
			return "", 0, "", 0, nil, errors.New("buffer overflow IPv6")
		}
		address = net.IP(chunk[pos : pos+16]).String()
		pos += 16
	default:
		return "", 0, "", 0, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	payload = chunk[pos:]
	return uuid, command, address, port, payload, nil
}

// isUUIDActive checks if a UUID exists and is active — the only auth gate for WS connections.
func isUUIDActive(uid string) bool {
	linksMutex.RLock()
	link, ok := links[uid]
	linksMutex.RUnlock()
	return ok && link.Active
}

func handleNativeWS(w http.ResponseWriter, r *http.Request) {
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// 1. Read first frame (contains VLESS header)
	msgType, firstChunk, err := ws.ReadMessage()
	if err != nil || msgType != websocket.BinaryMessage {
		return
	}

	uid, command, address, port, payload, err := parseVlessHeader(firstChunk)
	if err != nil {
		return
	}

	// 2. UUID authentication — reject fake/inactive UUIDs
	if !isUUIDActive(uid) {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1008, "unauthorized"), time.Now().Add(time.Second))
		return
	}

	// 3. VLESS spec requires command 1 (TCP) for proxies
	if command != 1 {
		return
	}

	// 4. Dial target destination (Fix: Safely joining IP and Port for IPv6 Support)
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		return
	}
	// Enable TCP keepalive so dead peers are detected quickly
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	targetConn := rawConn
	defer targetConn.Close()

	if len(payload) > 0 {
		if _, err := targetConn.Write(payload); err != nil {
			return
		}
	}

	errCh := make(chan error, 2)

	// 5. Relay: Client (WS) -> Target (TCP)
	go func() {
		bufPtr := wsRelayBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer wsRelayBufPool.Put(bufPtr)
		for {
			_, r, err := ws.NextReader()
			if err != nil {
				errCh <- err
				return
			}
			if _, err := io.CopyBuffer(targetConn, r, buf); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// 6. Relay: Target (TCP) -> Client (WS)
	// Pool-allocated buffer — returned when this goroutine exits.
	go func() {
		bufPtr := wsRelayBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer wsRelayBufPool.Put(bufPtr)

		// Pre-allocate header+data buffer once (cap = 2 + 32 KB).
		// append into it on the first packet avoids an extra heap copy.
		headerBuf := make([]byte, 2, 2+32*1024)
		headerBuf[0] = 0x00 // VLESS response version
		headerBuf[1] = 0x00 // addon length = 0

		firstPacket := true
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				var data []byte
				if firstPacket {
					// Prepend 2-byte VLESS header without a separate allocation.
					data = append(headerBuf[:2], buf[:n]...)
					firstPacket = false
				} else {
					data = buf[:n]
				}
				if err := ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
					errCh <- err
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Block until an error occurs (or disconnects)
	<-errCh
}


// ─── HTTP Middleware & Auth ──────────────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || !isValidSession(cookie.Value) {
			sendError(w, 401, "unauthorized")
			return
		}
		next(w, r)
	}
}

func isValidSession(token string) bool {
	if token == "" {
		return false
	}
	sessionMutex.RLock()
	exp, ok := sessions[token]
	sessionMutex.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		sessionMutex.Lock()
		delete(sessions, token)
		sessionMutex.Unlock()
		return false
	}
	return true
}

func checkLoginRate(ip string) bool {
	loginMutex.Lock()
	defer loginMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-60 * time.Second)

	attempts := loginAttempts[ip]
	n := 0
	for _, t := range attempts {
		if t.After(cutoff) {
			attempts[n] = t
			n++
		}
	}
	attempts = attempts[:n]

	if len(attempts) >= 10 {
		loginAttempts[ip] = attempts
		return false
	}

	loginAttempts[ip] = append(attempts, now)
	return true
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := strings.TrimSpace(parts[i]); ip != "" {
				return ip
			}
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}

// ─── API Handlers ────────────────────────────────────────────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ip := getClientIP(r)
	if !checkLoginRate(ip) {
		sendError(w, 429, "تعداد تلاش‌های ورود بیش از حد مجاز است. لطفاً یک دقیقه صبر کنید.")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, 400, "Invalid JSON body")
		return
	}

	if !hmac.Equal([]byte(hashPassword(body.Password)), []byte(hashedPassword)) {
		sendError(w, 401, "رمز عبور اشتباه است")
		return
	}

	token := secureRandomString(32)
	sessionMutex.Lock()
	sessions[token] = time.Now().Add(SessionTTL)
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		MaxAge:   int(SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.URL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookie); err == nil {
		sessionMutex.Lock()
		delete(sessions, cookie.Value)
		sessionMutex.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", MaxAge: -1, Path: "/"})
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookie)
	auth := err == nil && isValidSession(cookie.Value)
	sendJSON(w, 200, map[string]bool{"authenticated": auth})
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, 400, "Invalid request body")
		return
	}

	if !hmac.Equal([]byte(hashPassword(body.CurrentPassword)), []byte(hashedPassword)) {
		sendError(w, 400, "رمز فعلی اشتباه است")
		return
	}
	if len(body.NewPassword) < 4 {
		sendError(w, 400, "رمز جدید باید حداقل ۴ کاراکتر باشد")
		return
	}
	hashedPassword = hashPassword(body.NewPassword)

	cookie, _ := r.Cookie(SessionCookie)
	sessionMutex.Lock()
	for k := range sessions {
		if k != cookie.Value {
			delete(sessions, k)
		} else {
			sessions[k] = time.Now().Add(SessionTTL)
		}
	}
	sessionMutex.Unlock()
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, 200, map[string]string{
		"service":  "github.com/null-detected",
		"version":  "1.6.0 (Native WS)",
		"status":   "active",
		"host":     getPublicHost(),
		"protocol": "REALITY & WS & XHTTP",
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

	sendJSON(w, 200, map[string]interface{}{
		"status":      "ok",
		
		"ws_path":     config.WsPath,
		"http_port":   config.Port,
		"public_host": getPublicHost(),
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {

	linksMutex.RLock()
	lc := len(links)
	linksMutex.RUnlock()

	sendJSON(w, 200, map[string]interface{}{
		"timestamp":          time.Now().Format(time.RFC3339),
		"ws_path":            config.WsPath,
				"links_count":        lc,
		"public_host":        getPublicHost(),
			})
}

func handleGetLinks(w http.ResponseWriter, r *http.Request) {
	linksMutex.RLock()
	defer linksMutex.RUnlock()
	subMutex.RLock()
	wSet := wsSettings
	subMutex.RUnlock()

	var res []map[string]interface{}
	for uid, data := range links {
		defW := ""
		if wSet.Enabled {
			if wLinks := generateLinks(uid, data.Label, wSet); len(wLinks) > 0 {
				defW = wLinks[0]
			}
		}

		res = append(res, map[string]interface{}{
			"uuid":             uid,
			"label":            data.Label,
			"active":           data.Active,
			"created_at":       data.CreatedAt,
			"vless_link":       defW,
			"vless_ws_link":    defW,
		})
	}
	sendJSON(w, 200, map[string]interface{}{"links": res})
}

func handlePostLinks(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body struct {
		Label string `json:"label"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, 400, "Invalid JSON body")
		return
	}

	if body.Label == "" {
		body.Label = "لینک جدید"
	}

	uid := generateUUID()
	link := &Link{
		Label:     body.Label,
		CreatedAt: time.Now().Format(time.RFC3339),
		Active:    true,
	}

	linksMutex.Lock()
	links[uid] = link
	linksSnap := links
	linksMutex.Unlock()

	_ = atomicWriteJSON(linksFile, linksSnap)

	sendJSON(w, 200, map[string]interface{}{
		"uuid":       uid,
		"label":      link.Label,
		"active":     link.Active,
		"created_at": link.CreatedAt,
	})
}

func handlePatchLink(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	uid := r.PathValue("id")
	var body map[string]interface{}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, 400, "Invalid JSON body")
		return
	}

	linksMutex.Lock()
	link, ok := links[uid]
	if !ok {
		linksMutex.Unlock()
		sendError(w, 404, "link not found")
		return
	}

	if active, ok := body["active"].(bool); ok {
		link.Active = active
	}
	if label, ok := body["label"].(string); ok {
		link.Label = label
	}
	linksSnap := links
	linksMutex.Unlock()

	_ = atomicWriteJSON(linksFile, linksSnap)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	linksMutex.Lock()
	delete(links, uid)
	linksSnap := links
	linksMutex.Unlock()

	_ = atomicWriteJSON(linksFile, linksSnap)
	sendJSON(w, 200, map[string]bool{"ok": true})
}



func handleGetSub(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	linksMutex.RLock()
	link, ok := links[uid]
	linksMutex.RUnlock()

	if !ok || !link.Active {
		http.Error(w, "Not found or inactive", 404)
		return
	}

	subMutex.RLock()
	wSet := wsSettings
	subMutex.RUnlock()

	var wsConfigs []string
	if wSet.Enabled {
		wsConfigs = generateLinks(uid, link.Label, wSet)
	}

	plainText := strings.Join(wsConfigs, "\n")
	b64Text := base64.StdEncoding.EncodeToString([]byte(plainText))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, b64Text)
}

func handleSubSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		subMutex.RLock()
		defer subMutex.RUnlock()
		sendJSON(w, 200, map[string]interface{}{
			"ws":      wsSettings,
		})
		return
	}
	defer r.Body.Close()
	var body struct {
		Ws      SubSettings `json:"ws"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, 400, "Invalid JSON body")
		return
	}

	cleanList := func(list []string) []string {
		var out []string
		for _, v := range list {
			if st := strings.TrimSpace(v); st != "" {
				out = append(out, st)
			}
		}
		return out
	}

	subMutex.Lock()
	wsSettings.Enabled = body.Ws.Enabled
	wsSettings.IPs = cleanList(body.Ws.IPs)
	wsSettings.SNIs = cleanList(body.Ws.SNIs)
	wsSettings.Fingerprints = cleanList(body.Ws.Fingerprints)
	wsSettings.N = body.Ws.N

	wSnap := wsSettings
	subMutex.Unlock()

	_ = atomicWriteJSON(wSetFile, wSnap)

	sendJSON(w, 200, map[string]bool{"ok": true})
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	initConfig()
	initDataDir()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sessionCleanupLoop(ctx)

	mux := http.NewServeMux()

	// ─── Native Go VLESS over WebSocket Tunnel ─────────────────────────────
	mux.HandleFunc(config.WsPath, handleNativeWS)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		handleRoot(w, r)
	})
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err == nil && isValidSession(cookie.Value) {
			http.Redirect(w, r, "/dashboard", 302)
			return
		}
		_, _ = io.WriteString(w, LoginHTML)
	})
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || !isValidSession(cookie.Value) {
			http.Redirect(w, r, "/login", 302)
			return
		}
		_, _ = io.WriteString(w, DashboardHTML)
	})

	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("POST /api/logout", handleLogout)
	mux.HandleFunc("GET /api/me", handleMe)
	mux.HandleFunc("GET /sub/{id}", handleGetSub)

	mux.HandleFunc("POST /api/change-password", requireAuth(handleChangePassword))
	mux.HandleFunc("GET /stats", requireAuth(handleStats))
	mux.HandleFunc("GET /api/links", requireAuth(handleGetLinks))
	mux.HandleFunc("POST /api/links", requireAuth(handlePostLinks))
	mux.HandleFunc("PATCH /api/links/{id}", requireAuth(handlePatchLink))
	mux.HandleFunc("DELETE /api/links/{id}", requireAuth(handleDeleteLink))
	mux.HandleFunc("GET /api/sub-settings", requireAuth(handleSubSettings))
	mux.HandleFunc("POST /api/sub-settings", requireAuth(handleSubSettings))


	handler := corsMiddleware(mux)

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", config.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout and WriteTimeout removed: XHTTP uses long-lived
		// streaming connections that would be killed by these limits.
	}

	go func() {
		log.Printf("🚀 Null Detected API started — HTTP/WS on :%d", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("\n⚠️ OS Shutdown signal received. Performing graceful shutdown...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	}



	log.Println("✅ Shutdown complete.")
}
