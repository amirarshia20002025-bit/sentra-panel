// SENTRA — admin panel SPA (single self-contained HTML, RTL Persian, AMOLED dark default,
// light theme, simple/advanced modes, in-browser clean-IP Radar, PWA-ready).
// The UI talks only to /admin/api/* with session cookie + CSRF header.

export function panelPage() {
  return new Response(PANEL_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

export function landingPage(hostname) {
  return new Response(`<!doctype html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTRA</title><style>
body{background:#04070c;color:#e7ecef;font-family:Vazirmatn,Tahoma,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0}
.box{text-align:center;padding:40px;border:1px solid #16303f;border-radius:18px;background:#0a1420}
h1{color:#3ec8a8;margin:0 0 8px;font-size:28px;letter-spacing:4px}
p{color:#7f95a3;margin:6px 0}
a{display:inline-block;margin-top:18px;padding:10px 22px;background:#14524a;color:#aef0dd;border-radius:10px;text-decoration:none}
</style></head><body><div class="box">
<h1>SENTRA</h1>
<p>پنل پروکسی شخصی روی Cloudflare Workers</p>
<p>مدیریت کاربران، اشتراک، ربات تلگرام و رادار IP تمیز</p>
<a href="/admin">ورود به پنل ←</a>
</div></body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

const PANEL_HTML = `<!doctype html>
<html dir="rtl" lang="fa" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#04070c">
<title>SENTRA Panel</title>
<link rel="manifest" href='data:application/manifest+json,{"name":"SENTRA Panel","short_name":"SENTRA","display":"standalone","start_url":"/admin","background_color":"%2304070c","theme_color":"%2304070c"}'>
<style>
:root{--bg:#04070c;--card:#0a1420;--card2:#0e1a2a;--line:#16303f;--txt:#e7ecef;--mut:#7f95a3;--acc:#3ec8a8;--acc2:#14524a;--bad:#e5484d;--warn:#e5a13d}
[data-theme=light]{--bg:#f2f6f7;--card:#ffffff;--card2:#eef4f4;--line:#d5e0e2;--txt:#16242e;--mut:#5f7581;--acc:#0e8a70;--acc2:#d7efe8;--bad:#c62f34;--warn:#b97b1d}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:Vazirmatn,Tahoma,sans-serif;margin:0;font-size:14px}
.top{display:flex;gap:10px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:9}
.logo{font-weight:900;color:var(--acc);letter-spacing:3px}
.spacer{flex:1}
button,input,select,textarea{font-family:inherit;font-size:13px;background:var(--card2);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 10px;outline:none}
button{cursor:pointer}button:hover{border-color:var(--acc)}
button.primary{background:var(--acc2);border-color:var(--acc);color:var(--txt);font-weight:700}
button.danger{border-color:var(--bad);color:var(--bad)}
button.mini{padding:3px 8px;font-size:12px;border-radius:6px}
.wrap{max-width:1080px;margin:0 auto;padding:14px}
.nav{display:flex;gap:6px;flex-wrap:wrap;padding:10px 0}
.nav button{border-radius:10px}
.nav button.on{background:var(--acc2);border-color:var(--acc);font-weight:700}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin:10px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center}
.stat b{display:block;font-size:20px;color:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:right;padding:6px;border-bottom:1px solid var(--line);font-weight:600}
td{padding:7px 6px;border-bottom:1px solid var(--line)}
.bar{height:6px;background:var(--line);border-radius:3px;min-width:80px;overflow:hidden}
.bar>div{height:100%;background:var(--acc)}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;border:1px solid var(--line)}
.badge.on{color:var(--acc);border-color:var(--acc)}
.badge.off{color:var(--bad);border-color:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
label{display:block;color:var(--mut);font-size:12px;margin:8px 0 3px}
.sw{position:relative;width:38px;height:20px;background:var(--line);border-radius:10px;cursor:pointer;display:inline-block;vertical-align:middle}
.sw::after{content:'';position:absolute;top:2px;inset-inline-start:2px;width:16px;height:16px;background:var(--mut);border-radius:50%;transition:.2s}
.sw.on::after{inset-inline-start:20px;background:var(--acc)}
#toast{position:fixed;bottom:16px;inset-inline-start:50%;transform:translateX(50%);background:var(--acc2);border:1px solid var(--acc);padding:9px 18px;border-radius:10px;display:none;z-index:99}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;place-items:center;z-index:50}
.modal>.box{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;width:min(560px,94vw);max-height:88vh;overflow:auto}
.mut{color:var(--mut);font-size:12px}
code,.link{direction:ltr;display:inline-block;background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:2px 7px;word-break:break-all;font-size:12px}
svg.chart{width:100%;height:120px}
.center{text-align:center}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="top">
  <span class="logo">SENTRA</span>
  <span id="hdrMode" class="mut"></span>
  <span class="spacer"></span>
  <button class="mini" id="btnMode" title="حالت ساده/پیشرفته">⚙️</button>
  <button class="mini" id="btnTheme" title="تم">🌓</button>
  <button class="mini" id="btnOut" title="خروج">🚪</button>
</div>
<div class="wrap" id="app"></div>
<div id="toast"></div>
<div class="modal" id="modal"><div class="box" id="modalBox"></div></div>

<script>
'use strict';
const $=(s)=>document.querySelector(s);
const app=$('#app');
const esc=(s)=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtBytes=(n)=>{if(!n)return'0 B';const u=['B','KB','MB','GB','TB'];let i=0,v=n;while(v>=1024&&i<4){v/=1024;i++}return v.toFixed(1)+' '+u[i]};
const fmtDate=(t)=>t>0?new Date(t).toISOString().slice(0,10):'∞';
const toast=(m)=>{const t=$('#toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2200)};
const modal=(html)=>{$('#modalBox').innerHTML=html;$('#modal').style.display='grid'};
const closeModal=()=>{$('#modal').style.display='none'};
$('#modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal()});
$('#btnTheme').onclick=()=>{const h=document.documentElement;h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';localStorage.sentraTheme=h.dataset.theme};
$('#btnOut').onclick=async()=>{await api('logout',{method:'POST'});location.reload()};
if(localStorage.sentraTheme)document.documentElement.dataset.theme=localStorage.sentraTheme;

let CSRF='',ADV=localStorage.sentraAdv==='1';
$('#btnMode').onclick=()=>{ADV=!ADV;localStorage.sentraAdv=ADV?'1':'0';route(lastView)};
const api=async(path,opt={})=>{
  const o={headers:{},...opt};
  o.headers['content-type']='application/json';
  if(CSRF&&opt.method&&opt.method!=='GET')o.headers['x-sentra-csrf']=CSRF;
  const r=await fetch('/admin/api/'+path,o);
  if(r.status===401){state.view='login';renderLogin();throw new Error('unauth')}
  return r.json();
};
const state={view:'home',users:[],settings:null,stats:null};

// ── boot: install-info decides install vs login vs app ──
(async()=>{
  try{
    const info=await api('install-info');
    if(!info.installed){renderInstall(info.claim);return}
    const s=await api('settings').catch(()=>null);
    if(s&&s.ok){CSRF='';await loadApp()}
    else renderLogin();
  }catch(e){renderLogin()}
})();

// ── install ──
function renderInstall(claim){
  app.innerHTML='<div class="card" style="max-width:520px;margin:40px auto"><h2>نصب اولیه پنل</h2>'
  +'<p class="mut">توکن اتصال (claim) مالکیت این Worker را به شما گره می‌زند.</p>'
  +'<label>توکن نصب</label><input id="iClaim" style="width:100%" value="'+esc(claim||'')+'">'
  +'<label>رمز ادمین (حداقل ۸ کاراکتر)</label><input id="iPass" type="password" style="width:100%">'
  +'<label>تکرار رمز</label><input id="iPass2" type="password" style="width:100%">'
  +'<div class="row" style="margin-top:12px"><button class="primary" id="iGo">نصب و ورود</button></div></div>';
  $('#iGo').onclick=async()=>{
    if($('#iPass').value!==$('#iPass2').value)return toast('رمزها یکسان نیستند');
    const r=await api('install',{method:'POST',body:JSON.stringify({claim_token:$('#iClaim').value,password:$('#iPass').value})});
    if(!r.ok)return toast(r.error||'خطا');
    modal('<h3>✅ نصب شد — این‌ها را الان ذخیره کنید!</h3>'
      +'<p class="mut">کدهای بازیابی (یک‌بار مصرف):</p><pre style="direction:ltr">'+r.recoveryCodes.join('\\n')+'</pre>'
      +'<p class="mut">کلید TOTP برای اپ 2FA:</p><code>'+r.totpSecret+'</code>'
      +'<div class="row" style="margin-top:12px"><button class="primary" onclick="location.reload()">ذخیره کردم، برو</button></div>');
  };
}

// ── login ──
function renderLogin(){
  app.innerHTML='<div class="card" style="max-width:380px;margin:60px auto"><h2 class="center">ورود ادمین</h2>'
  +'<label>رمز</label><input id="lPass" type="password" style="width:100%">'
  +'<label>کد 2FA (اگر فعال است)</label><input id="lTotp" style="width:100%" placeholder="000000 یا کد بازیابی">'
  +'<div class="center" style="margin-top:14px"><button class="primary" id="lGo">ورود</button></div></div>';
  const go=async()=>{
    const r=await api('login',{method:'POST',body:JSON.stringify({password:$('#lPass').value,totp:$('#lTotp').value})});
    if(!r.ok)return toast(r.error||'خطا');
    CSRF=r.csrf;await loadApp();
  };
  $('#lGo').onclick=go;$('#lPass').addEventListener('keydown',e=>{if(e.key==='Enter')go()});
}

// ── app shell ──
let lastView='home';
async function loadApp(){
  await Promise.all([reloadUsers(),reloadSettings()]);
  renderApp();
}
async function reloadUsers(){const r=await api('users');state.users=r.users||[]}
async function reloadSettings(){const r=await api('settings');state.settings=r.settings||{}}
function renderApp(){
  app.innerHTML='<div class="nav">'
  +navBtn('home','📊 داشبورد')+navBtn('users','👥 کاربران')+navBtn('radar','📡 رادار')
  +(ADV?navBtn('settings','🔧 تنظیمات')+navBtn('ops','🛡 عملیات'):'')
  +'</div><div id="view"></div>';
  $('#hdrMode').textContent=ADV?'حالت پیشرفته':'حالت ساده';
  route(lastView);
}
function navBtn(id,txt){return '<button data-v="'+id+'" id="nv-'+id+'">'+txt+'</button>'}
function route(v){
  lastView=v;
  document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('on',b.dataset.v===v));
  ({home:viewHome,users:viewUsers,radar:viewRadar,settings:viewSettings,ops:viewOps}[v]||viewHome)();
}

// ── dashboard (advanced charts: stacked up/down bars, active donut, top-user bars) ──
async function viewHome(){
  $('#view').innerHTML='<div class="card center mut">در حال بارگذاری…</div>';
  const s=await api('stats');if(!s.ok)return;
  state.stats=s;
  const W=1000,H=140,C_DOWN='#3ec8a8',C_UP='#e5a13d';
  const max=Math.max(1,...s.daily.map(d=>d.bytes));
  const bw=W/Math.max(1,s.daily.length);
  const bars=s.daily.map((d,i)=>{
    const dh=Math.max(2,(d.down||0)/max*H), uh=Math.max(0,(d.up||0)/max*H);
    const x=i*bw+4, w=Math.max(2,bw-8);
    return '<rect x="'+x+'" y="'+(H-dh)+'" width="'+w+'" height="'+dh+'" rx="3" fill="'+C_DOWN+'"/>'
      +'<rect x="'+x+'" y="'+Math.max(0,H-dh-uh)+'" width="'+w+'" height="'+uh+'" rx="3" fill="'+C_UP+'"/>'
      +'<title>'+d.day+': ↑'+fmtBytes(d.up||0)+' ↓'+fmtBytes(d.down||0)+'</title>';
  }).join('');
  const total=Math.max(1,s.users.total), frac=s.users.active/total, R=42, C=2*Math.PI*R;
  const donut='<svg width="110" height="110" viewBox="0 0 110 110">'
    +'<circle cx="55" cy="55" r="'+R+'" fill="none" stroke="var(--line)" stroke-width="14"/>'
    +'<circle cx="55" cy="55" r="'+R+'" fill="none" stroke="var(--acc)" stroke-width="14" stroke-dasharray="'+(C*frac).toFixed(1)+' '+C.toFixed(1)+'" stroke-linecap="round" transform="rotate(-90 55 55)"/>'
    +'<text x="55" y="60" text-anchor="middle" fill="var(--txt)" font-size="15">'+s.users.active+'/'+s.users.total+'</text></svg>';
  const tmax=Math.max(1,...s.topUsers.map(t=>t.bytes));
  const topBars=s.topUsers.map(t=>'<div class="row" style="margin:5px 0"><span style="min-width:120px">'+esc(t.name)+'</span>'
    +'<div class="bar" style="flex:1"><div style="width:'+Math.round(t.bytes/tmax*100)+'%"></div></div>'
    +'<span class="mut">'+fmtBytes(t.bytes)+'</span></div>').join('')||'<p class="mut">—</p>';
  $('#view').innerHTML=
   '<div class="cards"><div class="stat"><b>'+s.users.active+'</b>فعال</div>'
   +'<div class="stat"><b>'+s.users.total+'</b>کل کاربران</div>'
   +'<div class="stat"><b>'+fmtBytes(s.usage)+'</b>مصرف کل</div>'
   +'<div class="stat"><b>'+(s.scan.filter(x=>x.ok).length)+'</b>IP سالم</div></div>'
   +'<div class="grid2"><div class="card"><h3>مصرف ۱۴ روز اخیر <span class="mut">(<i style="color:'+C_UP+'">■</i> آپلود <i style="color:'+C_DOWN+'">■</i> دانلود)</span></h3>'
   +'<svg class="chart" style="height:150px" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">'+bars+'</svg></div>'
   +'<div class="card"><h3>وضعیت کاربران</h3><div class="row">'+donut+'<div><p>🟢 فعال: '+s.users.active+'</p><p>🔴 غیرفعال: '+(s.users.total-s.users.active)+'</p></div></div></div></div>'
   +'<div class="grid2"><div class="card"><h3>بیشترین مصرف</h3>'+topBars+'</div>'
   +'<div class="card"><h3>رویدادهای اخیر</h3>'+listAudit(s.audit)+'</div></div>';
}
const listTop=(l)=>l.length?'<table>'+l.map(x=>'<tr><td>'+esc(x.name)+'</td><td style="text-align:left">'+fmtBytes(x.bytes)+'</td></tr>').join('')+'</table>':'<p class="mut">—</p>';
const listAudit=(l)=>l.length?'<table>'+l.map(x=>'<tr><td class="mut">'+new Date(x.at).toISOString().slice(5,16).replace('T',' ')+'</td><td>'+esc(x.action)+'</td><td class="mut">'+esc(x.detail||'')+'</td></tr>').join('')+'</table>':'<p class="mut">—</p>';

// ── users ──
async function viewUsers(){
  await reloadUsers();
  const u=state.users;
  $('#view').innerHTML='<div class="row"><button class="primary" id="uAdd">➕ کاربر جدید</button>'
  +'<span class="spacer"></span><button class="mini" id="uBulkE">فعال‌سازی انتخاب‌شده</button>'
  +'<button class="mini" id="uBulkD">غیرفعال</button><button class="mini" id="uBulkR">صفر کردن مصرف</button>'
  +'<button class="mini danger" id="uBulkX">حذف</button></div>'
  +'<div class="card" style="padding:0"><div style="overflow-x:auto"><table><tr><th></th><th>نام</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th>ریست</th><th>عملیات</th></tr>'
  +u.map(x=>userRow(x)).join('')+'</table></div></div>';
  $('#uAdd').onclick=()=>userModal(null);
  $('#uBulkE').onclick=()=>bulk('enable');$('#uBulkD').onclick=()=>bulk('disable');
  $('#uBulkR').onclick=()=>bulk('reset');$('#uBulkX').onclick=()=>bulk('delete');
}
const userRow=(x)=>{
  const pct=x.quotaBytes?Math.min(100,Math.round(x.usedBytes/x.quotaBytes*100)):0;
  return '<tr><td><input type="checkbox" class="sel" value="'+x.id+'"></td>'
  +'<td><b>'+esc(x.name)+'</b></td>'
  +'<td><span class="badge '+(x.enabled?'on':'off')+'">'+(x.enabled?'فعال':'خاموش')+'</span></td>'
  +'<td><div class="bar"><div style="width:'+pct+'%"></div></div><span class="mut">'+fmtBytes(x.usedBytes)+(x.quotaBytes?'/'+fmtBytes(x.quotaBytes):'')+'</span></td>'
  +'<td>'+fmtDate(x.expiresAt)+(x.startOnFirstConnect?' <span class="mut">(اولین اتصال)</span>':'')+'</td>'
  +'<td class="mut">'+(x.resetPeriod==='never'?'—':x.resetPeriod)+'</td>'
  +'<td><button class="mini" onclick="window._sub('+x.id+')">🔗</button> '
  +'<button class="mini" onclick="window._edit('+x.id+')">✏️</button> '
  +'<button class="mini" onclick="window._rot('+x.id+')">🔄</button> '
  +'<button class="mini danger" onclick="window._del('+x.id+')">🗑</button></td></tr>';
};
window._sub=async(id)=>{const x=state.users.find(u=>u.id===id);const h=location.host;
  const sub='https://'+h+'/sub/'+x.token, es=encodeURIComponent(sub), b64s=btoa(sub);
  modal('<h3>اشتراک '+esc(x.name)+'</h3><p class="mut">لینک عمومی (UA خودکار):</p><div class="link">'+sub+'</div>'
  +'<p class="mut">فرمت‌ها:</p><div class="link">…/sub/'+x.token+'?format=clash</div><div class="link">…/sub/'+x.token+'?format=singbox</div>'
  +'<p class="mut">ایمپورت یک‌کلیکی (روی دستگاهی که اپ در آن نصب است):</p>'
  +'<div class="row"><a href="v2rayng://install-sub?url='+es+'"><button class="mini">v2rayNG</button></a>'
  +'<a href="clash://install-config?url='+es+'"><button class="mini">Clash</button></a>'
  +'<a href="sing-box://import-remote?url='+es+'"><button class="mini">sing-box</button></a>'
  +'<a href="hiddify://import/sub?url='+es+'"><button class="mini">Hiddify</button></a>'
  +'<a href="sub://'+b64s+'"><button class="mini">Shadowrocket</button></a>'
  +'<a href="streisand://import/'+sub+'"><button class="mini">Streisand</button></a></div>'
  +'<p class="mut">صفحه سلف‌سرویس کاربر:</p><div class="link">'+sub+'/view</div>'
  +'<div class="row"><button class="primary" onclick="navigator.clipboard.writeText(\\''+sub+'\\')">کپی لینک</button>'
  +'<button onclick="window._qr(\\''+sub+'\\')">QR</button><button onclick="closeModal()">بستن</button></div><div id="qr" class="center"></div>')};
window._qr=(txt)=>{try{const q=window.qrcode(0,'M');q.addData(txt);q.make();$('#qr').innerHTML=q.createSvgTag({cellSize:4})}catch(e){$('#qr').textContent='QR: کتابخانه بارگذاری نشده'}};
window._edit=(id)=>userModal(state.users.find(u=>u.id===id));
window._rot=async(id)=>{if(!confirm('چرخش همه اعتبارنامه‌های این کاربر؟ لینک‌های قبلی باطل می‌شوند'))return;
  await api('users/'+id,{method:'PATCH',body:JSON.stringify({rotateCredentials:true})});await viewUsers();toast('چرخش شد')};
window._del=async(id)=>{if(!confirm('حذف کاربر؟'))return;await api('users/'+id,{method:'DELETE'});await viewUsers();toast('حذف شد')};
const bulk=async(op)=>{const ids=[...document.querySelectorAll('.sel:checked')].map(x=>+x.value);
  if(!ids.length)return toast('انتخابی نیست');if(op==='delete'&&!confirm('حذف '+ids.length+' کاربر؟'))return;
  const r=await api('users/bulk',{method:'POST',body:JSON.stringify({ids,op})});await viewUsers();toast(r.ok?'انجام شد':r.error)};
function userModal(x){
  const isNew=!x;x=x||{};
  modal('<h3>'+(isNew?'کاربر جدید':'ویرایش کاربر')+'</h3>'
  +'<label>نام</label><input id="mName" style="width:100%" value="'+esc(x.name||'')+'">'
  +'<div class="grid2"><div><label>سهمیه (GB، ۰=بی‌نهایت)</label><input id="mQuota" type="number" value="'+((x.quotaBytes||0)/1024**3||0)+'"></div>'
  +'<div><label>سهمیه ریکوئست (۰=بی‌نهایت)</label><input id="mReq" type="number" value="'+(x.quotaRequests||0)+'"></div>'
  +'<div><label>محدودیت دستگاه/IP (۰=بی‌نهایت)</label><input id="mIp" type="number" value="'+(x.ipLimit||0)+'"></div>'
  +'<div><label>ریست دوره‌ای</label><select id="mReset" style="width:100%"><option value="never"'+(x.resetPeriod==='never'?' selected':'')+'>هیچ‌وقت</option><option value="daily"'+(x.resetPeriod==='daily'?' selected':'')+'>روزانه</option><option value="weekly"'+(x.resetPeriod==='weekly'?' selected':'')+'>هفتگی</option><option value="monthly"'+(x.resetPeriod==='monthly'?' selected':'')+'>ماهانه</option></select></div>'
  +'<div><label>مدت روز از اولین اتصال</label><input id="mDur" type="number" value="'+(x.durationDays||0)+'"></div>'
  +'<div><label>تگ اپراتور</label><input id="mIsp" value="'+esc(x.ispTag||'')+'"></div></div>'
  +'<label><span class="sw '+(x.startOnFirstConnect?'on':'')+'" id="mFirst"></span> شروع شمارش اعتبار از اولین اتصال</label>'
  +'<label>یادداشت</label><input id="mNote" style="width:100%" value="'+esc(x.note||'')+'">'
  +(isNew?'':'<label>مصرف ۱۴ روز اخیر</label><div id="mSpark" class="mut">…</div>')
  +'<div class="row" style="margin-top:12px"><button class="primary" id="mSave">ذخیره</button><button onclick="closeModal()">انصراف</button></div>');
  if(!isNew){api('user-stats/'+x.id).then(r=>{if(!r.ok)return;
    const W=460,H=50,mx=Math.max(1,...r.daily.map(d=>(d.up||0)+(d.down||0)));
    const bw=W/Math.max(1,r.daily.length);
    const bars=r.daily.map((d,i)=>{const h=((d.up||0)+(d.down||0))/mx*H;
      return '<rect x="'+(i*bw+2)+'" y="'+(H-Math.max(1,h))+'" width="'+Math.max(2,bw-4)+'" height="'+Math.max(1,h)+'" rx="2" fill="var(--acc)"><title>'+d.day+': '+fmtBytes((d.up||0)+(d.down||0))+'</title></rect>'}).join('');
    $('#mSpark').innerHTML='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;height:60px">'+bars+'</svg>';
  }).catch(()=>{})}
  $('#mFirst').onclick=()=>$('#mFirst').classList.toggle('on');
  $('#mSave').onclick=async()=>{
    const body={name:$('#mName').value,quotaGb:+$('#mQuota').value,quotaRequests:+$('#mReq').value,
      ipLimit:+$('#mIp').value,resetPeriod:$('#mReset').value,durationDays:+$('#mDur').value,
      ispTag:$('#mIsp').value,note:$('#mNote').value,startOnFirstConnect:$('#mFirst').classList.contains('on')};
    if(isNew){const r=await api('users',{method:'POST',body:JSON.stringify(body)});
      if(r.ok)toast('ساخته شد — لینک: /sub/'+r.user.token)}
    else await api('users/'+x.id,{method:'PATCH',body:JSON.stringify(body)});
    closeModal();await viewUsers();
  };
}

// ── radar (client-side clean-IP) ──
async function viewRadar(){
  $('#view').innerHTML='<div class="card"><h3>📡 رادار IP تمیز (در مرورگر شما)</h3>'
  +'<p class="mut">از شبکه همین دستگاه پینگ می‌گیرد؛ نتیجه دقیقاً همان چیزی است که ISP شما می‌بیند.</p>'
  +'<div class="row"><button class="primary" id="rGo">شروع رادار</button><span id="rProg" class="mut"></span></div>'
  +'<div id="rOut"></div></div>'
  +'<div class="card"><h3>اسکنر سمت سرور</h3><div class="row"><button id="rScan">اسکن TCP از کلودفلر</button><span id="sOut" class="mut"></span></div></div>';
  $('#rGo').onclick=runRadar;
  $('#rScan').onclick=async()=>{$('#sOut').textContent='…';const r=await api('scan',{method:'POST'});
    $('#sOut').textContent=r.ok?r.results.map(x=>x.ip+' ('+x.latency+'ms)').join(' · '):r.error};
}
async function runRadar(){
  const r=await api('radar-pool');if(!r.ok)return;
  const out=[];const pool=r.pool.slice(0,24);
  for(let i=0;i<pool.length;i++){
    $('#rProg').textContent=(i+1)+'/'+pool.length;
    const ip=pool[i];const t0=performance.now();
    try{const ctl=new AbortController();setTimeout(()=>ctl.abort(),2200);
      await fetch('https://'+ip+'/cdn-cgi/trace',{signal:ctl.signal,mode:'cors',cache:'no-store'});
      out.push({ip,ms:Math.round(performance.now()-t0),ok:true});
    }catch(e){out.push({ip,ms:0,ok:false})}
  }
  out.sort((a,b)=>(a.ok?b.ms?a.ms-b.ms:0:-1));
  const best=out.filter(x=>x.ok).slice(0,8);
  $('#rProg').textContent='';
  $('#rOut').innerHTML='<table>'+best.map((x,i)=>'<tr><td>'+(i+1)+'</td><td class="link">'+x.ip+'</td><td>'+x.ms+'ms</td>'
    +(ADV?'<td><button class="mini" onclick="window._rToIsp(\\''+x.ip+'\\')">→ اپراتور</button></td>':'')+'</tr>').join('')+'</table>';
}
window._rToIsp=async(ip)=>{
  const isp=prompt('کدام اپراتور؟ (MCI / Irancell / Rightel / TCI / Gaming)','MCI');if(!isp)return;
  const s=state.settings;const list=s.isp_ips?.[isp]||[];
  if(!list.includes(ip))list.unshift(ip);
  await api('settings',{method:'PATCH',body:JSON.stringify({isp_ips:{...s.isp_ips,[isp]:list.slice(0,4)}})});
  await reloadSettings();toast('ذخیره شد — کاربران این اپراتور لینک '+isp+' را می‌گیرند');
};

// ── settings (advanced) ──
async function viewSettings(){
  const s=state.settings;
  const sw=(k,label,on)=>'<label><span class="sw '+(on?'on':'')+'" data-k="'+k+'"></span> '+label+'</label>';
  $('#view').innerHTML=
   '<div class="card"><h3>عمومی</h3>'
   +'<div class="grid2"><div><label>قالب نام نود</label><input id="sTpl" style="width:100%" value="'+esc(s.node_template||'')+'"></div>'
   +'<div><label>سطح امنیت</label><select id="sLevel" style="width:100%">'+['relaxed|ملایم','balanced|متعادل','hard|سختگیرانه'].map(o=>{const[a,b]=o.split('|');return '<option value="'+a+'"'+(s.security_level===a?' selected':'')+'>'+b+'</option>'}).join('')+'</select></div>'
   +'<div><label>زبان پنل/ربات</label><select id="sLang" style="width:100%">'+[['fa','فارسی'],['en','English'],['ru','Русский']].map(([a,b])=>'<option value="'+a+'"'+(s.panel_lang===a?' selected':'')+'>'+b+'</option>').join('')+'</select></div>'
   +'<div><label>رزولور ECH</label><input id="sEchR" style="width:100%" value="'+esc(s.ech_resolver||'')+'"></div></div>'
   +'<div class="card"><h3>ترنسپورت‌ها</h3>'
   +'<label><span class="sw on" style="opacity:.55"></span> WebSocket (همیشه فعال)</label>'
   +'<label><span class="sw '+(s.transports?.grpc?'on':'')+'" data-tk="grpc"></span> gRPC <span class="mut">(آزمایشی — بدون تریلر gRPC-status روی Workers)</span></label>'
   +'<label><span class="sw '+(s.transports?.xhttp?'on':'')+'" data-tk="xhttp"></span> XHTTP / SplitHTTP <span class="mut">(آزمایشی — نیاز به کلاینت Xray جدید)</span></label></div>'
   +sw('ech_enabled','ECH (رمزنگاری SNI)',s.ech_enabled)+sw('fragment_enabled','TLS Fragment',s.fragment_enabled)
   +'<div class="grid2"><div><label>طول فرگمنت</label><input id="sFLen" value="'+esc(s.fragment_len||'')+'"></div>'
   +'<div><label>فاصله فرگمنت</label><input id="sFInt" value="'+esc(s.fragment_interval||'')+'"></div></div>'
   +'<label>اثرانگشت TLS</label><select id="sFp">'+['chrome','safari','ios','android','edge','firefox'].map(f=>'<option'+(s.fingerprint===f?' selected':'')+'>'+f+'</option>').join('')+'</select></div>'
   +'<div class="card"><h3>مسیریابی</h3>'
   +sw('adblock','مسدودسازی تبلیغ',s.adblock)+sw('pornblock','مسدودسازی بزرگسال',s.pornblock)
   +sw('domestic_bypass','عبور مستقیم سایت‌های ایرانی',s.domestic_bypass)+sw('fakeip','FakeIP',s.fakeip)
   +sw('block_quic','مسدودسازی QUIC (UDP443)',s.block_quic)+sw('block_malware','مسدودسازی بدافزار/فیشینگ',s.block_malware)
   +sw('ai_sanction_bypass','دورزدن تحریم سرویس‌های AI',s.ai_sanction_bypass)+'</div>'
   +'<div class="card"><h3>پریست اپراتورها (IP تمیز)</h3>'
   +Object.keys(s.isp_ips||{}).map(k=>'<label>'+k+'</label><input id="isp-'+k+'" style="width:100%" value="'+esc((s.isp_ips[k]||[]).join(', '))+'">').join('')
   +'<p class="mut">IP تمیز هر اپراتور را با «→ اپراتور» از تب رادار یا دستی وارد کنید.</p></div>'
   +'<div class="card"><h3>لوکیشن‌های VIP</h3><label>هر خط: کدکشور=IP</label><textarea id="sLoc" style="width:100%;direction:ltr" rows="4">'+esc(Object.entries(s.locations||{}).map(([k,v])=>k+'='+v).join('\\n'))+'</textarea></div>'
   +'<div class="card"><h3>زنجیره پروکسی (JSON)</h3><textarea id="sChains" style="width:100%;direction:ltr" rows="4">'+esc(JSON.stringify(s.chains||[],null,1))+'</textarea>'
   +'<p class="mut">نمونه: [{"name":"mid","type":"socks5","host":"1.2.3.4","port":1080,"country":"CH"}]</p></div>'
   +'<div class="card"><h3>WARP / AmneziaWG</h3>'
   +'<div class="grid2"><div><label>PrivateKey</label><input id="wPk" style="width:100%" value="'+esc(s.warp?.private_key||'')+'"></div>'
   +'<div><label>PeerPublicKey</label><input id="wPub" style="width:100%" value="'+esc(s.warp?.peer_public_key||'')+'"></div>'
   +'<div><label>Address v4</label><input id="wA4" style="width:100%" value="'+esc(s.warp?.address_v4||'')+'"></div>'
   +'<div><label>Endpoint</label><input id="wEp" style="width:100%" value="'+esc(s.warp?.endpoint||'')+'"></div>'
   +'<div><label>Reserved (JSON)</label><input id="wRes" style="width:100%" value="'+esc(JSON.stringify(s.warp?.reserved||[]))+'"></div>'
   +'<div><label>MTU</label><input id="wMtu" type="number" value="'+(s.warp?.mtu||1280)+'"></div></div></div>'
   +'<div class="card"><h3>ربات تلگرام</h3>'
   +'<label>توکن ربات</label><input id="sTg" style="width:100%;direction:ltr" value="'+esc(s.tg_bot_token||'')+'" placeholder="123:ABC…">'
   +'<label>Chat ID مالک</label><input id="sChat" style="width:100%;direction:ltr" value="'+esc(s.tg_chat_id||'')+'">'
   +sw('tg_notify','اعلان‌های تلگرام',s.tg_notify)+'</div>'
   +'<div class="card"><h3>سایر</h3>'
   +sw('webproxy_enabled','وب‌پروکسی تلگرام (/tgk ، /tgz)',s.webproxy_enabled)
   +sw('kill_switch','⛔ کلید توقف سراسری',s.kill_switch)+'</div>'
   +'<div class="row"><button class="primary" id="sSave">ذخیره تنظیمات</button><span class="mut">چرخش رمز/دسترسی: تب عملیات</span></div>';
  document.querySelectorAll('.sw[data-k]').forEach(el=>el.onclick=()=>el.classList.toggle('on'));
  document.querySelectorAll('.sw[data-tk]').forEach(el=>el.onclick=()=>el.classList.toggle('on'));
  $('#sSave').onclick=async()=>{
    const g=(id)=>$('#'+id)?.value;
    const on=(k)=>!!document.querySelector('.sw[data-k="'+k+'"]').classList.contains('on');
    const tOn=(t)=>!!document.querySelector('.sw[data-tk="'+t+'"]')?.classList.contains('on');
    const locs={};(g('sLoc')||'').split('\\n').forEach(l=>{const[a,b]=l.split('=');if(a&&b)locs[a.trim()]=b.trim()});
    let chains=[];try{chains=JSON.parse(g('sChains')||'[]')}catch(e){return toast('JSON زنجیره نامعتبر')}
    const warp=(g('wPk')||g('wPub'))?{private_key:g('wPk'),peer_public_key:g('wPub'),
      address_v4:g('wA4'),endpoint:g('wEp'),mtu:+g('wMtu'),reserved:JSON.parse(g('wRes')||'[]')}:(state.settings.warp||null);
    const isp_ips={};Object.keys(state.settings.isp_ips||{}).forEach(k=>{isp_ips[k]=(g('isp-'+k)||'').split(',').map(x=>x.trim()).filter(Boolean)});
    const body={node_template:g('sTpl'),security_level:g('sLevel'),panel_lang:g('sLang'),ech_resolver:g('sEchR'),
      transports:{ws:true,grpc:tOn('grpc'),xhttp:tOn('xhttp')},
      ech_enabled:on('ech_enabled'),fragment_enabled:on('fragment_enabled'),fragment_len:g('sFLen'),fragment_interval:g('sFInt'),
      fingerprint:g('sFp'),adblock:on('adblock'),pornblock:on('pornblock'),domestic_bypass:on('domestic_bypass'),
      fakeip:on('fakeip'),block_quic:on('block_quic'),block_malware:on('block_malware'),ai_sanction_bypass:on('ai_sanction_bypass'),
      locations:locs,chains,isp_ips,warp,tg_notify:on('tg_notify'),webproxy_enabled:on('webproxy_enabled'),kill_switch:on('kill_switch')};
    const tok=g('sTg');if(tok&&!tok.startsWith('•••'))body.tg_bot_token=tok;
    body.tg_chat_id=g('sChat');
    const r=await api('settings',{method:'PATCH',body:JSON.stringify(body)});
    if(r.ok){await reloadSettings();toast('ذخیره شد')}else toast(r.error);
  };
}

// ── ops (advanced) ──
async function viewOps(){
  $('#view').innerHTML=
   '<div class="card"><h3>عملیات دوره‌ای</h3><div class="row">'
   +'<button id="oSweep">فلاش ترافیک + انقضا + ریست</button><span id="oOut" class="mut"></span></div></div>'
   +'<div class="card"><h3>پشتیبان‌گیری</h3><div class="row">'
   +'<a href="/admin/api/backup"><button>⬇️ خروجی کامل JSON</button></a>'
   +'<button id="oRest">⬆️ بازیابی از فایل</button></div>'
   +'<p class="mut">بکاپ شامل رمزها هم هست — مثل رمز عبور از آن نگه‌داری کنید.</p></div>'
   +'<div class="card"><h3>آینه گیت‌هاب برای لینک اشتراک</h3>'
   +'<label>مخزن (owner/repo)</label><input id="oMirror" style="width:100%;direction:ltr" value="'+esc(state.settings.github_mirror_repo||'')+'">'
   +'<p class="mut">با یک GitHub Action محتوا را هر روز به این مخزن push کنید تا لینک raw گیت‌هاب حتی پس از فیلتر دامنه زنده بماند (راهنما در README).</p>'
   +'<button class="primary" id="oMirrorSave">ذخیره مخزن</button></div>';
  $('#oSweep').onclick=async()=>{const r=await api('sweep?period=daily',{method:'POST'});$('#oOut').textContent=r.ok?'انجام شد':r.error};
  $('#oRest').onclick=()=>{const i=document.createElement('input');i.type='file';i.accept='.json';
    i.onchange=async()=>{const b=JSON.parse(await i.files[0].text());
      const r=await api('restore',{method:'POST',body:JSON.stringify(b)});
      toast(r.ok?('بازیابی '+r.restored+' کاربر'):r.error);if(r.ok)await loadApp()};
    i.click()};
  $('#oMirrorSave').onclick=async()=>{const r=await api('settings',{method:'PATCH',body:JSON.stringify({github_mirror_repo:$('#oMirror').value.trim()})});toast(r.ok?'ذخیره شد':r.error)};
}
</script>
<script src="/vendor/qrcode.js"></script>
</body></html>`;
