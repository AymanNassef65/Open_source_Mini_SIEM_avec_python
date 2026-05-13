// ── Constants ────────────────────────────────────────────────────────────────
const MITRE = {
  "SQL Injection":        {tactic:"Initial Access",    tech:"T1190",     techName:"Exploit Public-Facing Application", kc:"Exploitation"},
  "Brute Force":          {tactic:"Credential Access", tech:"T1110",     techName:"Brute Force",                       kc:"Weaponization"},
  "Port Scanning":        {tactic:"Discovery",         tech:"T1046",     techName:"Network Service Scanning",          kc:"Reconnaissance"},
  "Access Denied":        {tactic:"Defense Evasion",   tech:"T1078",     techName:"Valid Accounts",                    kc:"Installation"},
  "DDoS Attempt":         {tactic:"Impact",            tech:"T1499",     techName:"Endpoint Denial of Service",        kc:"Actions on Objectives"},
  "Ransomware":           {tactic:"Impact",            tech:"T1486",     techName:"Data Encrypted for Impact",         kc:"Actions on Objectives"},
  "Credential Stuffing":  {tactic:"Credential Access", tech:"T1110.004", techName:"Credential Stuffing",               kc:"Exploitation"},
  "Privilege Escalation": {tactic:"Privilege Escal.",  tech:"T1068",     techName:"Exploitation for Privilege Escal.", kc:"Escalation"},
  "XSS Attack":           {tactic:"Initial Access",    tech:"T1189",     techName:"Drive-by Compromise / XSS",         kc:"Exploitation"},
  "Normal":               {tactic:"—",                tech:"—",         techName:"Normal Activity",                   kc:"—"}
};

const ACTIONS = {
  "SQL Injection":        ["Block source IP immediately","Enable WAF SQL injection rules","Audit DB access logs","Patch vulnerable endpoints"],
  "Brute Force":          ["Lock affected account","Enforce MFA","Add source IP to blocklist","Review login attempts"],
  "Port Scanning":        ["Block source IP at firewall","Enable IDS port-scan detection","Audit exposed services","Review open ports"],
  "Access Denied":        ["Review ACL policies","Verify account privileges","Check for insider threat","Audit authentication logs"],
  "DDoS Attempt":         ["Enable rate limiting","Activate DDoS mitigation","Contact upstream ISP","Monitor bandwidth usage"],
  "Ransomware":           ["ISOLATE affected system NOW","Snapshot for forensics","Notify incident response","Check backup integrity"],
  "Credential Stuffing":  ["Force password reset","Enable CAPTCHA","Implement credential monitoring","Rate-limit authentication"],
  "Privilege Escalation": ["Revoke elevated privileges","Audit sudo/admin logs","Patch kernel/service","Review user roles"],
  "XSS Attack":           ["Sanitize all user inputs","Implement Content Security Policy","Enable XSS filter in WAF","Audit web application code"],
  "Normal":               ["No action required","Continue monitoring"]
};


const PROTOCOLS  = ["TCP","UDP","HTTP","HTTPS","SSH","SMB","RDP"];

// Real IP from DB (index 4) or fallback generated
function getIP(a)   { return (a[4] && a[4]!=='null') ? a[4] : (a[0]%2===0?`192.168.${(a[0]*7)%255}.${(a[0]*13)%255}`:`${45+(a[0]%30)}.${(a[0]*11)%255}.${(a[0]*23)%255}.${(a[0]*17)%255}`); }
function getTimestamp(a) { return (a[5] && a[5]!=='null') ? a[5] : extractTime(a[1]); }

function getPort(id) { const ports=[22,80,443,3306,8080,445,3389]; return ports[id%ports.length]; }
function getProto(id) { return PROTOCOLS[id%PROTOCOLS.length]; }
function getRisk(sev) { return {Critical:94,High:72,Medium:45,Low:18,Normal:5}[sev]||10; }
function getRiskColor(r) { return r>=80?'#ff3366':r>=60?'#ff8c00':r>=35?'#ffcc00':'#00e676'; }
function getSevClass(s) { return ({Critical:'critical',High:'high',Medium:'medium',Low:'low',Normal:'normal'}[s]||'normal'); }

function extractTime(msg) {
  const m = msg && msg.match(/(\d{2}:\d{2}:\d{2})/);
  if(m) return m[1];
  const n = new Date();
  return `${String(n.getHours()).padStart(2,'0')}:${String(n.getMinutes()).padStart(2,'0')}:${String(n.getSeconds()).padStart(2,'0')}`;
}

// ── State ────────────────────────────────────────────────────────────────────
let state = {
  alerts:[], logs:[], topIPs:[],
  selectedAlertId:null,
  alertsFilter:{search:'',severity:'',type:''},
  logsFilter:{search:'',type:''},
  sortDir:-1,
  charts:{},
  _lastHash: ''          // for change-detection
};

// ── Clock ────────────────────────────────────────────────────────────────────
function tickClock() {
  const n=new Date(), el=document.getElementById('clock');
  if(el) el.textContent = n.toUTCString().slice(0,25)+' UTC';
}
setInterval(tickClock,1000); tickClock();

// ── Tabs ─────────────────────────────────────────────────────────────────────
function switchTab(id) {
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item[data-tab]').forEach(n=>n.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  document.querySelector(`.nav-item[data-tab="${id}"]`).classList.add('active');
  const titles={overview:'Security Overview',alerts:'Threat Alerts',logs:'Log Archive',analytics:'Analytics',admin:'User Management'};
  document.getElementById('page-title').textContent = titles[id]||id;
  if(id==='analytics') renderAnalytics();
  if(id==='admin') loadAdminUsers();
}

// ── Single fetch with change detection ───────────────────────────────────────
async function fetchAll() {
  try {
    const d = await fetch('/api/dashboard').then(r=>r.json());
    if(d.error) return;

    // Hash key stats — skip heavy re-renders if nothing changed
    const hash = `${d.alert_count}|${d.log_count}|${d.critical}`;
    const changed = hash !== state._lastHash;
    state._lastHash = hash;

    // Always update lightweight elements
    updateKPIs(d);
    renderAlertBadge(d.alert_count);
    updateLastSeen();

    // Only do heavy DOM work if data changed
    if(changed) {
      state.alerts = d.alerts || [];
      state.logs   = d.all_logs || [];
      state.topIPs = d.top_ips || [];
      updateFeed(d.alerts);
      renderAlertsTable();
      renderLogsTable();
      renderTopIPs();
      updateCharts(d);
    }
  } catch(e) { console.error('Fetch error:',e); }
}

function updateCharts(d) {
  renderTimelineChart(d.timeline||[]);
  renderDonutChart(d.event_stats||[]);
  renderSevChart(d.severity_stats||[]);
}

function updateKPIs(d) {
  animateCount('kpi-logs',    d.log_count    ||0);
  animateCount('kpi-alerts',  d.alert_count  ||0);
  animateCount('kpi-critical',d.critical     ||0);
  animateCount('kpi-high',    d.high         ||0);
  animateCount('kpi-brute',   d.failed_logins||0);
  animateCount('kpi-access',  d.access_denied||0);
  animateCount('kpi-ddos',    d.ddos_count   ||0);
}

function animateCount(id, target) {
  const el=document.getElementById(id); if(!el) return;
  const cur=parseInt(el.textContent)||0;
  if(cur===target){el.textContent=target;return;}
  const step=Math.ceil(Math.abs(target-cur)/6);
  const dir=target>cur?1:-1; let v=cur;
  const t=setInterval(()=>{ v+=dir*step; if((dir>0&&v>=target)||(dir<0&&v<=target)){v=target;clearInterval(t);} el.textContent=v; },50);
}

function updateLastSeen() {
  const el=document.getElementById('last-updated');
  if(el) el.textContent='Synced '+new Date().toLocaleTimeString();
}
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}
function renderAlertBadge(n){const b=document.getElementById('nav-badge-alerts');if(b){b.textContent=n;b.style.display=n>0?'':' none';}}

// ── Live Feed ─────────────────────────────────────────────────────────────────
function updateFeed(alerts) {
  const el=document.getElementById('live-feed');
  if(!el) return;
  el.innerHTML='';
  const recent=(alerts||[]).slice(0,8);
  if(!recent.length){el.innerHTML='<div style="color:var(--t3);font-size:.78rem;padding:10px 0">No alerts yet.</div>';return;}
  recent.forEach(a=>{
    const [id,msg,sev,type]=a;
    const time=extractTime(msg);
    const risk=getRisk(sev);
    const clr=getRiskColor(risk);
    const m=MITRE[type]||MITRE['Normal'];
    el.innerHTML+=`<div class="feed-item">
      <div class="feed-dot" style="background:${clr};box-shadow:0 0 5px ${clr}"></div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
          <span class="feed-type">${type||'Unknown'}</span>
          <span class="badge badge-${getSevClass(sev)}">${sev}</span>
          <span class="feed-time" style="margin-left:auto">${time}</span>
        </div>
        <div class="feed-msg">${msg?msg.slice(0,80)+'…':''}</div>
        <div style="margin-top:4px"><span class="mitre-pill">${m.tech} · ${m.tactic}</span></div>
      </div>
    </div>`;
  });
}

// ── Alerts Table ──────────────────────────────────────────────────────────────
function renderAlertsTable() {
  const tbody=document.getElementById('alerts-tbody');
  if(!tbody) return;
  let data=[...state.alerts];
  const {search,severity,type}=state.alertsFilter;
  if(search)   data=data.filter(a=>(a[1]||'').toLowerCase().includes(search.toLowerCase())||(a[3]||'').toLowerCase().includes(search.toLowerCase())||(a[4]||'').includes(search));
  if(severity) data=data.filter(a=>a[2]===severity);
  if(type)     data=data.filter(a=>a[3]===type);
  data.sort((a,b)=>state.sortDir*(a[0]-b[0]));

  setText('alerts-count',`${data.length} alerts`);
  tbody.innerHTML='';
  if(!data.length){tbody.innerHTML=`<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--t3)"><i class="fas fa-check-circle" style="font-size:1.5rem;color:var(--green);display:block;margin-bottom:8px"></i>No alerts match the current filter</td></tr>`;return;}
  data.forEach(a=>{
    const [id,msg,sev,type]=a;
    const ts=getTimestamp(a);
    const time=ts.length>8?ts.slice(11,19)||ts.slice(0,8):ts;
    const ip=getIP(a);
    const m=MITRE[type]||MITRE['Normal'];
    const risk=getRisk(sev); const rclr=getRiskColor(risk);
    const sel=state.selectedAlertId===id;
    tbody.innerHTML+=`<tr onclick="selectAlert(${id})" class="${sel?'selected':''}">
      <td><span class="badge badge-${getSevClass(sev)}">${sev}</span></td>
      <td class="mono">${time}</td>
      <td class="bold">${type||'—'}</td>
      <td class="mono" style="color:var(--cyan)">${ip}</td>

      <td><span class="mitre-pill">${m.tech}</span></td>
      <td><span class="kc-pill">${m.kc}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:7px">
          <div class="risk-bar-bg"><div class="risk-bar-fill" style="width:${risk}%;background:${rclr}"></div></div>
          <span style="font-size:.7rem;color:${rclr};font-family:'Space Mono',monospace;width:24px">${risk}</span>
        </div>
      </td>
    </tr>`;
  });
}

function selectAlert(id) {
  state.selectedAlertId=id;
  renderAlertsTable();
  const a=state.alerts.find(x=>x[0]===id);
  if(a) showDetailPanel(a);
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
const KC_PHASES=['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions on Objectives'];

function showDetailPanel(a) {
  const [id,msg,sev,type]=a;
  const m=MITRE[type]||MITRE['Normal'];
  const ip=getIP(a);
  const port=getPort(id); const proto=getProto(id);
  const risk=getRisk(sev); const rclr=getRiskColor(risk);
  const ts=getTimestamp(a);
  const actions=(ACTIONS[type]||['Investigate and monitor']).map(ac=>`<li><i class="fas fa-chevron-right"></i>${ac}</li>`).join('');
  const kcHtml=KC_PHASES.map(p=>`<span class="kc-step${p===m.kc||m.kc==='Escalation'&&p==='Actions on Objectives'?' active':''}">${p}</span>`).join('');

  document.getElementById('dp-title').textContent=`Alert #${id}`;
  document.getElementById('dp-severity').innerHTML=`<span class="badge badge-${getSevClass(sev)}">${sev}</span>`;
  document.getElementById('dp-body').innerHTML=`
    <div class="dp-section">
      <div class="dp-section-title">Event Details</div>
      <div class="dp-row"><span class="dp-key">Timestamp</span><span class="dp-val mono">${ts}</span></div>
      <div class="dp-row"><span class="dp-key">Attack Type</span><span class="dp-val bold">${type}</span></div>
      <div class="dp-row"><span class="dp-key">Risk Score</span><span class="dp-val" style="color:${rclr};font-family:'Space Mono',monospace;font-weight:700">${risk}/100</span></div>
      <div class="dp-row"><span class="dp-key">Protocol</span><span class="dp-val mono">${proto}/${port}</span></div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Network Context</div>
      <div class="dp-row"><span class="dp-key">Source IP</span><span class="dp-val mono" style="color:var(--cyan)">${ip}</span></div>

      <div class="dp-row"><span class="dp-key">Dest. Port</span><span class="dp-val mono">${port}</span></div>
      <div class="dp-row"><span class="dp-key">Protocol</span><span class="dp-val mono">${proto}</span></div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">MITRE ATT&CK</div>
      <div class="mitre-card">
        <div class="mitre-tactic">${m.tactic}</div>
        <div class="mitre-tech">${m.techName}</div>
        <div class="mitre-id" style="margin-top:4px">${m.tech}</div>
      </div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Kill Chain Phase</div>
      <div class="kc-steps">${kcHtml}</div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Raw Message</div>
      <div class="dp-raw">${msg||'N/A'}</div>
    </div>
    <div class="dp-section">
      <div class="dp-section-title">Recommended Actions</div>
      <ul class="action-list">${actions}</ul>
    </div>`;
  document.getElementById('detail-panel').classList.add('open');
}

function closeDetailPanel() {
  document.getElementById('detail-panel').classList.remove('open');
  state.selectedAlertId=null;
  renderAlertsTable();
}

// ── Top IPs ───────────────────────────────────────────────────────────────────
function renderTopIPs() {
  const el=document.getElementById('top-ips-list');
  if(!el) return;
  const data=state.topIPs||[];
  if(!data.length){el.innerHTML='<li style="color:var(--t3);font-size:.78rem">No IP data yet — run the attack simulator</li>';return;}
  const max=data[0]?.[1]||1;
  el.innerHTML=data.map(([ip,cnt],i)=>`<li>
    <span class="top-rank">${i+1}</span>
    <span class="mono" style="flex:1;font-size:.75rem;color:var(--cyan)">${ip||'unknown'}</span>
    <div class="top-bar-bg"><div class="top-bar-f" style="width:${(cnt/max*100).toFixed(0)}%"></div></div>
    <span class="top-count">${cnt}</span>
  </li>`).join('');
}

// ── Logs Table ────────────────────────────────────────────────────────────────
let visibleLogs=20;
function renderLogsTable() {
  const tbody=document.getElementById('logs-tbody');
  if(!tbody) return;
  let data=[...state.logs];
  const {search,type}=state.logsFilter;
  if(search) data=data.filter(l=>(l[1]||'').toLowerCase().includes(search.toLowerCase())||(l[2]||'').toLowerCase().includes(search.toLowerCase()));
  if(type)   data=data.filter(l=>l[2]===type);
  setText('logs-count',`${data.length} events`);
  const slice=data.slice(0,visibleLogs);
  tbody.innerHTML='';
  slice.forEach(l=>{
    const [ts,ev,atype]=l;
    const m=MITRE[atype]||MITRE['Normal'];
    tbody.innerHTML+=`<tr>
      <td class="mono" style="color:var(--t3);font-size:.72rem">${ts||'—'}</td>
      <td style="color:var(--green);font-family:'Space Mono',monospace;font-size:.75rem;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ev||'—'}</td>
      <td><span class="badge badge-${getSevClass(atype==='Normal'?'Normal':'Medium')}" style="font-size:.62rem">${atype||'Unknown'}</span></td>
      <td><span class="mitre-pill">${m.tech}</span></td>
    </tr>`;
  });
  const btn=document.getElementById('logs-more');
  if(btn) btn.style.display=visibleLogs>=data.length?'none':'';
}

function loadMoreLogs() { visibleLogs+=20; renderLogsTable(); }

// ── Charts ────────────────────────────────────────────────────────────────────
const CHART_COLORS=['rgba(0,212,255,.7)','rgba(255,51,102,.7)','rgba(255,140,0,.7)','rgba(255,204,0,.7)','rgba(156,111,255,.7)','rgba(0,230,118,.7)','rgba(255,107,53,.7)','rgba(0,188,212,.7)'];

function renderTimelineChart(data) {
  const ctx=document.getElementById('chart-timeline');
  if(!ctx) return;
  const labels=data.map(d=>d.hour);
  const values=data.map(d=>d.count);
  if(state.charts.timeline) {
    // Update in place — works for both normal updates and post-reset zeros
    state.charts.timeline.data.datasets[0].data=values;
    state.charts.timeline.update('none');
    return;
  }

  state.charts.timeline=new Chart(ctx,{
    type:'line',
    data:{labels,datasets:[{label:'Events',data:values,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,.1)',borderWidth:2,pointRadius:3,pointBackgroundColor:'#00d4ff',fill:true,tension:.4}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#0d1b2e',borderColor:'rgba(0,212,255,.3)',borderWidth:1,titleColor:'#00d4ff',bodyColor:'#7f9ab5'}},
      scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#445566',font:{size:9}}},y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#445566',font:{size:9}},beginAtZero:true}}}
  });
}

function renderDonutChart(data) {
  const ctx=document.getElementById('chart-donut');
  if(!ctx) return;
  // Always destroy the old instance first
  if(state.charts.donut) { state.charts.donut.destroy(); state.charts.donut=null; }
  if(!data.length) {
    // Draw empty placeholder
    const parent=ctx.parentElement;
    const old=parent.querySelector('.chart-empty');
    if(!old) {
      const msg=document.createElement('div');
      msg.className='chart-empty';
      msg.style.cssText='position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--t3);font-size:.78rem;';
      msg.textContent='No attack data';
      parent.style.position='relative'; parent.appendChild(msg);
    }
    return;
  }
  // Remove empty placeholder if present
  ctx.parentElement.querySelectorAll('.chart-empty').forEach(e=>e.remove());
  state.charts.donut=new Chart(ctx,{
    type:'doughnut',
    data:{labels:data.map(d=>d[0]),datasets:[{data:data.map(d=>d[1]),backgroundColor:CHART_COLORS,borderColor:'rgba(255,255,255,.05)',borderWidth:1}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,cutout:'70%',
      plugins:{legend:{position:'right',labels:{color:'#7f9ab5',font:{size:10},boxWidth:10,padding:8}},
        tooltip:{backgroundColor:'#0d1b2e',borderColor:'rgba(0,212,255,.3)',borderWidth:1,titleColor:'#00d4ff',bodyColor:'#7f9ab5'}}}
  });
}

let sevChartInstance=null;
function renderSevChart(data) {
  const ctx=document.getElementById('chart-severity');
  if(!ctx) return;
  const order=['Critical','High','Medium','Low','Normal'];
  const map=Object.fromEntries(data.map(d=>[d[0],d[1]]));
  const labels=order.filter(k=>map[k]!==undefined);
  const values=labels.map(k=>map[k]||0);
  const colors={'Critical':'#ff3366','High':'#ff8c00','Medium':'#ffcc00','Low':'#00e676','Normal':'#445566'};
  if(sevChartInstance) sevChartInstance.destroy();
  sevChartInstance=new Chart(ctx,{
    type:'bar',
    data:{labels,datasets:[{label:'Count',data:values,backgroundColor:labels.map(l=>colors[l]+'bb'),borderColor:labels.map(l=>colors[l]),borderWidth:1,borderRadius:4}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#0d1b2e',borderColor:'rgba(0,212,255,.3)',borderWidth:1,titleColor:'#00d4ff',bodyColor:'#7f9ab5'}},
      scales:{x:{grid:{display:false},ticks:{color:'#445566'}},y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#445566'},beginAtZero:true}}}
  });
}

function renderAnalytics() {
  // Top attack types
  const el=document.getElementById('top-types-list');
  if(el && state.alerts.length) {
    const counts={};
    state.alerts.forEach(a=>{ counts[a[3]]=(counts[a[3]]||0)+1; });
    const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
    const max=sorted[0]?.[1]||1;
    el.innerHTML=sorted.map(([k,v],i)=>`<li>
      <span class="top-rank">${i+1}</span>
      <span style="flex:1;font-size:.78rem;color:var(--t1)">${k}</span>
      <div class="top-bar-bg"><div class="top-bar-f" style="width:${(v/max*100).toFixed(0)}%"></div></div>
      <span class="top-count">${v}</span>
    </li>`).join('');
  }
  // Duplicate timeline on analytics page
  const ctx2=document.getElementById('chart-timeline-2');
  if(ctx2 && state.charts.timeline) {
    if(state.charts.timeline2) state.charts.timeline2.destroy();
    const src=state.charts.timeline;
    state.charts.timeline2=new Chart(ctx2,{
      type:'bar',
      data:{labels:src.data.labels,datasets:[{label:'Events',data:src.data.datasets[0].data,backgroundColor:'rgba(0,212,255,.35)',borderColor:'#00d4ff',borderWidth:1,borderRadius:3}]},
      options:{responsive:true,maintainAspectRatio:false,animation:false,
        plugins:{legend:{display:false},tooltip:{backgroundColor:'#0d1b2e',borderColor:'rgba(0,212,255,.3)',borderWidth:1,titleColor:'#00d4ff',bodyColor:'#7f9ab5'}},
        scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#445566',font:{size:9}}},y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#445566'},beginAtZero:true}}}
    });
  }
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportCSV() {
  const rows=[['ID','Time','Severity','Attack Type','Source IP','Protocol','Port','MITRE Technique','Kill Chain','Risk Score','Message']];
  state.alerts.forEach(a=>{
    const [id,msg,sev,type]=a;
    const m=MITRE[type]||MITRE['Normal'];
    rows.push([id,getTimestamp(a),sev,type,getIP(a),getProto(id),getPort(id),m.tech,m.kc,getRisk(sev),'"'+(msg||'').replace(/"/g,"''")+'"']);
  });
  const csv=rows.map(r=>r.join(',')).join('\n');
  const a=document.createElement('a'); a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download=`cyberwolf_alerts_${Date.now()}.csv`; a.click();
}

// ── Clear Logs ────────────────────────────────────────────────────────────────
async function clearLogs() {
  if(!confirm('⚠ This will permanently delete all logs and alerts. Continue?')) return;
  await fetch('/api/clear_logs',{method:'POST'});
  fetchAll();
}

// ── Email Modal ───────────────────────────────────────────────────────────────
function openEmailModal() {
  document.getElementById('modal-email-input').value=document.getElementById('display-email').textContent.trim();
  document.getElementById('modal-fb').textContent='';
  document.getElementById('email-modal').classList.add('open');
}
function closeEmailModal() { document.getElementById('email-modal').classList.remove('open'); }
document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('email-modal')?.addEventListener('click',e=>{ if(e.target.id==='email-modal') closeEmailModal(); });
  document.getElementById('modal-email-input')?.addEventListener('keydown',e=>{ if(e.key==='Enter') saveEmail(); if(e.key==='Escape') closeEmailModal(); });
});
async function saveEmail() {
  const email=document.getElementById('modal-email-input').value.trim();
  const fb=document.getElementById('modal-fb');
  if(!email||!email.includes('@')){fb.style.color='var(--red)';fb.textContent='⚠ Enter a valid email.';return;}
  const res=await fetch('/api/update_email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
  const d=await res.json();
  if(d.status==='success'){
    document.getElementById('display-email').textContent=d.email;
    document.getElementById('user-avatar').textContent=d.email[0].toUpperCase();
    fb.style.color='var(--green)'; fb.textContent='✔ Updated!';
    setTimeout(closeEmailModal,1000);
  } else { fb.style.color='var(--red)'; fb.textContent='⚠ '+(d.message||'Error'); }
}

// ── Filters & Sort ────────────────────────────────────────────────────────────
function alertSearch(v) { state.alertsFilter.search=v; renderAlertsTable(); }
function alertSevFilter(v) { state.alertsFilter.severity=v; renderAlertsTable(); }
function alertTypeFilter(v) { state.alertsFilter.type=v; renderAlertsTable(); }
function logSearch(v) { state.logsFilter.search=v; renderLogsTable(); }
function logTypeFilter(v) { state.logsFilter.type=v; renderLogsTable(); }

// ── Admin Functions ───────────────────────────────────────────────────────────
async function loadAdminUsers() {
  const tbody = document.getElementById('admin-users-tbody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/users');
    const d = await res.json();
    if (!d.users) return;
    tbody.innerHTML = '';
    d.users.forEach(u => {
      const role = u.is_admin ? '<span class="badge badge-critical">Admin</span>' : '<span class="badge badge-medium">Operator</span>';
      const actions = u.is_admin
        ? '<span style="color:var(--t3);font-size:.72rem">—</span>'
        : `<button class="btn btn-cyan" style="font-size:.68rem;padding:4px 10px" onclick="adminClearLogs(${u.id})"><i class="fas fa-eraser"></i> Clear Logs</button>
           <button class="btn btn-red" style="font-size:.68rem;padding:4px 10px;margin-left:4px" onclick="adminDeleteUser(${u.id},'${u.email}')"><i class="fas fa-trash"></i> Delete</button>`;
      tbody.innerHTML += `<tr><td class="mono">${u.id}</td><td style="color:var(--cyan)">${u.email}</td><td>${role}</td><td>${actions}</td></tr>`;
    });
  } catch (e) { console.error('Admin fetch error:', e); }
}

async function adminClearLogs(uid) {
  if (!confirm('Clear all logs and alerts for this user?')) return;
  await fetch(`/api/users/${uid}/clear`, { method: 'POST' });
  alert('Logs cleared.');
}

async function adminDeleteUser(uid, email) {
  if (!confirm(`Delete user ${email}? This will remove their account and all data.`)) return;
  const res = await fetch(`/api/users/${uid}`, { method: 'DELETE' });
  const d = await res.json();
  if (d.status === 'success') { loadAdminUsers(); }
  else { alert(d.message || 'Error'); }
}

// ── Auto refresh (10s — reduced from 5s for stability) ───────────────────────
fetchAll();
setInterval(fetchAll, 10000);
