package dashboard

const setupHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenWAAP Console — Installer</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23f6821f'/%3E%3Ctext x='16' y='22' font-family='system-ui,sans-serif' font-size='17' font-weight='800' fill='%23fff' text-anchor='middle'%3EW%3C/text%3E%3C/svg%3E">
<style>
:root{--bg:#f6f7f9;--card:#fff;--line:#e6e8ec;--txt:#1c2733;--mut:#6b7688;--acc:#f6821f;--acc2:#e06f10;--ok:#16a34a;--err:#c53030;--rad:14px}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
.wrap{max-width:760px;margin:0 auto;padding:40px 20px 60px}
.logo{font-weight:800;font-size:20px;letter-spacing:-.2px;display:flex;align-items:center;gap:10px;margin-bottom:4px}
.sub{color:var(--mut);margin-bottom:28px}
.steps{display:flex;gap:6px;margin-bottom:26px}
.step{flex:1;text-align:center;padding:9px 4px;border-radius:9px;background:#eceef2;color:var(--mut);font-size:12px;font-weight:600;border:1px solid transparent}
.step.on{background:#fdeeda;color:#8a4a00;border-color:#ffd59e}
.step.done{background:#e3f4e8;color:#11733b}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--rad);padding:26px 28px;box-shadow:0 1px 3px rgba(16,24,40,.05)}
h2{margin:0 0 6px;font-size:19px}
.lead{color:var(--mut);margin:0 0 20px;line-height:1.5}
label{display:block;font-weight:600;font-size:13px;margin:14px 0 5px}
input,select{width:100%;padding:9px 11px;border:1px solid #ccd2da;border-radius:9px;font-size:14px;background:#fff;color:var(--txt)}
input:focus,select:focus{outline:2px solid #ffd9a8;border-color:var(--acc)}
.row{display:flex;gap:12px}.row>div{flex:1}
.tgl{display:flex;align-items:center;justify-content:space-between;padding:11px 4px;border-bottom:1px solid #f0f2f5}
.tgl:last-child{border-bottom:0}
.tgl b{font-size:14px}.tgl span{display:block;color:var(--mut);font-size:12px;margin-top:2px}
.sw{position:relative;width:40px;height:22px;flex:0 0 40px}
.sw input{opacity:0;width:0;height:0;position:absolute}
.sl{position:absolute;inset:0;background:#ccd2da;border-radius:999px;transition:.15s;cursor:pointer}
.sl:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+.sl{background:var(--acc)}
.sw input:checked+.sl:before{transform:translateX(18px)}
.btnrow{display:flex;justify-content:space-between;margin-top:24px;gap:10px}
button{cursor:pointer;border:0;border-radius:9px;font-weight:700;font-size:14px;padding:10px 18px}
.btn{background:#eef0f4;color:var(--txt)}
.btn:hover{background:#e2e5ea}
.primary{background:linear-gradient(180deg,var(--acc),var(--acc2));color:#fff}
.primary:hover{filter:brightness(1.04)}
.primary:disabled{opacity:.5;cursor:not-allowed}
.err{color:var(--err);font-size:13px;margin-top:10px;min-height:18px}
.field-err{border-color:var(--err)!important;box-shadow:0 0 0 3px rgba(197,48,48,.15)}
.ok{color:var(--ok)}
.mini{font-size:12px;color:var(--mut)}
.kv{display:grid;grid-template-columns:180px 1fr;gap:8px 14px;font-size:13.5px}
.kv b{color:var(--mut);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;background:#eef0f4;font-size:12px;font-weight:600;color:#39424e}
.hidden{display:none}
.done-box{text-align:center;padding:18px 0 6px}
.done-box .big{font-size:30px}
#installing{pointer-events:none;opacity:.65}
pre.sum{background:#f2f4f7;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px;max-height:200px}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">OpenWAAP&nbsp;Console</div>
  <div class="sub">First-run installer &middot; configure the edge and go live in minutes</div>

  <div class="steps" id="steps"></div>

  <div class="card" id="card">
    <!-- STEP 0: listeners -->
    <div class="pane" id="p0">
      <h2>Listeners &amp; TLS</h2>
      <p class="lead">The addresses the edge binds, and how the TLS listener is provisioned. HTTPS is always encrypted; the HTTP listener 308-redirects to HTTPS.</p>
      <div class="err" id="p0e"></div>
      <label>HTTPS listen address</label>
      <input id="iListH" value=":8443" spellcheck="false">
      <label>HTTP redirect address <span class="mini">(leave empty to disable)</span></label>
      <input id="iListP" value=":8080" spellcheck="false">
      <label>TLS certificate source</label>
      <select id="iTlsMode">
        <option value="selfsigned">Generate self-signed certificate (fastest)</option>
        <option value="custom">Provide my own certificate files</option>
      </select>
      <div id="tlsCustom">
        <div class="row">
          <div><label>Certificate PEM path</label><input id="iCert" placeholder="/etc/openwaap/certs/fullchain.pem" spellcheck="false"></div>
          <div><label>Key PEM path</label><input id="iKey" placeholder="/etc/openwaap/certs/privkey.pem" spellcheck="false"></div>
        </div>
        <p class="mini">Copy your certificate here before installing; the edge verifies the files exist.</p>
      </div>
    </div>

    <!-- STEP 1: origin -->
    <div class="pane hidden" id="p1">
      <h2>Your origin</h2>
      <p class="lead">The public hostname you are protecting and the backend server it points to.</p>
      <div class="err" id="p1e"></div>
      <label>Public hostname</label>
      <input id="iHost" placeholder="example.com" spellcheck="false">
      <div class="row">
        <div style="max-width:130px"><label>Scheme</label><select id="iScheme"><option>http</option><option>https</option></select></div>
        <div><label>Origin host</label><input id="iOHost" placeholder="127.0.0.1" spellcheck="false"></div>
        <div style="max-width:130px"><label>Port</label><input id="iOPort" value="8080" spellcheck="false"></div>
      </div>
      <label>Web application firewall mode</label>
      <select id="iWaf">
        <option value="block">Block — enforce protection (recommended)</option>
        <option value="detection">Detection — log attacks only</option>
        <option value="disabled">Disabled — bypass WAF</option>
      </select>
    </div>

    <!-- STEP 2: protection profile -->
    <div class="pane hidden" id="p2">
      <h2>Protection profile</h2>
      <p class="lead">Pick a posture; each can be tuned after install from the console.</p>
      <div class="err" id="p2e"></div>
      <div class="row" style="margin-bottom:6px">
        <button class="btn" id="presetBasic" style="flex:1;height:auto;padding:14px">Basic<br><span class="mini">WAF + header hardening</span></button>
        <button class="btn" id="presetStd" style="flex:1;height:auto;padding:14px">Standard<br><span class="mini">+ rate limit, bot, DDoS</span></button>
        <button class="btn" id="presetStrict" style="flex:1;height:auto;padding:14px">Strict<br><span class="mini">+ paranoia 2, lockdown</span></button>
      </div>
      <p class="mini" id="presetDesc"></p>
      <div>
        <div class="tgl"><div><b>Rate limiting</b><span>Per-IP sliding-window request caps</span></div><label class="sw"><input type="checkbox" id="tRl"><span class="sl"></span></label></div>
        <div class="tgl"><div><b>Bot detection</b><span>UA heuristics + reputation learning</span></div><label class="sw"><input type="checkbox" id="tBot"><span class="sl"></span></label></div>
        <div class="tgl"><div><b>DDoS guard (layer 7)</b><span>Per-IP burst + site-wide defense mode</span></div><label class="sw"><input type="checkbox" id="tDdos"><span class="sl"></span></label></div>
        <div class="tgl"><div><b>Proof-of-work challenge</b><span>Human interstitial before protected content</span></div><label class="sw"><input type="checkbox" id="tCh"><span class="sl"></span></label></div>
        <div class="tgl"><div><b>Security response headers</b><span>HSTS, X-Frame-Options, nosniff, referrer-policy</span></div><label class="sw"><input type="checkbox" id="tHdrs"><span class="sl"></span></label></div>
      </div>
    </div>

    <!-- STEP 3: admin -->
    <div class="pane hidden" id="p3">
      <h2>Administrator</h2>
      <p class="lead">Console credentials for <code>https://&lt;edge&gt;/-/</code>. Choose a strong password and keep it safe.</p>
      <div class="err" id="p3e"></div>
      <div class="row">
        <div><label>Admin username</label><input id="iUser" value="admin" spellcheck="false"></div>
        <div><label>Password <span class="mini">(min 12 chars, no username/hostname)</span></label><input id="iPass" type="password"></div>
      </div>
      <label>Confirm password</label><input id="iPass2" type="password">
      <label>Admin access (CIDR / IP, comma-separated)</label>
      <input id="iAdminIps" placeholder="203.0.113.7/32, 198.51.100.0/24" spellcheck="false">
      <p class="mini">When non-empty, the login page and console are reachable only from these source addresses; everyone else gets 404. Leave empty to allow the listener&rsquo;s reach (credentials still gate data). See kurulum.md for the SSH-tunnel alternative.</p>
      <label>HMAC signing secret</label>
      <div style="display:flex;gap:8px"><input id="iHmac" readonly style="font-family:monospace;font-size:13px"><button type="button" class="btn" onclick="genHmac()" style="white-space:nowrap">Regenerate</button></div>
      <p class="mini">Signs admin sessions and challenge proofs. Keep it secret &mdash; anyone with it can mint sessions.</p>
      <label>Console path <span class="mini">(hidden login URL, not guessable by scanners)</span></label>
      <div style="display:flex;gap:8px"><input id="iConsolePath" readonly style="font-family:monospace;font-size:13px"><button type="button" class="btn" onclick="genConsolePath()" style="white-space:nowrap">Regenerate</button></div>
      <p class="mini">Write this down: after install the console only answers at <code>https://&lt;edge&gt;<span id="consolePathHint"></span>/login</code> &mdash; <code>/-/login</code> stops resolving.</p>
    </div>

    <!-- STEP 4: review -->
    <div class="pane hidden" id="p4">
      <h2>Review &amp; install</h2>
      <p class="lead">Confirm the configuration below. The edge persists it to disk, then restarts itself; you will be redirected to the sign-in page.</p>
      <div class="kv" id="reviewSum"></div>
      <pre class="sum" id="reviewYaml"></pre>
      <div class="err" id="p4e"></div>
    </div>

    <!-- installing -->
    <div class="pane hidden" id="pInst">
      <div class="done-box"><div class="big">⚙</div><h2 style="margin:8px 0 4px">Configuring the edge&hellip;</h2><p class="lead" style="margin:0">The edge is applying your configuration and restarting. Hold tight.</p><p class="mini" id="instTip"></p></div>
    </div>

    <!-- success -->
    <div class="pane hidden" id="pDone">
      <div class="done-box"><div class="big">✓</div><h2 style="margin:8px 0 4px">OpenWAAP is installed</h2><p class="lead">The edge is live with your configuration. Continue to the console to monitor traffic and tune protection.</p>
      <p><a href="/-/login" id="doneLink" style="color:var(--acc);font-weight:700;text-decoration:none">Continue to console &rarr;</a></p></div>
    </div>

    <div class="btnrow" id="navrow">
      <button class="btn" id="btnBack" onclick="prev()">Back</button>
      <button class="primary" id="btnNext" onclick="next()">Continue</button>
    </div>
  </div>
  <p class="mini" style="margin-top:16px;text-align:center">OpenWAAP &middot; operator console installer</p>
</div>

<script>
const S = { step:0, preset:'standard',
  tls:{mode:'selfsigned',cert:'',key:''} };
const STEPS = ['Listeners','Origin','Profile','Admin','Review'];

function genHmac(){const a=new Uint8Array(32);crypto.getRandomValues(a);document.getElementById('iHmac').value=Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');}
function genConsolePath(){
  const a=new Uint8Array(4);crypto.getRandomValues(a);
  const p='/ops-'+Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
  document.getElementById('iConsolePath').value=p;
  document.getElementById('consolePathHint').textContent=p;
}
function preset(name){
  S.preset=name;
  const d=document.getElementById('presetDesc');
  const on=id=>{document.getElementById(id).checked=true;};
  const off=id=>{document.getElementById(id).checked=false;};
  if(name==='basic'){off('tRl');off('tBot');off('tDdos');off('tCh');on('tHdrs');d.textContent='Managed-waf ruleset + origin firewall + hardening headers. Quietest false-positive profile.';
    document.getElementById('iWaf').value='block';}
  else if(name==='standard'){on('tRl');on('tBot');on('tDdos');off('tCh');on('tHdrs');d.textContent='Adds per-IP rate limits, bot detection and the layer-7 DDoS guard.';}
  else {on('tRl');on('tBot');on('tDdos');on('tCh');on('tHdrs');document.getElementById('iWaf').value='block';d.textContent='Everything on, stricter managed ruleset (paranoia 2) and JavaScript proof-of-work gate. Start here for high-value targets.';}
  hlPreset();
}
function hlPreset(){
  ['basic','std','strict'].forEach(p=>{
    const b=document.getElementById('preset'+p[0].toUpperCase()+p.slice(1));
    b.style.background = S.preset===p ? 'linear-gradient(180deg,var(--acc),var(--acc2))' : '';
    b.style.color = S.preset===p ? '#fff' : '';
  });
}
function renderSteps(){
  document.getElementById('steps').innerHTML = STEPS.map((s,i)=>
    '<div class="step'+(i<S.step?' done':(i===S.step?' on':''))+'">'+s+'</div>').join('');
}
function showPane(i){
  for(let k=0;k<=4;k++)document.getElementById('p'+k).classList.toggle('hidden',k!==i);
  document.getElementById('pInst').classList.add('hidden');
  document.getElementById('pDone').classList.add('hidden');
  document.getElementById('navrow').style.display='flex';
  document.getElementById('btnBack').style.visibility = i===0 ? 'hidden':'visible';
  document.getElementById('btnNext').textContent = i===4 ? 'Install OpenWAAP' : 'Continue';
}
function fieldsFor(i){
  if(i===0)return ['iCert','iKey'];
  if(i===1)return ['iHost','iOHost','iOPort'];
  if(i===3)return ['iUser','iPass','iPass2'];
  return [];
}
function markFieldErr(ids){
  ids.forEach(id=>{const el=document.getElementById(id);if(el)el.classList.add('field-err');});
}
function clearFieldErr(i){
  fieldsFor(i).forEach(id=>{const el=document.getElementById(id);if(el)el.classList.remove('field-err');});
}
function validate(i){
  const err=document.getElementById('p'+i+'e');
  if(err)err.textContent='';
  clearFieldErr(i);
  if(i===0){
    S.tls.mode=document.getElementById('iTlsMode').value;
    S.tls.cert=document.getElementById('iCert').value.trim();
    S.tls.key=document.getElementById('iKey').value.trim();
    if(S.tls.mode==='custom'&&(!S.tls.cert||!S.tls.key)){
      if(err)err.textContent='Fill in both certificate and key paths (or switch to self-signed).';
      markFieldErr([!S.tls.cert?'iCert':null,!S.tls.key?'iKey':null].filter(Boolean));
      return false;
    }
    return true;
  }
  if(i===1){
    const noHost=!document.getElementById('iHost').value.trim();
    const noOHost=!document.getElementById('iOHost').value.trim();
    const noOPort=!document.getElementById('iOPort').value.trim();
    if(noHost||noOHost||noOPort){
      if(err)err.textContent=noHost?'Enter the public hostname you are protecting.':'Set the origin host and port.';
      markFieldErr([noHost?'iHost':null,noOHost?'iOHost':null,noOPort?'iOPort':null].filter(Boolean));
      return false;
    }
    return true;
  }
  if(i===3){
    const u=document.getElementById('iUser').value.trim(),p=document.getElementById('iPass').value,p2=document.getElementById('iPass2').value;
    const host=(document.getElementById('iHost').value||'').trim().toLowerCase();
    const lp=p.toLowerCase();
    if(!u){if(err)err.textContent='Choose an admin username.';markFieldErr(['iUser']);return false;}
    if(p.length<12){if(err)err.textContent='Password must be at least 12 characters.';markFieldErr(['iPass']);return false;}
    if(u&&lp.includes(u.toLowerCase())){if(err)err.textContent='Password must not contain the admin username.';markFieldErr(['iPass']);return false;}
    if(host&&lp.includes(host)){if(err)err.textContent='Password must not contain the protected hostname.';markFieldErr(['iPass']);return false;}
    if(p!==p2){if(err)err.textContent='Passwords do not match.';markFieldErr(['iPass','iPass2']);return false;}
    if(!document.getElementById('iHmac').value){genHmac();}
    return true;
  }
  return true;
}
function want(id){return document.getElementById(id).checked;}
function buildConfig(){
  const strict=S.preset==='strict';
  const hasRl=want('tRl'), hasBot=want('tBot'), hasDdos=want('tDdos'),
        hasCh=want('tCh'), hasHdrs=want('tHdrs');
  const host=document.getElementById('iHost').value.trim();
  const selfsigned=S.tls.mode==='selfsigned';
  return {
    version:'1',
    server:{
      listen_https:document.getElementById('iListH').value.trim()||':443',
      listen_http:document.getElementById('iListP').value.trim(),
      tls_cert_file:selfsigned?'':S.tls.cert,
      tls_key_file:selfsigned?'':S.tls.key,
    },
    security:{
      engine_fail_mode:strict?'fail_closed':'fail_open',
      hmac_secret:document.getElementById('iHmac').value,
      challenge: hasCh?{enabled:true,difficulty:4,ttl:'600s',proof_ttl:'180s'}:{enabled:false,difficulty:4,ttl:'600s',proof_ttl:'180s'},
      headers: hasHdrs?{hsts:true,frame_options:strict?'DENY':'SAMEORIGIN',no_sniff:true,referrer_policy:'strict-origin-when-cross-origin',csp:''}:null,
      ddos: hasDdos?{enabled:true,per_ip_rate:strict?20:40,per_ip_action:'challenge',site_burst_rps:strict?500:2000,defense_action:'challenge',defense_ttl:'60s',allowlist:[]}:null,
      store:{type:'memory'},
    },
    log:{rotation_max_mb:0,rotation_keep:5},
    dashboard:{enabled:true,listen:'',admin_user:document.getElementById('iUser').value.trim(),admin_password:document.getElementById('iPass').value,admin_allowlist:document.getElementById('iAdminIps').value.split(',').map(s=>s.trim()).filter(Boolean),session_ttl:'12h',max_events:10000,console_path:document.getElementById('iConsolePath').value},
    ui:{},
    domains:[{
      hostname:host,enabled:true,
      origin:{scheme:document.getElementById('iScheme').value,host:document.getElementById('iOHost').value.trim(),port:document.getElementById('iOPort').value.trim()},
      waf:{mode:document.getElementById('iWaf').value,managed:{ruleset_version:'1.0.0',paranoia_level:strict?2:1,categories:{}},custom_rules:[]},
      rate_limits: hasRl?{enabled:true,limits:[{id:'global',name:'Global per-IP',enabled:true,scope:'ip',max:strict?10:60,throttle_max:strict?20:120,window:'60s',action:'RATE_LIMIT'}]}:null,
      bot: hasBot?{enabled:true,challenge_below:strict?30:20,block_below:strict?10:5,verified_bots:[]}:null,
    }],
  };
}
async function install(){
  const cfg=buildConfig();
  const btn=document.getElementById('btnNext');btn.disabled=true;
  document.getElementById('p4e').textContent='';
  document.getElementById('instTip').textContent='Writing configuration and provisioning TLS…';
  showInstalling();
  try{
    const r=await fetch('/-/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({config:cfg,generate_cert:S.tls.mode==='selfsigned',hosts:[document.getElementById('iHost').value.trim()]})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok){showRegret();document.getElementById('p4e').textContent='Install failed: '+(j.error||r.status);btn.disabled=false;return;}
    showDone();
    setTimeout(()=>{location.href='/-/login';},1800);
  }catch(e){
    showRegret();document.getElementById('p4e').textContent='Network error: '+e;
    btn.disabled=false;
  }
}
function showInstalling(){for(let k=0;k<=4;k++)document.getElementById('p'+k).classList.add('hidden');document.getElementById('pInst').classList.remove('hidden');document.getElementById('navrow').style.display='none';}
function showDone(){for(let k=0;k<=4;k++)document.getElementById('p'+k).classList.add('hidden');document.getElementById('pInst').classList.add('hidden');document.getElementById('pDone').classList.remove('hidden');document.getElementById('navrow').style.display='none';}
function showRegret(){document.getElementById('p4').classList.remove('hidden');document.getElementById('pInst').classList.add('hidden');document.getElementById('navrow').style.display='flex';}
function next(){
  if(!validate(S.step))return;
  if(S.step===4){install();return;}
  S.step++;renderSteps();showPane(S.step);
}
function prev(){if(S.step===0)return;S.step--;renderSteps();showPane(S.step);}

document.getElementById('iTlsMode').addEventListener('change',e=>{
  document.getElementById('tlsCustom').classList.toggle('hidden',e.target.value==='selfsigned');
});
['presetBasic','presetStd','presetStrict'].forEach(id=>{
  document.getElementById(id).addEventListener('click',()=>{S.preset=id==='presetBasic'?'basic':(id==='presetStd'?'standard':'strict');preset(S.preset);});
});
preset('standard');
genHmac();
genConsolePath();
renderSteps();showPane(0);
document.querySelectorAll('input,select').forEach(el=>{
  const clear=()=>el.classList.remove('field-err');
  el.addEventListener('input',clear);
  el.addEventListener('change',clear);
});
</script>
</body>
</html>`
