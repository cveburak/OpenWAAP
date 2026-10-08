package dashboard

const panelHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenWAAP</title>
<style>
  :root { --bg:#f4f6fb; --panel:#ffffff; --border:#e3e8f0; --text:#1f2d3d; --muted:#7c8798;
          --hover:#f0f3f9; --ripple:#f7fafc; --line:#f1f4f9; --chip:#eef1f7; --field:#fbfcfe;
          --heading:#122033;
          --shadow:0 1px 2px rgba(16,44,87,.04), 0 4px 14px rgba(16,44,87,.05);
          --accent:#f6821f; --accent-deep:#c9670d; --accent-soft:#fff3e4; --focus:rgba(246,130,31,.14);
          --blue:#2563eb; --ok:#16a34a; --danger:#dc2626; --warn:#d97706;
          --rad:12px; --pad-r:18px; --pad-v:16px; --font-s:14px; --gap-s:16px; }
  body[data-theme="emerald"]  { --bg:#e2efe7; --panel:#f2f9f4; --border:#c3e0cd; --text:#1b3a26; --muted:#59745f; --heading:#0f2f1a;
          --hover:#e1f1e7; --ripple:#f7fbf8; --line:#e6f2ea; --chip:#d5eadd; --field:#ecf7ef;
          --accent:#16a34a; --accent-deep:#15803d; --accent-soft:#ddf2e4; --focus:rgba(22,163,74,.16); }
  body[data-theme="sapphire"] { --bg:#dce8f7; --panel:#eff5fd; --border:#bfd6ef; --text:#15283e; --muted:#576b8a; --heading:#0d1f36;
          --hover:#dce9fa; --ripple:#f5f9fe; --line:#e4eefa; --chip:#d3e2f6; --field:#e8f0fb;
          --accent:#2563eb; --accent-deep:#1d4ed8; --accent-soft:#dbe8ff; --focus:rgba(37,99,235,.16); }
  body[data-theme="amethyst"] { --bg:#e6def4; --panel:#f5f1fb; --border:#d2c5ec; --text:#291c40; --muted:#675d85; --heading:#1c1033;
          --hover:#e7dff7; --ripple:#faf8fd; --line:#ece5f7; --chip:#ded2f1; --field:#f0eafa;
          --accent:#7c3aed; --accent-deep:#6d28d9; --accent-soft:#e7dcff; --focus:rgba(124,58,237,.16); }
  body[data-theme="coral"]    { --bg:#f5e0e5; --panel:#fdf3f5; --border:#eec7d1; --text:#3c1a25; --muted:#895460; --heading:#2e1020;
          --hover:#f4e1e7; --ripple:#fdf8f9; --line:#f5e6eb; --chip:#f0d8df; --field:#f8e9ed;
          --accent:#e11d48; --accent-deep:#be123c; --accent-soft:#fbd7e1; --focus:rgba(225,29,72,.16); }
  body[data-theme="graphite"] { --bg:#e2e4e9; --panel:#f4f5f7; --border:#cfd3db; --text:#242b34; --muted:#64707d; --heading:#141a22;
          --hover:#e6e9ed; --ripple:#f8f9fa; --line:#e9ebef; --chip:#dde1e7; --field:#edf0f3;
          --accent:#334155; --accent-deep:#1e293b; --accent-soft:#e2e7ee; --focus:rgba(51,65,85,.16); }
  body[data-theme="night"]    { --bg:#0c1117; --panel:#161d26; --border:#27303d; --text:#e3e9f0; --muted:#8b96a5;
          --heading:#f4f7fa; --hover:#1b2430; --ripple:#202a37; --line:#212a38; --chip:#1e2733; --field:#0f151d;
          --shadow:0 1px 2px rgba(0,0,0,.4), 0 4px 16px rgba(0,0,0,.25);
          --accent:#f6821f; --accent-deep:#fb923c; --accent-soft:#3a2a17; --focus:rgba(246,130,31,.22);
          color-scheme:dark; }
  body[data-density="compact"] { --pad-r:12px; --pad-v:10px; --font-s:13px; --gap-s:10px; }
  * { box-sizing:border-box; }
  html,body { margin:0; height:100%; }
  body { background:var(--bg); color:var(--text);
         font-family: system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
         font-size:var(--font-s); display:flex; }
  aside { width:256px; min-width:256px; background:var(--panel); border-right:1px solid var(--border);
          display:flex; flex-direction:column; }
  .brand { display:flex; align-items:center; gap:11px; padding:20px 18px 14px; }
  .brand .name { font-weight:800; font-size:16px; letter-spacing:.2px; color:var(--heading); }
  .brand .name small { display:block; font-weight:500; color:var(--muted); font-size:10.5px; letter-spacing:.2px; }
  #search { margin:4px 10px 4px; padding:8px 10px 8px 30px; background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='none' stroke='%237c8798' stroke-width='2' viewBox='0 0 24 24'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m20 20-3.5-3.5'/%3E%3C/svg%3E");
           background-repeat:no-repeat; background-position:10px 50%; }
  nav { flex:1; overflow-y:auto; padding:2px 12px 18px; transition:all .15s; }
  nav .grp { display:flex; align-items:center; justify-content:space-between; gap:8px; width:100%;
             margin:16px 2px 4px; padding:5px 10px; border:0; background:none; font:inherit;
             font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:1.1px;
             color:var(--muted); cursor:pointer; white-space:nowrap; }
  nav .grp:hover { color:var(--text); }
  nav .grp .tc { font-size:9px; line-height:1; transition:transform .15s; }
  nav .grp[aria-expanded="false"] .tc { transform:rotate(-90deg); }
  nav .gitems.collapsed { display:none; }
  nav a { display:flex; align-items:center; gap:8px; padding:8px 12px; border-radius:8px;
          color:var(--text); text-decoration:none; margin:1px 0; cursor:pointer; transition:background .12s; }
  nav a:hover { background:var(--hover); }
  nav a.on { background:var(--accent-soft); color:var(--accent-deep); font-weight:700; }
  nav .cnt { color:var(--muted); font-size:11px; margin:12px 12px 0; font-style:italic; display:none; }
  nav .cnt.show { display:block; }
  aside .foot { padding:12px 18px; border-top:1px solid var(--border); color:var(--muted); font-size:11.5px;
                display:flex; justify-content:space-between; gap:8px; }
  main { flex:1; display:flex; flex-direction:column; min-width:0; }
  header { background:var(--panel); border-bottom:1px solid var(--border);
           padding:0 22px; height:58px; display:flex; align-items:center; gap:12px; }
  header h1 { font-size:16px; font-weight:700; margin:0; }
  header .crumb { color:var(--muted); font-size:12px; }
  header .spacer { flex:1; }
  .dirty-dot { width:8px; height:8px; border-radius:50%; background:var(--accent); opacity:0; transition:opacity .2s; }
  .dirty-dot.show { opacity:1; animation:pulse 1.4s infinite; }
  @keyframes pulse { 50%{ opacity:.25; } }
  .btn { border:1px solid var(--border); background:var(--panel); color:var(--text); padding:7px 14px;
         border-radius:8px; font:inherit; font-weight:600; cursor:pointer; display:inline-flex;
         align-items:center; gap:7px; transition:background .1s, box-shadow .1s; }
  .btn:hover { background:var(--hover); }
  .btn.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  .btn.primary:hover { background:var(--accent-deep); }
  .btn.danger { color:var(--danger); border-color:#f3cccc; }
  .btn.danger:hover { background:#fdf0f0; }
  .btn[disabled] { opacity:.5; cursor:not-allowed; }
  .btn.sm { padding:4px 9px; font-size:12px; }
  .wrap { flex:1; overflow-y:auto; padding:var(--pad-r); max-width:1120px; width:100%; margin:0 auto; }
  .spin { width:22px; height:22px; border:3px solid var(--border); border-top-color:var(--accent);
          border-radius:50%; margin:30px auto; animation:spin 1s linear infinite; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:var(--rad); padding:var(--pad-v) var(--pad-r);
          box-shadow:var(--shadow); }
  .stat .lbl { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); }
  .stat .big { font-size:26px; font-weight:800; margin-top:4px; }
  .stat.ok .big { color:var(--ok); } .stat.bad .big { color:var(--danger); }
  .stat.warn .big { color:var(--warn); } .stat.info .big { color:var(--blue); }
  .sharebar { display:flex; height:8px; border-radius:999px; overflow:hidden; margin-top:10px; gap:1px; }
  .sharebar span { height:100%; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:var(--rad);
           padding:var(--pad-v) var(--pad-r); margin-top:var(--gap-s); box-shadow:var(--shadow); }
  .panel h2 { margin:0 0 12px; font-size:13px; font-weight:700; }
  .panel h2 .muted { font-weight:500; margin-left:8px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:var(--gap-s); }
  @media (max-width:900px){ .grid2{grid-template-columns:1fr;} }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.4px; }
  .bars { display:flex; align-items:flex-end; gap:2px; height:96px; }
  .bar { flex:1; display:flex; flex-direction:column; justify-content:flex-end; gap:1px; min-width:2px;
         background:var(--chip); border-radius:3px 3px 0 0; }
  .bar span { width:100%; display:block; }
  .bar .s-ok { background:#c9d4e4; } .bar .s-blk { background:#f87171; }
  .bar .s-ch { background:#fbbf24; } .bar .s-rl { background:#fb923c; } .bar .s-ua { background:#a78bfa; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; margin-top:8px; font-size:11.5px; color:var(--muted); }
  .legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }
  .share { display:flex; height:10px; border-radius:999px; overflow:hidden; margin-top:8px; gap:1px; }
  .share span { height:100%; }
  .share .sh-allowed { background:#c9d4e4; } .share .sh-blocked { background:#f87171; }
  .share .sh-challenged { background:#fbbf24; } .share .sh-rl { background:#fb923c; }
  .share .sh-unauthorized { background:#a78bfa; }
  .overlay { position:fixed; inset:0; background:rgba(15,23,42,.45); display:none; align-items:flex-start;
             justify-content:center; padding:60px 18px; overflow-y:auto; z-index:60; }
  .overlay.show { display:flex; }
  .modal { background:var(--panel); border:1px solid var(--border); border-radius:14px; width:min(560px,100%);
           box-shadow:0 18px 50px rgba(16,44,87,.25); }
  .modal .mhead { display:flex; align-items:center; gap:10px; padding:14px 18px; border-bottom:1px solid var(--border); }
  .modal .mhead h3 { margin:0; font-size:14px; font-weight:700; flex:1; }
  .modal .mbody { padding:14px 18px; font-size:13px; }
  .modal .mbody dl { margin:0; display:grid; grid-template-columns:auto 1fr; gap:6px 14px; }
  .modal .mbody dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.4px; padding-top:2px; }
  .modal .mbody dd { margin:0; font-weight:600; word-break:break-all; }
  .modal .mbody .rsn { display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
  .modal .mbody .rsn .chip { background:var(--accent-soft); border-color:var(--border); color:var(--accent-deep); }
  .modal .mfoot { display:flex; justify-content:flex-end; gap:8px; padding:12px 18px; border-top:1px solid var(--border); }
  .badge { display:none; align-items:center; gap:5px; background:#fdf3d7; color:#b45309; border:1px solid #f0dfa8;
           border-radius:999px; font-size:11px; font-weight:700; padding:4px 10px; }
  .badge.show { display:inline-flex; }
  .badge .pulse { width:7px; height:7px; border-radius:50%; background:#f59e0b; animation:pulse 1.4s infinite; }
  .stale { opacity:.55; }
  .evq { flex:1; max-width:240px; }
  .evcount { color:var(--muted); font-size:11.5px; }
  .pager { display:flex; align-items:center; justify-content:center; gap:12px; margin-top:14px; }
  .pager .evcount { margin:0; }
  .rowtab td { cursor:pointer; }
  .rowtab tr:hover td { background:var(--ripple); }
  .tag { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:700; }
  .tag.ALLOW { background:#e7f6ec; color:#15803d; } .tag.BLOCK { background:#fde8e8; color:#b91c1c; }
  .tag.CHALLENGE { background:#fdf3d7; color:#b45309; } .tag.RATE_LIMIT { background:#fde9d2; color:#c2410c; }
  .tag.THROTTLE { background:#dfeafe; color:#1d4ed8; } .tag.LOG { background:#eef0f4; color:#64748b; }
  .tag.UNAUTHORIZED { background:#efe7fb; color:#6d28d9; }
  .filters { display:flex; gap:10px; align-items:center; }
  select,input,textarea { border:1px solid var(--border); background:var(--field); color:var(--text);
          border-radius:8px; padding:7px 10px; font:inherit; }
  textarea { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }
  select:focus,input:focus,textarea:focus { outline:none; border-color:var(--accent);
          box-shadow:0 0 0 3px var(--focus); }
  .muted { color:var(--muted); font-size:12px; }
  .sgroup { background:var(--panel); border:1px solid var(--border); border-radius:var(--rad); margin-top:var(--gap-s); overflow:hidden; box-shadow:var(--shadow); }
  .sgroup .head { padding:14px 18px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px; }
  .sgroup .head h3 { margin:0; font-size:14px; font-weight:700; }
  .sgroup .head .note { color:var(--muted); font-size:12px; margin-top:2px; }
  .sgroup .head .spacer { flex:1; }
  .row { display:flex; align-items:center; gap:14px; padding:12px 18px; border-bottom:1px solid var(--line); }
  .row:last-child { border-bottom:0; }
  .row .rl { flex:1; }
  .row .rl .t { font-weight:600; }
  .row .rl .h { color:var(--muted); font-size:12px; margin-top:2px; }
  .row .rc { min-width:200px; max-width:360px; }
  .row .rc input, .row .rc select { width:100%; }
  .row .rc input[type="color"] { width:56px; height:34px; padding:2px; border-radius:8px; cursor:pointer; }
  .navrow .rc { width:104px; }
  .switch { position:relative; display:inline-block; width:44px; height:24px; }
  .switch input { opacity:0; width:0; height:0; }
  .switch .sl { position:absolute; inset:0; background:#cbd5e0; border-radius:999px;
                transition:.18s; cursor:pointer; }
  .switch .sl:before { content:""; position:absolute; width:18px; height:18px; border-radius:50%;
                background:#fff; top:3px; left:3px; transition:.18s; }
  .switch input:checked + .sl { background:var(--accent); }
  .switch input:checked + .sl:before { transform:translateX(20px); }
  .item { border:1px solid var(--border); border-radius:10px; margin:10px 0; padding:10px 14px; background:var(--field); }
  .item .row { padding:8px 0; }
  .sgroup button[data-add] { margin:6px 18px 16px; }
  .toasts { position:fixed; right:20px; bottom:20px; display:flex; flex-direction:column; gap:8px; z-index:50; }
  .toast { background:#1f2d3d; color:#fff; padding:11px 14px; border-radius:10px; font-size:13px;
           box-shadow:0 8px 24px rgba(0,0,0,.18); animation:in .18s ease-out; max-width:380px;
           display:flex; align-items:center; gap:10px; }
  .toast .msg { flex:1; }
  .toast .x { cursor:pointer; opacity:.6; background:none; border:0; color:#fff; font-size:15px; line-height:1; }
  .toast .x:hover { opacity:1; }
  .toast.err { background:#b91c1c; } .toast.ok { background:#15803d; } .toast.warn { background:#b45309; }
  @keyframes in { from{opacity:0; transform:translateY(8px);} to{opacity:1;} }
  @keyframes spin { to { transform:rotate(360deg); } }
  .chips { display:flex; flex-wrap:wrap; gap:6px; }
  .chip { background:var(--chip); border:1px solid var(--border); border-radius:999px;
          padding:5px 11px; font-size:12.5px; display:flex; align-items:center; gap:6px; }
  .chip button { border:0; background:none; color:var(--muted); cursor:pointer; font-size:14px; line-height:1; }
  .chip button:hover { color:var(--danger); }
  .domainpill { background:var(--chip); border:1px solid var(--border); border-radius:999px;
                padding:5px 13px; font-size:12px; font-weight:600; color:var(--muted); }
  .theme { display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted); }
  .theme select { padding:5px 8px; border-radius:8px; }
  .lang select { padding:5px 4px; border-radius:8px; font-weight:700; }
</style>
</head>
<body data-theme="dawn" data-density="comfortable">

<aside>
  <div class="brand">
    <div class="name">OpenWAAP<small>Security console</small></div>
  </div>
  <input id="search" placeholder="Search pages" autocomplete="off">
  <div class="cnt" id="navcnt"></div>
  <nav id="nav"></nav>
  <div class="foot" id="foot"></div>
</aside>

<main>
  <header>
    <h1 id="pagetitle">Overview</h1>
    <span id="domainpill"></span>
    <span class="spacer"></span>
    <span class="dirty-dot" id="dirtyDot" title="Unsaved changes on this page"></span>
    <label class="lang" title="Interface language">
      <select id="langSel">
        <option value="en">EN</option>
        <option value="tr">TR</option>
      </select>
    </label>
    <label class="theme" title="Quick-switch appearance (persisted)">
      <span id="hdrTheme">Theme</span>
      <select id="themeSel">
        <option value="dawn">Dawn (amber)</option>
        <option value="night">Night (dark)</option>
        <option value="emerald">Emerald</option>
        <option value="sapphire">Sapphire</option>
        <option value="amethyst">Amethyst</option>
        <option value="coral">Coral</option>
        <option value="graphite">Graphite</option>
      </select>
    </label>
    <span class="badge" id="restartBadge"><span class="pulse"></span>restart required</span>
    <button class="btn" id="btnRestart" title="Persist current config and restart the edge">&#x21bb;&nbsp;<span id="hdrRestart">Restart</span></button>
    <a class="btn" href="/-/logout"><span id="hdrSignout">Sign out</span></a>
  </header>
  <div class="wrap" id="view"></div>
</main>

<div class="toasts" id="toasts"></div>
<div class="overlay" id="overlay"><div class="modal" id="modal"></div></div>

<script>
"use strict";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const card = (n, l, c) => '<div class="stat ' + c + '"><div class="lbl">' + l + '</div><div class="big">' + esc(n) + "</div></div>";
const $ = id => document.getElementById(id);

let LANG = "en";
const I18N = {
  en: {
    "Overview":"Overview", "Audit log":"Audit log", "Security":"Security",
    "WAF &amp; Rules":"WAF &amp; Rules", "Rate limiting":"Rate limiting", "Bot &amp; reputation":"Bot &amp; reputation",
    "API security":"API security", "Challenge":"Challenge", "DDoS guard":"DDoS guard",
    "Hardening":"Hardening", "Origin &amp; domains":"Origin &amp; domains", "GeoIP / ASN":"GeoIP / ASN",
    "SIEM / audit":"SIEM / audit", "Console &amp; logging":"Console &amp; logging", "Settings &amp; appearance":"Settings &amp; appearance",
    "Analytics":"Analytics", "Configuration":"Configuration", "Origin":"Origin", "Integration":"Integration",
    "theme":"Theme", "search_pages":"Search pages", "restart":"Restart", "sign_out":"Sign out",
    "restart_required":"restart required", "save_page":"Save this page", "remove":"Remove", "add":"Add",
    "items_added":"Item added — save to apply.", "discard":"Discard unsaved changes on this page?",
    "config_saved_restart":"Configuration saved. Restart to apply changes.",
    "config_saved_applied":"Configuration saved &amp; applied.",
    "protection_posture":"Protection posture", "auto_refresh":"Auto-refresh", "auto_refresh_off":"Auto-refresh off",
    "outcome_share":"Outcome share", "blocked_of":"blocked", "attacked_req":"requests carried attack signals",
    "requests_allowed":"Requests allowed", "Blocked":"Blocked", "Challenged":"Challenged",
    "Rate limited":"Rate limited", "Unauthorized":"Unauthorized", "Total evaluated":"Total evaluated",
    "Appearance &amp; theme":"Appearance &amp; theme", "sidebar_layout":"Sidebar layout",
    "search_result":"{shown} of {total} pages match",
    "fail_restart":"Failed to save", "Show":"Show", "Hide":"Hide",
    "Add rule":"Add rule", "Add limit rule":"Add limit rule", "Add route":"Add route", "Add endpoint":"Add endpoint",
    "engine_fail_mode":"Engine fail mode", "fail_open":"fail-open", "fail_closed":"fail-closed",
  },
  tr: {
    "Overview":"Genel bakış", "Audit log":"Denetim kaydı", "Security":"Güvenlik",
    "WAF &amp; Rules":"WAF &amp; kurallar", "Rate limiting":"Hız sınırlama", "Bot &amp; reputation":"Bot &amp; itibar",
    "API security":"API güvenliği", "Challenge":"Doğrulama", "DDoS guard":"DDoS koruması",
    "Hardening":"Sertleştirme", "Origin &amp; domains":"Origin &amp; alanlar", "GeoIP / ASN":"Coğrafi IP / ASN",
    "SIEM / audit":"SIEM / denetim", "Console &amp; logging":"Konsol &amp; kayıt", "Settings &amp; appearance":"Ayarlar &amp; görünüm",
    "Analytics":"Analitik", "Configuration":"Yapılandırma", "Origin":"Origin", "Integration":"Entegrasyon",
    "theme":"Tema", "search_pages":"Sayfa ara", "restart":"Yeniden başlat", "sign_out":"Çıkış",
    "restart_required":"yeniden başlatma gerekli", "save_page":"Bu sayfayı kaydet", "remove":"Kaldır", "add":"Ekle",
    "items_added":"Öğe eklendi — uygulamak için kaydedin.", "discard":"Bu sayfadaki kaydedilmemiş değişiklikler silinsin mi?",
    "config_saved_restart":"Yapılandırma kaydedildi. Değişiklikleri uygulamak için yeniden başlatın.",
    "config_saved_applied":"Yapılandırma kaydedildi ve uygulandı.",
    "protection_posture":"Koruma durumu", "auto_refresh":"Otomatik yenileme", "auto_refresh_off":"Otomatik yenileme kapalı",
    "outcome_share":"Sonuç dağılımı", "blocked_of":"engellendi", "attacked_req":"istek saldırı sinyali taşıyor",
    "requests_allowed":"İzin verilen istekler", "Blocked":"Engellenen", "Challenged":"Doğrulanan",
    "Rate limited":"Hız sınırlı", "Unauthorized":"Yetkisiz", "Total evaluated":"Toplam değerlendirilen",
    "Appearance &amp; theme":"Görünüm &amp; tema", "sidebar_layout":"Yan çubuk düzeni",
    "search_result":"{total} sayfadan {shown} eşleşti",
    "fail_restart":"Kaydedilemedi", "Show":"Göster", "Hide":"Gizle",
    "Add rule":"Kural ekle", "Add limit rule":"Hız sınırı kuralı ekle", "Add route":"Rota ekle", "Add endpoint":"Uç nokta ekle",
    "engine_fail_mode":"Motor hata modu", "fail_open":"açık-hata modu", "fail_closed":"kapalı-hata modu",
  }
};
const t = (k, def) => (I18N[LANG] && I18N[LANG][k]) || def || (LANG === "tr" ? k : def || k);

const THEMES = { dawn:"Dawn (amber)", night:"Night (dark)", emerald:"Emerald", sapphire:"Sapphire", amethyst:"Amethyst", coral:"Coral", graphite:"Graphite" };
const VALID_THEMES = new Set(Object.keys(THEMES));
function applyTheme(t, accent) {
  if (!VALID_THEMES.has(t)) t = t === "custom" ? "custom" : "dawn";
  document.body.setAttribute("data-theme", t);
  if (t === "custom" && accent) { document.documentElement.style.setProperty("--accent", accent); }
  else { document.documentElement.style.removeProperty("--accent"); }
  try { localStorage.setItem("wa_theme", t); localStorage.setItem("wa_accent", accent || ""); } catch (_) {}
}
function applyDensity(d) {
  document.body.setAttribute("data-density", d === "compact" ? "compact" : "comfortable");
}
function applyPrefs() {
  if (!CFG || !CFG.ui) return;
  const u = CFG.ui;
  const t = u.theme || "dawn";
  applyTheme(t, u.accent);
  applyDensity(u.density);
  AUTO = u.auto_refresh !== false;
  try { localStorage.setItem("wa_theme", t); localStorage.setItem("wa_accent", u.accent || ""); } catch (_) {}
  const ts = $("themeSel");
  if (ts) ts.value = t;
  $("dirtyDot") && $("dirtyDot").classList.remove("show");
}
(function () {
  let saved = "dawn";
  try { saved = localStorage.getItem("wa_theme") || "dawn"; } catch (_) {}
  let acc = "";
  try { acc = localStorage.getItem("wa_accent") || ""; } catch (_) {}
  try { LANG = localStorage.getItem("wa_lang") === "tr" ? "tr" : "en"; } catch (_) {}
  applyTheme(saved, acc);
})();
function applyLang() {
  const ls = $("langSel");
  if (ls) ls.value = LANG;
  const el = $("hdrTheme"); if (el) el.textContent = t("theme", "Theme");
  const r = $("hdrRestart"); if (r) r.textContent = t("restart", "Restart");
  const so = $("hdrSignout"); if (so) so.textContent = t("sign_out", "Sign out");
  const rb = $("restartBadge"); if (rb) rb.textContent = t("restart_required", "restart required");
  const s = $("search"); if (s) s.placeholder = t("search_pages", "Search pages");
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (res.status === 401) { window.location.href = "/-/login"; throw new Error("unauthorized"); }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) {}
    const e = new Error(msg); e.status = res.status; throw e;
  }
  return res.json();
}
function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.innerHTML = '<span class="msg">' + esc(msg) + '</span><button class="x" title="dismiss">&times;</button>';
  $("toasts").appendChild(el);
  const timer = setTimeout(() => { el.remove(); }, 5200);
  el.querySelector(".x").addEventListener("click", () => { clearTimeout(timer); el.remove(); });
}
function cleanToasts(){ $("toasts").innerHTML = ""; }

let CFG = null;
let DIRTY = false;
let SEARCH = "";
const MASKED = "***MASKED***";
const setDirty = d => { DIRTY = d; const dd = $("dirtyDot"); if (dd) dd.classList.toggle("show", !!d); };
window.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "s" && DIRTY) {
    e.preventDefault();
    const pg = PAGES.find(p => p.id === CUR);
    if (pg && pg.id !== "overview" && pg.id !== "audit") savePage(pg);
  }
});
window.addEventListener("beforeunload", (e) => { if (DIRTY) { e.preventDefault(); e.returnValue = ""; } });
const getPath = (o, p) => { let v = o; for (const k of p.split(".")) { if (v == null) return undefined; v = v[k]; } return v; };
const setPath = (o, p, val) => {
  const segs = p.split("."); let v = o;
  for (let i = 0; i < segs.length - 1; i++) {
    const k = segs[i]; const nk = segs[i + 1];
    if (v[k] == null) v[k] = /^\d+$/.test(nk) ? [] : {};
    v = v[k];
  }
  v[segs[segs.length - 1]] = val;
};
const findCfgRoot = p => p.split(".")[0];
function normalize(cfg) {
  const D = cfg.domains && cfg.domains[0] || {};
  const sec = cfg.security = cfg.security || {};
  sec.challenge = sec.challenge || {enabled:false, difficulty:4, ttl:600, proof_ttl:180};
  sec.geoip    = sec.geoip    || {enabled:false};
  sec.siem     = sec.siem     || {enabled:false, batch_interval:2, batch_size:100, max_buffer:8192, endpoints:[]};
  sec.siem.endpoints = Array.isArray(sec.siem.endpoints) ? sec.siem.endpoints : [];
  sec.store    = sec.store    || {type:"memory"};
  sec.store.redis = sec.store.redis || {address:"", password:"", db:0, prefix:""};
  sec.ddos     = sec.ddos     || {enabled:false, per_ip_rate:50, per_ip_action:"challenge", site_burst_rps:0, defense_action:"challenge", defense_ttl:60, allowlist:[]};
  sec.headers  = sec.headers  || {hsts:true, frame_options:"SAMEORIGIN", no_sniff:true, referrer_policy:"strict-origin-when-cross-origin", csp:""};
  cfg.log = cfg.log || {rotation_max_mb:0, rotation_keep:5};
  cfg.server = cfg.server || {};
  cfg.dashboard = cfg.dashboard || {};
  cfg.dashboard.listen = cfg.dashboard.listen || "";
  cfg.dashboard.console_path = cfg.dashboard.console_path || "/-";
  if (!Array.isArray(cfg.dashboard.admin_allowlist)) cfg.dashboard.admin_allowlist = [];
  D.waf = D.waf || {mode:"block"};
  D.waf.managed = D.waf.managed || {ruleset_version:"1.0.0", paranoia_level:1};
  if (!D.waf.managed.categories || !Object.keys(D.waf.managed.categories).length)
    D.waf.managed.categories = {SQL_INJECTION:true, XSS:true, RCE:true, LFI:true, PATH_TRAVERSAL:true};
  D.waf.custom_rules = Array.isArray(D.waf.custom_rules) ? D.waf.custom_rules : [];
  D.origin = D.origin || {scheme:"http", host:"", port:""};
  D.tls = D.tls || {};
  D.honeypot   = D.honeypot   || {enabled:false, paths:[], auto_generate:true};
  D.honeypot.paths = Array.isArray(D.honeypot.paths) ? D.honeypot.paths : [];
  D.rate_limits= D.rate_limits|| {enabled:false, limits:[]};
  D.rate_limits.limits = Array.isArray(D.rate_limits.limits) ? D.rate_limits.limits : [];
  D.bot        = D.bot        || {enabled:false, challenge_below:20, block_below:5, verified_bots:[]};
  D.bot.verified_bots = Array.isArray(D.bot.verified_bots) ? D.bot.verified_bots : [];
  D.reputation = D.reputation || {enabled:false, honeypot_points:50, blocked_request_points:25, block_score:60};
  D.api_security = D.api_security || {enabled:false, jwt:{}, routes:[], policy:{}};
  D.api_security.jwt = D.api_security.jwt || {algorithm:"", secret:"", public_key_pem:"", header:"authorization", required_claims:[]};
  D.api_security.routes = Array.isArray(D.api_security.routes) ? D.api_security.routes : [];
  D.api_security.policy = D.api_security.policy || {authn_required:false, validate_schema:false, override:""};
  D.behavior   = D.behavior   || {enabled:false, cookie_name:"waap_client", secret:"", cookie_ttl:86400, idle_ttl:3600, max_clients:10000, challenge_above:60, block_above:85};
  cfg.ui = cfg.ui || {};
  const u = cfg.ui;
  u.theme = VALID_THEMES.has(u.theme) ? u.theme : (u.theme === "custom" ? "custom" : "dawn");
  u.accent = typeof u.accent === "string" ? u.accent : "";
  u.density = u.density === "compact" ? "compact" : "comfortable";
  u.time_range = [300, 3600, 21600, 86400].includes(u.time_range) ? u.time_range : 300;
  u.chart_bucket = [15, 30, 60, 120].includes(u.chart_bucket) ? u.chart_bucket : 15;
  u.auto_refresh = u.auto_refresh !== false;
  u.hidden_pages = Array.isArray(u.hidden_pages) ? u.hidden_pages.filter(h => h !== "overview" && h !== "interface") : [];
  u.pages_order = Array.isArray(u.pages_order) ? u.pages_order.filter(p => PAGES.some(x => x.id === p)) : [];
  u.language = u.language === "tr" ? "tr" : "en";
}

const PAGES = [
  { id:"overview", g:"Analytics", ic:"&#x1f4ca;", label:"Overview" },
  { id:"audit", g:"Analytics", ic:"&#x1f4c1;", label:"Audit log" },
  { id:"security", g:"Configuration", ic:"&#x1f6e1;", label:"Security",
    groups:[
      { title:"Engine posture", fields:[
        { key:"security.engine_fail_mode", label:"Engine fail mode", type:"select",
          options:[{v:"fail_open",l:"fail-open (availability first)"},{v:"fail_closed",l:"fail-closed (security first)"}] },
        { key:"security.hmac_secret", label:"HMAC secret", type:"secret",
          help:"Signs admin sessions + challenge proofs. Changing it logs everyone out." },
      ]},
      { title:"Store &amp; rate limiting backend", fields:[
        { key:"security.store.type", label:"Counter backend", type:"select",
          options:[{v:"memory",l:"memory (single instance)"},{v:"redis",l:"redis (distributed)"}] },
        { key:"security.store.redis.address", label:"Redis address", type:"text" },
        { key:"security.store.redis.password", label:"Redis password", type:"secret" },
        { key:"security.store.redis.db", label:"Redis DB", type:"number" },
        { key:"security.store.redis.prefix", label:"Key prefix", type:"text" },
      ]},
    ]},
  { id:"waf", g:"Configuration", ic:"&#x1f6e1;", label:"WAF &amp; Rules",
    groups:[
      { title:"Security level (domain)", domain:true, fields:[
        { key:"domains.0.waf.mode", label:"WAF posture", type:"select",
          options:[{v:"block",l:"block (enforce)"},{v:"detection",l:"detection (log only)"},{v:"disabled",l:"disabled (bypass)"}] },
        { key:"domains.0.waf.managed.ruleset_version", label:"Ruleset version", type:"text" },
        { key:"domains.0.waf.managed.paranoia_level", label:"Paranoia level", type:"select", numeric:true,
          options:[{v:0,l:"Level 0 (low)"},{v:1,l:"Level 1 (standard)"},{v:2,l:"Level 2 (strict)"}] },
      ]},
      { title:"Managed rule categories", domain:true, cols:2, fields:[
        { key:"domains.0.waf.managed.categories.SQL_INJECTION", label:"SQL Injection", type:"bool" },
        { key:"domains.0.waf.managed.categories.XSS", label:"Cross-Site Scripting", type:"bool" },
        { key:"domains.0.waf.managed.categories.RCE", label:"Remote Code Execution", type:"bool" },
        { key:"domains.0.waf.managed.categories.LFI", label:"Local File Inclusion", type:"bool" },
        { key:"domains.0.waf.managed.categories.PATH_TRAVERSAL", label:"Path Traversal", type:"bool" },
      ]},
      { title:"Custom rules", domain:true, list:{ path:"domains.0.waf.custom_rules", add:"Add rule",
        blank:{id:"", name:"New rule", enabled:true, dsl:""},
        fields:[
          { key:"enabled", label:"On", type:"bool" },
          { key:"id", label:"ID", type:"text" },
          { key:"name", label:"Name", type:"text" },
          { key:"dsl", label:"Expression (DSL)", type:"textarea", wide:true, help:'Example: IF path starts_with "/admin" AND country != "TR" THEN BLOCK' },
        ]
      },
        help:"Live-applied without restart." },
    ]},
  { id:"ratelimit", g:"Configuration", ic:"&#x1f504;", label:"Rate limiting",
    groups:[
      { title:"Rate limiting", domain:true, enabled:{path:"domains.0.rate_limits.enabled", label:"Enable rate limiting"}, help:"Sliding-window counters with two tiers: max = soft threshold (THROTTLE), throttle_max = hard ceiling before action.",
        list:{ path:"domains.0.rate_limits.limits", add:"Add limit rule",
          blank:{id:"", name:"New limit", enabled:true, scope:"ip_path", path:"", method:"", header:"", max:10, throttle_max:null, window:60, action:"BLOCK"},
          fields:[
            { key:"enabled", label:"On", type:"bool" },
            { key:"id", label:"ID", type:"text" },
            { key:"name", label:"Name", type:"text" },
            { key:"scope", label:"Scope", type:"select", options:[{v:"ip",l:"IP"},{v:"path",l:"Path"},{v:"ip_path",l:"IP + path"},{v:"ip_method",l:"IP + method"},{v:"header",l:"Header"}] },
            { key:"path", label:"Path", type:"text" },
            { key:"method", label:"Method", type:"text" },
            { key:"header", label:"Header", type:"text" },
            { key:"max", label:"Max / window", type:"number" },
            { key:"throttle_max", label:"Throttle max", type:"number" },
            { key:"window", label:"Window (s)", type:"number" },
            { key:"action", label:"Action", type:"select", options:[{v:"BLOCK",l:"BLOCK"},{v:"THROTTLE",l:"THROTTLE"},{v:"CHALLENGE",l:"CHALLENGE"},{v:"RATE_LIMIT",l:"RATE_LIMIT (429)"}] },
          ]},
        help:"Protects /login against brute force: scope=ip_path, path=/login, max=5. Live-applied." },
    ]},
  { id:"bot", g:"Configuration", ic:"&#x1f916;", label:"Bot &amp; reputation",
    groups:[
      { title:"Bot detection", domain:true, enabled:{path:"domains.0.bot.enabled", label:"Enable bot detection"}, fields:[
        { key:"domains.0.bot.challenge_below", label:"Challenge score below", type:"number" },
        { key:"domains.0.bot.block_below", label:"Block score below", type:"number" },
        { key:"domains.0.bot.verified_bots", label:"Verified good bots", type:"tags", help:"Comma separated UA substrings (googlebot, bingbot)." },
      ]},
      { title:"Behavioral bot detection", domain:true, enabled:{path:"domains.0.behavior.enabled", label:"Enable behavioral detection"}, fields:[
        { key:"domains.0.behavior.cookie_name", label:"Fingerprint cookie", type:"text" },
        { key:"domains.0.behavior.secret", label:"Cookie signing secret", type:"secret", help:"Env-ref it (${BEHAVIOR_SECRET}); empty = random per boot." },
        { key:"domains.0.behavior.challenge_above", label:"Challenge score &ge;", type:"number" },
        { key:"domains.0.behavior.block_above", label:"Block score &ge;", type:"number" },
        { key:"domains.0.behavior.cookie_ttl", label:"Fingerprint cookie TTL (s)", type:"number" },
        { key:"domains.0.behavior.idle_ttl", label:"Idle eviction (s)", type:"number" },
        { key:"domains.0.behavior.max_clients", label:"Max tracked clients", type:"number" },
      ]},
      { title:"IP reputation", domain:true, enabled:{path:"domains.0.reputation.enabled", label:"Enable reputation"}, fields:[
        { key:"domains.0.reputation.honeypot_points", label:"Honeypot hit points", type:"number" },
        { key:"domains.0.reputation.blocked_request_points", label:"Blocked request points", type:"number" },
        { key:"domains.0.reputation.block_score", label:"Hard-block score", type:"number" },
      ]},
      { title:"Honeypot (auto decoys)", domain:true, enabled:{path:"domains.0.honeypot.enabled", label:"Enable honeypot"}, fields:[
        { key:"domains.0.honeypot.auto_generate", label:"Auto-generate decoys", type:"bool" },
        { key:"domains.0.honeypot.paths", label:"Extra decoy paths", type:"tags" },
      ]},
    ]},
  { id:"apisec", g:"Configuration", ic:"&#x1f4e6;", label:"API security",
    groups:[
      { title:"API security", domain:true, enabled:{path:"domains.0.api_security.enabled", label:"Enable API security"}, fields:[
        { key:"domains.0.api_security.jwt.algorithm", label:"JWT algorithm", type:"select", options:[{v:"HS256",l:"HS256 (shared secret)"},{v:"RS256",l:"RS256 (public key)"}] },
        { key:"domains.0.api_security.jwt.secret", label:"JWT secret", type:"secret" },
        { key:"domains.0.api_security.jwt.public_key_pem", label:"RS256 public key (PEM)", type:"textarea", wide:true },
        { key:"domains.0.api_security.jwt.header", label:"Token header", type:"text", help:"Defaults to authorization (Bearer &lt;token&gt;)." },
        { key:"domains.0.api_security.jwt.issuer", label:"Issuer", type:"text" },
        { key:"domains.0.api_security.jwt.audiences", label:"Audiences", type:"tags" },
        { key:"domains.0.api_security.jwt.required_claims", label:"Required claims", type:"tags" },
        { key:"domains.0.api_security.jwt.leeway_seconds", label:"Clock leeway (s)", type:"number" },
        { key:"domains.0.api_security.policy.authn_required", label:"Require authentication", type:"bool" },
        { key:"domains.0.api_security.policy.validate_schema", label:"Enforce request schema", type:"bool" },
        { key:"domains.0.api_security.policy.no_auth_action", label:"Bad-token action", type:"select", options:[{v:"UNAUTHORIZED",l:"UNAUTHORIZED (401)"},{v:"ALLOW",l:"ALLOW"},{v:"BLOCK",l:"BLOCK"},{v:"LOG",l:"LOG"}] },
        { key:"domains.0.api_security.policy.override", label:"Validation-violation override", type:"select", options:[{v:"",l:"&mdash; inherit"},{v:"BLOCK",l:"BLOCK"},{v:"LOG",l:"LOG"},{v:"UNAUTHORIZED",l:"UNAUTHORIZED (401)"}] },
      ]},
      { title:"API routes (schema validation)", domain:true, list:{ path:"domains.0.api_security.routes", add:"Add route",
        blank:{path:"", method:"", auth_none:false, request_schema:""},
        fields:[
          { key:"path", label:"Path prefix", type:"text" },
          { key:"method", label:"Method", type:"text" },
          { key:"auth_none", label:"Public (no auth)", type:"bool" },
          { key:"request_schema", label:"JSON Schema", type:"textarea", wide:true },
        ],
      },
        help:'Example schema: {"type":"object","properties":{"qty":{"type":"integer"}},"required":["qty"]}' },
    ]},
  { id:"challenge", g:"Configuration", ic:"&#x1f512;", label:"Challenge",
    groups:[
      { title:"Proof-of-work challenge", enabled:{path:"security.challenge.enabled", label:"Enable challenge"}, help:"CHALLENGE decisions serve a real SHA-256 proof-of-work interstitial.",
        fields:[
          { key:"security.challenge.difficulty", label:"Difficulty (leading zero hex)", type:"number" },
          { key:"security.challenge.ttl", label:"Access cookie TTL (s)", type:"number" },
          { key:"security.challenge.proof_ttl", label:"Proof validity (s)", type:"number" },
        ]},
    ]},
  { id:"ddos", g:"Configuration", ic:"&#x1f525;", label:"DDoS guard",
    groups:[
      { title:"Per-IP rate protection", enabled:{path:"security.ddos.enabled", label:"Enable DDoS guard"}, help:"Two independent limbs. Per-IP: one source can sustain at most per_ip_rate requests/second before the chosen action. Site burst: when site-wide RPS exceeds site_burst_rps the edge arms defense mode for defense_ttl and actionable clients that lack a valid proof-of-work cookie. Challenge actions require the Challenge module enabled so visitors get a real PoW page.",
        fields:[
          { key:"security.ddos.per_ip_rate", label:"Max requests / s per IP", type:"number", help:"0 disables the per-IP limb." },
          { key:"security.ddos.per_ip_action", label:"Per-IP action", type:"select",
            options:[{v:"challenge",l:"challenge (proof-of-work)"},{v:"block",l:"block (403)"}] },
          { key:"security.ddos.site_burst_rps", label:"Site burst RPS (0=off)", type:"number" },
          { key:"security.ddos.defense_action", label:"Defense-mode action", type:"select",
            options:[{v:"challenge",l:"challenge (proof-of-work)"},{v:"block",l:"block (403)"}] },
          { key:"security.ddos.defense_ttl", label:"Defense hold (s)", type:"number" },
          { key:"security.ddos.allowlist", label:"Allowlist CIDRs", type:"tags", help:"Comma separated networks that bypass the guard (monitoring, origin infra)." },
        ]},
    ]},
  { id:"hardening", g:"Configuration", ic:"&#x1f6e1;&#xfe0f;", label:"Hardening",
    groups:[
      { title:"Security response headers (all domains)", help:"Injected at the edge on every proxied and denied response. The edge is the last writer, so the origin can never weaken these.",
        fields:[
          { key:"security.headers.hsts", label:"HSTS (max-age=1y)", type:"bool" },
          { key:"security.headers.frame_options", label:"X-Frame-Options", type:"select",
            options:[{v:"",l:"&mdash; omit"},{v:"DENY",l:"DENY"},{v:"SAMEORIGIN",l:"SAMEORIGIN"}] },
          { key:"security.headers.no_sniff", label:"X-Content-Type-Options: nosniff", type:"bool" },
          { key:"security.headers.referrer_policy", label:"Referrer-Policy", type:"select",
            options:[{v:"",l:"&mdash; omit"},{v:"strict-origin-when-cross-origin",l:"strict-origin-when-cross-origin"},{v:"same-origin",l:"same-origin"},{v:"strict-origin",l:"strict-origin"},{v:"no-referrer",l:"no-referrer"},{v:"no-referrer-when-downgrade",l:"no-referrer-when-downgrade"},{v:"origin",l:"origin"},{v:"origin-when-cross-origin",l:"origin-when-cross-origin"}] },
          { key:"security.headers.csp", label:"Content-Security-Policy", type:"textarea", wide:true, help:'Example: default-src \'self\' ' },
        ]},
      { title:"Per-domain overrides", domain:true, help:"Empty fields fall back to the global values above. Only set what must differ for this domain.",
        fields:[
          { key:"domains.0.headers.hsts", label:"HSTS override", type:"bool" },
          { key:"domains.0.headers.frame_options", label:"X-Frame-Options override", type:"select",
            options:[{v:"",l:"&mdash; inherit"},{v:"DENY",l:"DENY"},{v:"SAMEORIGIN",l:"SAMEORIGIN"}] },
          { key:"domains.0.headers.no_sniff", label:"nosniff override", type:"bool" },
          { key:"domains.0.headers.referrer_policy", label:"Referrer-Policy override", type:"select",
            options:[{v:"",l:"&mdash; inherit"},{v:"strict-origin-when-cross-origin",l:"strict-origin-when-cross-origin"},{v:"same-origin",l:"same-origin"},{v:"strict-origin",l:"strict-origin"},{v:"no-referrer",l:"no-referrer"},{v:"no-referrer-when-downgrade",l:"no-referrer-when-downgrade"},{v:"origin",l:"origin"},{v:"origin-when-cross-origin",l:"origin-when-cross-origin"}] },
          { key:"domains.0.headers.csp", label:"CSP override", type:"textarea", wide:true },
        ]},
    ]},
  { id:"target", g:"Origin", ic:"&#x1f310;", label:"Origin &amp; domains",
    groups:[
      { title:"Protected domain", domain:true, fields:[
        { key:"domains.0.enabled", label:"Domain active", type:"bool" },
        { key:"domains.0.hostname", label:"Hostname", type:"text" },
        { key:"domains.0.origin.scheme", label:"Origin scheme", type:"select", options:[{v:"http",l:"http"},{v:"https",l:"https"}] },
        { key:"domains.0.origin.host", label:"Origin host", type:"text" },
        { key:"domains.0.origin.port", label:"Origin port", type:"text" },
      ]},
      { title:"Per-domain TLS (optional)", domain:true, help:"Leave empty to use the server-level certificates.",
        fields:[
          { key:"domains.0.tls.cert_file", label:"Cert file", type:"text" },
          { key:"domains.0.tls.key_file", label:"Key file", type:"text" },
        ]},
      { title:"Listener", fields:[
        { key:"server.listen_https", label:"HTTPS listen", type:"text" },
        { key:"server.listen_http", label:"HTTP redirect listen", type:"text" },
        { key:"server.tls_cert_file", label:"TLS certificate", type:"text" },
        { key:"server.tls_key_file", label:"TLS key", type:"text" },
      ], restart:true },
    ]},
  { id:"geoip", g:"Integration", ic:"&#x1f30d;", label:"GeoIP / ASN",
    groups:[
      { title:"Geolocation enrichment", enabled:{path:"security.geoip.enabled", label:"Enable GeoIP / ASN"}, restart:true, help:"Resolve source country + ASN from a MaxMind GeoLite2 .mmdb; usable in custom rules and events.",
        fields:[
          { key:"security.geoip.db_path", label:"Database path (.mmdb)", type:"text" },
        ]},
    ]},
  { id:"siem", g:"Integration", ic:"&#x1f4e4;", label:"SIEM / audit",
    groups:[
      { title:"Forwarding", enabled:{path:"security.siem.enabled", label:"Enable SIEM forwarding"}, restart:true,
        fields:[
          { key:"security.siem.batch_interval", label:"Batch interval (s)", type:"number" },
          { key:"security.siem.batch_size", label:"Batch size", type:"number" },
          { key:"security.siem.max_buffer", label:"Max buffer", type:"number" },
        ],
        list:{ path:"security.siem.endpoints", add:"Add endpoint",
          blank:{type:"http", url:"", token:"", hmac_secret:"", network:"udp", address:""},
          fields:[
            { key:"type", label:"Type", type:"select", options:[{v:"http",l:"http"},{v:"syslog",l:"syslog"}] },
            { key:"url", label:"URL", type:"text" },
            { key:"token", label:"Bearer token", type:"secret" },
            { key:"hmac_secret", label:"HMAC secret", type:"secret" },
            { key:"network", label:"Network", type:"select", options:[{v:"udp",l:"udp"},{v:"tcp",l:"tcp"}] },
            { key:"address", label:"Address", type:"text" },
          ],
      },
        help:"Events are batched and forwarded asynchronously; collector outages never block traffic." },
    ]},
  { id:"dashboard", g:"Integration", ic:"&#x1f4c8;", label:"Console &amp; logging",
    groups:[
      { title:"Console (this panel)", restart:true, fields:[
        { key:"dashboard.enabled", label:"Enable console", type:"bool" },
        { key:"dashboard.listen", label:"Separate admin listener", type:"text", help:"Empty = served on the edge under the console path." },
        { key:"dashboard.console_path", label:"Console path (secret)", type:"text", help:"Hidden prefix the operator console lives under (default /-). Set a random value like /ops-8x3h so probing the domain reveals nothing: the login page is not under /-/ anymore. The path may contain letters, digits, - and _." },
        { key:"dashboard.admin_user", label:"Admin user", type:"text" },
        { key:"dashboard.admin_password", label:"Admin password", type:"secret" },
        { key:"dashboard.session_ttl", label:"Session TTL (s)", type:"number" },
        { key:"dashboard.max_events", label:"In-memory event cap", type:"number" },
        { key:"dashboard.admin_allowlist", label:"Admin access (CIDRs)", type:"tags", help:"Restrict the console (login + panel + /-/api/*) to these sources. Empty = anyone who can reach the listener. Set your office CIDR here so the login page is not even reachable from outside." },
      ]},
      { title:"Security event log", restart:true, fields:[
        { key:"log.rotation_max_mb", label:"Rotation size (MB, 0=off)", type:"number" },
        { key:"log.rotation_keep", label:"Archives kept", type:"number" },
      ]},
    ]},
  { id:"interface", g:"Integration", ic:"&#x1f3a8;", label:"Settings &amp; appearance",
    groups:[
      { title:"Appearance &amp; theme", help:"Console look &amp; feel. Persisted server-side (survives across browsers); applies live without restart.",
        fields:[
          { key:"ui.theme", label:"Theme", type:"select",
            options:[{v:"dawn",l:"Dawn (amber)"},{v:"night",l:"Night (dark)"},{v:"emerald",l:"Emerald"},{v:"sapphire",l:"Sapphire"},{v:"amethyst",l:"Amethyst"},{v:"coral",l:"Coral"},{v:"graphite",l:"Graphite"},{v:"custom",l:"Custom accent"}] },
          { key:"ui.language", label:"Language", type:"select", options:[{v:"en",l:"English"},{v:"tr",l:"Türkçe"}] },
          { key:"ui.accent", label:"Custom accent", type:"color", help:"Applied when Theme = Custom accent." },
          { key:"ui.density", label:"Density", type:"select", options:[{v:"comfortable",l:"Comfortable"},{v:"compact",l:"Compact"}] },
          { key:"ui.auto_refresh", label:"Auto-refresh events by default", type:"bool" },
          { key:"ui.time_range", label:"Overview default window", type:"select", numeric:true,
            options:[{v:"300",l:"Last 5 minutes"},{v:"3600",l:"Last hour"},{v:"21600",l:"Last 6 hours"},{v:"86400",l:"Last 24 hours"}] },
          { key:"ui.chart_bucket", label:"Chart bucket size", type:"select", numeric:true,
            options:[{v:"15",l:"15 seconds"},{v:"30",l:"30 seconds"},{v:"60",l:"60 seconds"},{v:"120",l:"2 minutes"}] },
        ]},
    ]},
];

let CUR = "overview";
let AUTO = true;
function visiblePages() {
  if (!CFG || !CFG.ui) return PAGES;
  const u = CFG.ui;
  let list = [];
  for (const id of u.pages_order) { const p = PAGES.find(x => x.id === id); if (p) list.push(p); }
  for (const p of PAGES) if (!list.includes(p)) list.push(p);
  return list.filter(p => (p.id === "overview" || p.id === "interface") || !u.hidden_pages.includes(p.id));
}
function buildNav() {
  const nav = $("nav"); let html = ""; let last = "";
  const pages = visiblePages();
  let shown = 0;
  const navOpen = () => { try { return JSON.parse(localStorage.getItem("wa_navopen") || "{}") || {}; } catch (_) { return {}; } };
  for (const p of pages) {
    if (SEARCH && esc(p.label).toLowerCase().indexOf(SEARCH.toLowerCase()) === -1 && p.id.toLowerCase().indexOf(SEARCH.toLowerCase()) === -1) continue;
    if (p.g !== last) {
      if (last !== "") html += "</div>";
      html += '<button type="button" class="grp" data-g="' + esc(p.g) + '"><span>' + t(p.g, p.g) + '</span><span class="tc">&#9660;</span></button>';
      html += '<div class="gitems" data-gid="' + esc(p.g) + '">';
      last = p.g;
    }
    shown++;
    html += '<a data-page="' + p.id + '" class="' + (CUR === p.id ? "on" : "") + '">' + p.ic + "&nbsp; " + t(p.label, p.label) + "</a>";
  }
  if (last !== "") html += "</div>";
  const cnt = $("navcnt");
  if (SEARCH) {
    if (cnt) { cnt.style.display = "block"; cnt.textContent = t("search_result", "{shown} of {total} pages match").replace("{shown}", shown).replace("{total}", pages.length); }
  } else if (cnt) cnt.style.display = "none";
  nav.innerHTML = html;
  const open = navOpen();
  nav.querySelectorAll(".grp").forEach(b => {
    const g = b.nextElementSibling;
    if (!g || g.classList.contains("grp")) return;
    const collapsed = !SEARCH && open[g.dataset.gid] === false;
    g.classList.toggle("collapsed", collapsed);
    b.setAttribute("aria-expanded", collapsed ? "false" : "true");
  });
  nav.querySelectorAll(".grp").forEach(b => b.addEventListener("click", () => {
    const g = b.nextElementSibling;
    if (!g || g.classList.contains("grp")) return;
    g.classList.toggle("collapsed");
    const collapsed = g.classList.contains("collapsed");
    b.setAttribute("aria-expanded", collapsed ? "false" : "true");
    const o = navOpen(); o[g.dataset.gid] = !collapsed;
    try { localStorage.setItem("wa_navopen", JSON.stringify(o)); } catch (_) {}
  }));
  nav.querySelectorAll("a").forEach(a => a.addEventListener("click", () => { if (DIRTY && !confirm("Discard unsaved changes on this page?")) return; CUR = a.dataset.page; buildNav(); render(); setDirty(false); }));
}

function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString([], {hour12:false}) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function shareHtml(sum, total) {
  if (!total) return "";
  const p = v => (v / Math.max(1, total) * 100).toFixed(1);
  return '<div class="share" title="Allowed ' + p(sum.allowed) + '% · Blocked ' + p(sum.blocked) +
    '% · Challenged ' + p(sum.challenged) + '% · Rate limited ' + p(sum.rate_limited + sum.throttled) +
    '% · Unauthorized ' + p(sum.unauthorized) + '%">' +
    '<span class="sh-allowed" style="width:' + p(sum.allowed) + '%"></span>' +
    '<span class="sh-blocked" style="width:' + p(sum.blocked) + '%"></span>' +
    '<span class="sh-challenged" style="width:' + p(sum.challenged) + '%"></span>' +
    '<span class="sh-rl" style="width:' + p(sum.rate_limited + sum.throttled) + '%"></span>' +
    '<span class="sh-unauthorized" style="width:' + p(sum.unauthorized) + '%"></span></div>';
}
async function renderOverview() {
  const u = CFG.ui || {};
  const since = u.time_range || 300;
  const bucket = u.chart_bucket || 15;
  const [sum, series, ips, paths, countries, rules, events] = await Promise.all([
    api("/-/api/summary?since=" + since),
    api("/-/api/series?since=" + since + "&bucket=" + bucket),
    api("/-/api/topips?since=" + since + "&n=8"),
    api("/-/api/toppaths?since=" + since + "&n=8"),
    api("/-/api/topcountries?since=" + since + "&n=8"),
    api("/-/api/toprules?since=" + since + "&n=8"),
    api("/-/api/events?limit=200"),
  ]);
  const total = sum.allowed + sum.blocked + sum.challenged + sum.rate_limited + sum.throttled + sum.unauthorized;
  const attacked = events.filter(e => (e.attack_score || 0) > 0).length;
  const D = CFG.domains && CFG.domains[0] || {};
  const sec = CFG.security || {};
  const pmode = (D.waf && D.waf.mode) || "disabled";
  const modeChip = pmode === "block" ? '<span class="chip" style="background:#e7f6ec;border-color:#bce7c9;color:#15803d;font-weight:700">WAF &#9642;&nbsp;block (enforce)</span>'
    : pmode === "detection" ? '<span class="chip" style="background:#fdf3d7;border-color:#f0dfa8;color:#b45309;font-weight:700">WAF &#9642;&nbsp;detection (log only)</span>'
    : '<span class="chip" style="color:#64748b">WAF &#9642;&nbsp;disabled</span>';
  const feat = [
    ["Challenge / PoW", sec.challenge && sec.challenge.enabled],
    ["DDoS guard", sec.ddos && sec.ddos.enabled],
    ["Hardening headers", !!(sec.headers && (sec.headers.hsts || sec.headers.frame_options || sec.headers.no_sniff || sec.headers.csp || sec.headers.referrer_policy))],
    ["Rate limiting", D.rate_limits && D.rate_limits.enabled],
    ["Bot detection", D.bot && D.bot.enabled],
    ["Behavioral", D.behavior && D.behavior.enabled],
    ["API security", D.api_security && D.api_security.enabled],
    ["IP reputation", D.reputation && D.reputation.enabled],
    ["Honeypot", D.honeypot && D.honeypot.enabled],
    ["SIEM export", sec.siem && sec.siem.enabled],
    ["GeoIP / ASN", sec.geoip && sec.geoip.enabled],
  ];
  const featHtml = feat.map(([t, on]) =>
    '<span class="chip" style="' + (on ? "background:#e7f6ec;border-color:#bce7c9;color:#15803d" : "color:var(--muted)") + '">' + esc(t) + (on ? " &#10003;" : " &mdash;") + "</span>").join("");
  const blkPct = total ? Math.round(sum.blocked / total * 100) : 0;
  $("view").innerHTML =
    '<div class="panel" style="margin-top:0"><div class="filters"><span style="font-weight:700">' + t("protection_posture", "Protection posture") + '</span><span class="spacer"></span><span class="muted" id="updatedStamp">updated &mdash;</span>' +
    '<button class="btn" id="advAuto">' + (AUTO ? "&#10074;&#10074;&nbsp;" + t("auto_refresh", "Auto-refresh") : "&#9654;&nbsp;" + t("auto_refresh_off", "Auto-refresh off")) + '</button></div>' +
    '<div class="chips" style="margin-top:10px">' + modeChip + featHtml + "</div></div>" +
    '<div class="stats">' +
    card(sum.allowed, t("requests_allowed", "Requests allowed"), "ok") + card(sum.blocked, t("Blocked", "Blocked"), "bad") +
    card(sum.challenged, t("Challenged", "Challenged"), "warn") + card(sum.rate_limited + sum.throttled, t("Rate limited", "Rate limited"), "warn") +
    card(sum.unauthorized, t("Unauthorized", "Unauthorized"), "info") + card(total, t("Total evaluated", "Total evaluated"), "info") +
    '</div>' +
    (total ? '<div class="panel" style="margin-top:12px"><div class="filters"><span style="font-weight:700">' + t("outcome_share", "Outcome share") + '</span><span class="spacer"></span>' +
      '<span class="muted">' + blkPct + "% " + t("blocked_of", "blocked") + " &middot; " + attacked + " " + t("attacked_req", "requests carried attack signals") + "</span></div>" +
      shareHtml(sum, total) +
      '<div class="legend"><span><i style="background:#c9d4e4"></i>allowed</span><span><i style="background:#f87171"></i>blocked</span>' +
      '<span><i style="background:#fbbf24"></i>challenged</span><span><i style="background:#fb923c"></i>rate limited</span>' +
      '<span><i style="background:#a78bfa"></i>unauthorized</span></div></div>' : "") +
    '<div class="panel"><div class="filters"><h2 style="margin:0">Traffic</h2>' +
    '<span class="legend" style="margin:0;gap:10px"><span><i style="background:#c9d4e4"></i>allowed</span><span><i style="background:#f87171"></i>blocked</span><span><i style="background:#fbbf24"></i>challenge</span><span><i style="background:#fb923c"></i>rate limit</span></span>' +
    '<span class="spacer"></span>' +
    '<label class="muted" style="display:flex;gap:6px;align-items:center">Window<select id="ovSince">' +
    '<option value="300"' + (since === 300 ? " selected" : "") + '>5 min</option>' +
    '<option value="3600"' + (since === 3600 ? " selected" : "") + '>1 h</option>' +
    '<option value="21600"' + (since === 21600 ? " selected" : "") + '>6 h</option>' +
    '<option value="86400"' + (since === 86400 ? " selected" : "") + '>24 h</option></select></label>' +
    '<label class="muted" style="display:flex;gap:6px;align-items:center">Bucket<select id="ovBucket">' +
    '<option value="15"' + (bucket === 15 ? " selected" : "") + '>15 s</option>' +
    '<option value="30"' + (bucket === 30 ? " selected" : "") + '>30 s</option>' +
    '<option value="60"' + (bucket === 60 ? " selected" : "") + '>60 s</option>' +
    '<option value="120"' + (bucket === 120 ? " selected" : "") + '>2 min</option></select></label>' +
    '</div><div class="bars" id="bars"></div></div>' +
    '<div class="grid2">' +
    '<div class="panel"><h2>Top source IPs</h2><table id="topips"><thead><tr><th>IP</th><th>Count</th></tr></thead><tbody></tbody></table></div>' +
    '<div class="panel"><h2>Top paths</h2><table id="toppaths"><thead><tr><th>Path</th><th>Count</th></tr></thead><tbody></tbody></table></div>' +
    '<div class="panel"><h2>Top countries</h2><table id="topcountries"><thead><tr><th>Country</th><th>Count</th></tr></thead><tbody></tbody></table></div>' +
    '<div class="panel"><h2>Top triggered rules</h2><table id="toprules"><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody></tbody></table></div>' +
    '</div>' +
    '<div class="panel"><div class="filters"><h2 style="margin:0">Security events</h2><span class="evcount" id="evcount"></span><span class="spacer"></span>' +
    '<input id="evq" class="evq" placeholder="search IP / path / rule / category" autocomplete="off">' +
    '<select id="evaction"><option value="">all actions</option><option>ALLOW</option><option>BLOCK</option><option>CHALLENGE</option><option>RATE_LIMIT</option><option>THROTTLE</option><option>UNAUTHORIZED</option><option>LOG</option></select>' +
    '<button class="btn" id="evrefresh">Refresh</button>' +
    '<button class="btn" id="evcsv">&#8681;&nbsp;CSV</button></div>' +
    '<table class="rowtab" id="events"><thead><tr><th>Time</th><th>Action</th><th>IP</th><th>Method</th><th>Path</th><th>Rule</th><th>Category</th><th>Attack / Bot</th></tr></thead><tbody></tbody></table></div>';
  const bars = $("bars");
  bars.innerHTML = series.map(p => {
    const H = Math.max(4, p.total);
    const top = Math.min(96, 4 + H * 2);
    const out = Math.round(p.total ? p.allowed / p.total * H * 2 : 0);
    const blk = Math.round(p.total ? p.blocked / p.total * H * 2 : 0);
    const ch = Math.round(p.total ? p.challenged / p.total * H * 2 : 0);
    const rl = Math.round(p.total ? (p.rate_limited + p.throttled) / p.total * H * 2 : 0);
    return '<div class="bar" style="height:' + top + 'px" title="' + p.timestamp +
      ' total=' + p.total + " allowed=" + p.allowed + " blocked=" + p.blocked +
      " challenged=" + p.challenged + " rate_limited=" + p.rate_limited + " throttled=" + p.throttled + '">' +
      (out ? '<span class="s-ok" style="height:' + out + 'px"></span>' : "") +
      (blk ? '<span class="s-blk" style="height:' + blk + 'px"></span>' : "") +
      (ch ? '<span class="s-ch" style="height:' + ch + 'px"></span>' : "") +
      (rl ? '<span class="s-rl" style="height:' + Math.max(2, rl) + 'px"></span>' : "") +
      "</div>";
  }).join("");
  const fill = (id, rows) => {
    $("view").querySelector("#" + id + " tbody").innerHTML =
      rows.map(r => "<tr><td>" + esc(r.label) + "</td><td>" + r.count + "</td></tr>").join("") || '<tr><td colspan=2 class="muted">none</td></tr>';
  };
  fill("topips", ips);
  fill("toppaths", paths);
  fill("topcountries", countries);
  fill("toprules", rules);
  drawEvents(events, "events");
  $("evaction").addEventListener("change", () => loadEvents(200, 0, "events"));
  $("evrefresh").addEventListener("click", () => loadEvents(200, 0, "events"));
  $("evcsv").addEventListener("click", exportCSV);
  $("evq").addEventListener("input", () => { EVQ = $("evq").value; drawEvents(EVS, "events"); });
  $("ovSince").addEventListener("change", async () => { CFG.ui.time_range = Number($("ovSince").value); try { await persistPrefs(); render(); } catch (e) { toast("Failed to save window preference: " + e.message, "err"); } });
  $("ovBucket").addEventListener("change", async () => { CFG.ui.chart_bucket = Number($("ovBucket").value); try { await persistPrefs(); render(); } catch (e) { toast("Failed to save bucket preference: " + e.message, "err"); } });
  const aa = $("advAuto");
  if (aa) aa.addEventListener("click", () => {
    AUTO = !AUTO;
    aa.innerHTML = AUTO ? "&#10074;&#10074;&nbsp;Auto-refresh" : "&#9654;&nbsp;Auto-refresh off";
    tick();
    stampNow();
  });
  stampNow();
}
function tick() {
  clearInterval(window.__ovTimer);
  window.__ovTimer = 0;
  if (!AUTO) return;
  window.__ovTimer = setInterval(() => {
    if (CUR === "overview") loadEvents(200, 0, "events");
    else if (CUR === "audit") { AUDIT.offset = 0; loadEvents(200, 0, "audit"); }
  }, 5000);
}
function stampNow() {
  const s = $("updatedStamp");
  if (s) s.textContent = "updated " + new Date().toLocaleTimeString([], {hour12:false});
}
let EVS = [];
let EVQ = "";
async function loadEvents(limit, offset, tableId, append) {
  const v = tableId === "audit"
    ? { action: $("afAct").value, ip: $("afIp").value.trim(), rule: $("afRule").value.trim(), category: $("afCat").value.trim() }
    : { action: $("evaction").value };
  const q = new URLSearchParams({ limit: String(limit || 200), offset: String(offset || 0) });
  for (const k in v) if (v[k]) q.set(k, v[k]);
  const events = await api("/-/api/events?" + q.toString());
  EVS = append ? EVS.concat(events) : events;
  drawEvents(EVS, tableId);
  if (tableId === "audit" && $("evcount")) $("evcount").textContent = "showing " + EVS.length + " loaded";
  return events.length;
}
function drawEvents(events, tableId) {
  stampNow();
  EVS = events;
  const tb = $(tableId + " tbody");
  if (!tb) return;
  const q = (EVQ || "").toLowerCase();
  const src = q
    ? events.map((e, si) => ({ e, si })).filter(({ e }) => (e.source_ip + " " + e.path + " " + (e.rule_id || "") + " " + (e.category || "")).toLowerCase().includes(q))
    : events.map((e, si) => ({ e, si }));
  tb.innerHTML = src.map(({ e, si }) =>
    '<tr data-ei="' + si + '"><td>' + fmtTime(e.timestamp) + "</td><td><span class='tag " + esc(e.action) + "'>" + esc(e.action) +
    "</span></td><td>" + esc(e.source_ip) + "</td><td>" + esc(e.method) + "</td><td>" + esc(e.path) +
    "</td><td>" + esc(e.rule_id || "—") + "</td><td>" + esc(e.category || "—") + "</td><td>" +
    (e.attack_score ? e.attack_score : "—") + " / " + (e.bot_score ? e.bot_score : "—") + "</td></tr>").join("") ||
    '<tr><td colspan=8 class="muted">No events yet — visit the site or fire an attack.</td></tr>';
  tb.onclick = ev => {
    const tr = ev.target && ev.target.closest && ev.target.closest("tr[data-ei]");
    if (!tr) return;
    openEventDetail(EVS[+tr.getAttribute("data-ei")]);
  };
  const c = $("evcount");
  if (c) c.textContent = src.length + " of " + events.length + " shown";
}
function openEventDetail(e) {
  if (!e) return;
  const reasons = (e.reasons || []).map(r =>
    '<span class="chip">' + esc(r.label) +
    (r.points != null ? " &nbsp;+" + r.points : "") +
    (r.threshold ? " (≥" + r.threshold + ")" : "") +
    (r.rule_id ? ' <small>[' + esc(r.rule_id) + "]</small>" : "") + "</span>").join("");
  const rows = [
    ["Action", '<span class="tag ' + esc(e.action) + '">' + esc(e.action) + "</span>"],
    ["Time", fmtTime(e.timestamp)],
    ["Source IP", esc(e.source_ip)],
    ["Country / ASN", esc(e.country || "—") + " / " + (e.asn ? "AS" + e.asn : "—")],
    ["Hostname", esc(e.hostname || "—")],
    ["Method", esc(e.method || "—")],
    ["Path", esc(e.path || "—")],
    ["Rule", esc(e.rule_id || "—")],
    ["Category", esc(e.category || "—")],
    ["Attack score", e.attack_score || "—"],
    ["Bot score", e.bot_score || "—"],
    ["Match count", e.match_count || "—"],
    ["Honeypot hit", e.honeypot_hit ? "yes" : "no"],
    ["Duration", e.duration_ms ? e.duration_ms + " ms" : "—"],
    ["Status code", e.status_code || "—"],
    ["Request id", esc(e.request_id || "—")],
  ];
  const dl = rows.map(([k, v]) => "<dt>" + k + "</dt><dd>" + v + "</dd>").join("");
  $("modal").innerHTML =
    '<div class="mhead"><h3>Event detail</h3><span class="spacer"></span>' +
    '<button class="btn sm" id="mcopy" title="Copy request id">Copy request id</button>' +
    '<button class="btn sm" id="mclose">&times;</button></div>' +
    '<div class="mbody"><dl>' + dl +
    (reasons ? '<dt>Reasons</dt><dd><div class="rsn">' + reasons + "</div></dd>" : "") +
    "</dl></div>" +
    '<div class="mfoot"><button class="btn primary" id="mok">Close</button></div>';
  $("overlay").classList.add("show");
  const close = () => $("overlay").classList.remove("show");
  $("mclose").addEventListener("click", close);
  $("mok").addEventListener("click", close);
  $("overlay").addEventListener("click", ev => { if (ev.target === $("overlay")) close(); });
  $("mcopy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(e.request_id || ""); toast("Copied request id " + (e.request_id || ""), "ok"); }
    catch (_) { toast("Clipboard blocked by browser.", "warn"); }
  });
}
function exportCSV() {
  const cols = ["timestamp", "action", "source_ip", "country", "method", "path", "rule_id", "category", "attack_score", "bot_score", "match_count", "status_code", "request_id"];
  const pick = e => [e.timestamp, e.action, e.source_ip, e.country || "", e.method, e.path, e.rule_id || "", e.category || "", e.attack_score || "", e.bot_score || "", e.match_count || "", e.status_code || "", e.request_id || ""].join(",");
  const csv = cols.join(",") + "\n" + EVS.map(pick).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = "waap-events.csv";
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
  toast("Exported " + EVS.length + " events.", "ok");
}

const ACTION_OPTS = ["ALLOW", "BLOCK", "CHALLENGE", "RATE_LIMIT", "THROTTLE", "UNAUTHORIZED", "LOG"];
const AUDIT = { limit: 200, offset: 0 };
async function renderAudit() {
  AUDIT.offset = 0;
  $("view").innerHTML =
    '<div class="panel" style="margin-top:0"><div class="filters"><span style="font-weight:700">Filters</span><span class="muted">server-side — every field narrows the query</span><span class="spacer"></span>' +
    '<button class="btn" id="afAuto">' + (AUTO ? "&#10074;&#10074;&nbsp;Auto-refresh" : "&#9654;&nbsp;Auto-refresh off") + "</button></div>" +
    '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">' +
    '<select id="afAct"><option value="">all actions</option>' + ACTION_OPTS.map(a => "<option>" + a + "</option>").join("") + "</select>" +
    '<input id="afIp" class="evq" placeholder="filter source IP" autocomplete="off">' +
    '<input id="afRule" class="evq" placeholder="filter rule id" autocomplete="off">' +
    '<input id="afCat" class="evq" placeholder="filter category" autocomplete="off">' +
    '<button class="btn primary" id="afRefresh">Apply filters</button>' +
    '<button class="btn" id="afCsv">&#8681;&nbsp;CSV</button></div></div>' +
    '<div class="panel"><div class="filters"><h2 style="margin:0">Security events</h2><span class="evcount" id="evcount"></span><span class="spacer"></span>' +
    '<input id="evq" class="evq" placeholder="search IP / path / rule / category" autocomplete="off"></div>' +
    '<table class="rowtab" id="events"><thead><tr><th>Time</th><th>Action</th><th>IP</th><th>Method</th><th>Path</th><th>Rule</th><th>Category</th><th>Attack / Bot</th></tr></thead><tbody></tbody></table>' +
    '<div class="pager"><span class="evcount" id="auditMoreHint">newest first — scroll into the ring buffer</span><span class="spacer"></span>' +
    '<button class="btn" id="afMore">Load more (+200)</button></div></div>';
  $("afRefresh").addEventListener("click", () => { AUDIT.offset = 0; EVS = []; loadEvents(200, 0, "audit"); });
  $("afCsv").addEventListener("click", exportCSV);
  ["afIp", "afRule", "afCat"].forEach(id => $(id).addEventListener("keydown", ev => { if (ev.key === "Enter") $("afRefresh").click(); }));
  $("afAct").addEventListener("change", () => $("afRefresh").click());
  const aa = $("afAuto");
  if (aa) aa.addEventListener("click", () => {
    AUTO = !AUTO;
    aa.innerHTML = AUTO ? "&#10074;&#10074;&nbsp;Auto-refresh" : "&#9654;&nbsp;Auto-refresh off";
    tick();
  });
  $("evq").addEventListener("input", () => { EVQ = $("evq").value; drawEvents(EVS, "audit"); });
  $("afMore").addEventListener("click", async () => {
    const n = await loadEvents(200, AUDIT.offset, "audit", true);
    if (n < 200) $("afMore").disabled = true;
    AUDIT.offset += 200;
  });
  const n = await loadEvents(200, 0, "audit");
  $("auditMoreHint").textContent = n + " events in the current window" + (AUDIT.offset >= 200 ? " · scrolled to offset " + AUDIT.offset : "");
}

function fieldHtml(f, path) {
  const val = getPath(CFG, path);
  const id = "f-" + path.replace(/[^A-Za-z0-9]/g, "_");
  switch (f.type) {
    case "bool": return '<label class="switch"><input type="checkbox" data-b="' + path + '" ' + (val ? "checked" : "") + '><span class="sl"></span></label>';
    case "select": return '<select data-b="' + path + '" ' + (f.numeric ? 'data-num' : "") + '>' + f.options.map(o => '<option value="' + esc(o.v) + '" ' + (String(val) === String(o.v) ? "selected" : "") + ">" + o.l + "</option>").join("") + "</select>";
    case "tags": return '<input type="text" data-b="' + path + '" data-tags value="' + esc((val || []).join(", ")) + '" placeholder="a, b, c">';
    case "secret": return '<input type="password" data-b="' + path + '" value="' + esc(val || "") + '" autocomplete="off" placeholder="••••••••">';
    case "textarea": return '<textarea data-b="' + path + '" rows="3" style="width:100%">' + esc(val || "") + "</textarea>";
    case "number": return '<input type="number" data-b="' + path + '" value="' + esc(val ?? "") + '">';
    case "color": return '<input type="color" data-b="' + path + '" value="' + esc(val && /^#[0-9a-fA-F]{6}$/.test(val) ? val : "#f6821f") + '" title="Custom accent when Theme = Custom">';
    default: return '<input type="text" data-b="' + path + '" value="' + esc(val ?? "") + '">';
  }
}
function renderGroup(grp) {
  let html = '<div class="sgroup"><div class="head"><h3>' + t(grp.title, grp.title) + "</h3><span class='spacer'></span>";
  if (grp.restart) html += '<span class="muted" title="Persisted; needs Restart to take effect">&#x21bb; restart</span>';
  if (grp.enabled) html += fieldHtml(grp.enabled, grp.enabled.path);
  html += "</div>";
  if (grp.help) html += '<div class="head" style="border:0"><span class="muted">' + grp.help + "</span></div>";
  const cols = grp.cols || 1;
  for (let r = 0; r < (grp.fields || []).length; r += cols) {
    const row = (grp.fields || []).slice(r, r + cols);
    html += '<div class="row" style="' + (cols > 1 ? "flex-wrap:wrap" : "") + '">';
    for (const f of row) {
      html += '<div class="rl"><div class="t">' + f.label + "</div>" + (f.help ? '<div class="h">' + f.help + "</div>" : "") + "</div>" +
              '<div class="rc">' + fieldHtml(f, f.key) + "</div>";
      if (cols > 1) html += '<div style="width:100%;border-bottom:1px solid #f1f4f9;margin:6px 0"></div>';
    }
    html += "</div>";
  }
  if (grp.list) {
    const items = getPath(CFG, grp.list.path) || [];
    items.forEach((item, i) => {
      if (!item) return;
      html += '<div class="item"><div class="filters"><b>' + esc(item.id || item.name || "item") + "</b><span class='spacer'></span>" +
        '<button class="btn danger" data-del="' + grp.list.path + '" data-i="' + i + '">' + t("remove", "Remove") + '</button></div>';
      for (const f of grp.list.fields) {
        const p = grp.list.path + "." + i + "." + f.key;
        html += '<div class="row"><div class="rl"><div class="t">' + f.label + "</div></div><div class='rc' style='" + (f.wide ? "max-width:none;flex:1" : "") + "'>" + fieldHtml(f, p) + "</div></div>";
      }
      html += "</div>";
    });
    html += '<button class="btn" data-add="' + grp.list.path + '" data-blank="' + esc(JSON.stringify(grp.list.blank)) + '">+ ' + (grp.list.add ? t(grp.list.add, grp.list.add) : t("add", "Add")) + "</button>";
  }
  html += '<div class="head" style="border:0;justify-content:flex-end"><button class="btn primary" data-save>' + t("save_page", "Save this page") + '</button></div></div>';
  return html;
}
function sidebarCustomizerHtml() {
  const u = CFG.ui || {};
  const rows = PAGES.map(p => {
    const hidden = u.hidden_pages.includes(p.id);
    const locked = p.id === "overview" || p.id === "interface";
    const updn = '<button class="btn sm" data-navup="' + p.id + '" title="Move up" ' + (locked ? "disabled" : "") + '>&#8593;</button>' +
                 '<button class="btn sm" data-navdn="' + p.id + '" title="Move down" ' + (locked ? "disabled" : "") + '>&#8595;</button>';
    return '<div class="row navrow"><div class="rl"><div class="t">' + p.ic + "&nbsp; " + t(p.label, p.label) + (locked ? ' <span class="muted">(always visible)</span>' : "") + "</div></div>" +
      '<span class="rc" style="display:flex;gap:6px;justify-content:flex-end">' + updn +
      '<button class="btn sm ' + (hidden ? "" : "primary") + '" data-navhide="' + p.id + '" ' + (locked ? "disabled" : "") + '>' + (hidden ? t("Show", "Show") : t("Hide", "Hide")) + "</button></span></div>";
  }).join("");
  return '<div class="sgroup"><div class="head"><h3>' + t("sidebar_layout", "Sidebar layout") + '</h3><span class="spacer"></span></div>' +
    '<div class="head" style="border:0"><span class="muted">Reorder or hide pages. Overview and this page are pinned. Save to apply to the sidebar.</span></div>' + rows +
    '<div class="head" style="border:0;justify-content:flex-end"><button class="btn primary" data-save>' + t("save_page", "Save this page") + '</button></div></div>';
}
function reorderNav(id, dir) {
  const u = CFG.ui;
  let cur = (u.pages_order || []).filter(Boolean);
  const idx = cur.indexOf(id);
  if (idx === -1) { cur = PAGES.map(p => p.id); }
  const i = cur.indexOf(id);
  if (i === -1) return;
  const j = i + dir;
  if (j < 0 || j >= cur.length) return;
  [cur[i], cur[j]] = [cur[j], cur[i]];
  u.pages_order = cur;
  render();
}
function renderSettings(page) {
  $("view").innerHTML = page.groups.map(renderGroup).join("") + (page.id === "interface" ? sidebarCustomizerHtml() : "");
  $("view").addEventListener("input", (ev) => {
    if (ev.target && ev.target.dataset && ev.target.dataset.b !== undefined) setDirty(true);
  });
  $("view").addEventListener("change", (ev) => {
    const t = ev.target;
    if (!t || !t.dataset || t.dataset.b === undefined) return;
    const b = t.dataset.b;
    if (b.indexOf("ui.") === 0) {
      if (b === "ui.theme") { CFG.ui.theme = t.value; applyPrefs(); }
      else if (b === "ui.density") { CFG.ui.density = t.value; applyPrefs(); }
      else if (b === "ui.language") { CFG.ui.language = t.value; LANG = t.value; try { localStorage.setItem("wa_lang", LANG); } catch (_) {} applyLang(); buildNav(); render(); }
      else if (b === "ui.accent") { CFG.ui.accent = t.value; if (CFG.ui.theme === "custom") applyTheme("custom", t.value); }
      else setPath(CFG, b, t.value);
      setDirty(true);
      return;
    }
    setDirty(true);
  });
  $("view").addEventListener("click", (ev) => {
    const t = ev.target;
    if (t.dataset && t.dataset.add !== undefined) {
      let list = getPath(CFG, t.dataset.add);
      if (!Array.isArray(list)) { list = []; setPath(CFG, t.dataset.add, list); }
      list.push(JSON.parse(t.dataset.blank));
      setDirty(true);
      ev.preventDefault(); render();
      toast(t("items_added", "Item added — save to apply."));
    } else if (t.dataset && t.dataset.del !== undefined) {
      let list = getPath(CFG, t.dataset.del);
      if (!Array.isArray(list)) { list = []; setPath(CFG, t.dataset.del, list); }
      list.splice(+t.dataset.i, 1);
      setDirty(true);
      ev.preventDefault(); render();
    } else if (t.dataset && t.dataset.navup !== undefined) {
      ev.preventDefault(); setDirty(true); reorderNav(t.dataset.navup, -1);
    } else if (t.dataset && t.dataset.navdn !== undefined) {
      ev.preventDefault(); setDirty(true); reorderNav(t.dataset.navdn, 1);
    } else if (t.dataset && t.dataset.navhide !== undefined) {
      ev.preventDefault();
      const id = t.dataset.navhide;
      const u = CFG.ui;
      const i = u.hidden_pages.indexOf(id);
      if (i >= 0) u.hidden_pages.splice(i, 1); else u.hidden_pages.push(id);
      setDirty(true); render();
    } else if (t.dataset && t.dataset.save !== undefined) {
      ev.preventDefault();
      savePage(page);
    }
  });
}
function collect(C) {
  $("view").querySelectorAll("[data-b]").forEach(el => {
    const p = el.dataset.b;
    let v;
    if (el.type === "checkbox") v = el.checked;
    else if (el.dataset.num !== undefined) v = el.value === "" ? null : Number(el.value);
    else if (el.type === "number") v = el.value === "" ? null : Number(el.value);
    else if (p === "security.hmac_secret") v = el.value;
    else if (p.endsWith(".override") && el.value === "") v = null;
    else if (el.dataset.tags !== undefined) v = el.value.split(",").map(s => s.trim()).filter(Boolean);
    else v = el.value;
    setPath(C, p, v);
  });
  return C;
}
function stripMaskedSecrets(c) {
  const del = (o, p) => {
    const segs = p.split(".");
    let v = o;
    for (let i = 0; i < segs.length - 1; i++) { if (v == null) return; v = v[segs[i]]; }
    if (v != null) delete v[segs[segs.length - 1]];
  };
  const dropIfMasked = p => { if (getPath(c, p) === MASKED) del(c, p); };
  dropIfMasked("security.hmac_secret");
  dropIfMasked("dashboard.admin_password");
  dropIfMasked("security.store.redis.password");
  (getPath(c, "security.siem.endpoints") || []).forEach(e => {
    if (!e) return;
    if (e.token === MASKED) delete e.token;
    if (e.hmac_secret === MASKED) delete e.hmac_secret;
  });
  (c.domains || []).forEach(d => {
    if (!d) return;
    if (d.behavior && d.behavior.secret === MASKED) delete d.behavior.secret;
    if (d.api_security && d.api_security.jwt && d.api_security.jwt.secret === MASKED) delete d.api_security.jwt.secret;
  });
  return c;
}
async function savePage(page) {
  const btn = $("view").querySelector("[data-save]");
  btn.disabled = true;
  const clone = JSON.parse(JSON.stringify(CFG));
  collect(clone);
  stripMaskedSecrets(clone);
  try {
    const resp = await api("/-/api/config", { method:"PUT",
      headers:{"Content-Type":"application/json"}, body: JSON.stringify(clone) });
    CFG = resp.config;
    normalize(CFG);
    applyPrefs();
    buildNav();
    cleanToasts();
    setDirty(false);
    if (resp.restart_required && resp.restart_required.length) {
      toast(t("config_saved_restart", "Configuration saved. Restart to apply changes.") + " (" + resp.restart_required.join(", ") + ")", "warn");
      const rb = $("restartBadge");
      if (rb) rb.classList.add("show");
    } else {
      toast(t("config_saved_applied", "Configuration saved & applied."), "ok");
    }
    render();
  } catch (e) {
    toast("Save failed: " + e.message, "err");
  } finally { btn.disabled = false; }
}

async function render() {
  $("pagetitle").textContent = PAGES.find(p => p.id === CUR).label;
  clearInterval(window.__ovTimer);
  window.__ovTimer = 0;
  if (CUR === "overview" || CUR === "audit") {
    $("view").innerHTML = '<div class="spin"></div>';
    if (CUR === "overview") await renderOverview(); else await renderAudit();
    tick();
  } else {
    const page = PAGES.find(p => p.id === CUR);
    renderSettings(page);
  }
}
async function boot() {
  $("view").innerHTML = '<div class="spin"></div>';
  $("search").addEventListener("input", (e) => { SEARCH = e.target.value.trim(); buildNav(); });
  $("foot").textContent = "loading…";
  CFG = await api("/-/api/config");
  normalize(CFG);
  if (CFG.ui && (CFG.ui.language === "tr" || CFG.ui.language === "en")) LANG = CFG.ui.language;
  applyPrefs();
  applyLang();
  buildNav();
  $("foot").textContent = "version " + (await api("/-/health")).version + " · console";
  try { $("domainpill").textContent = "domain: " + (CFG.domains || []).map(d => d.hostname).join(", ") || "—"; } catch (_) {}
  const ls = $("langSel");
  if (ls) {
    ls.value = LANG;
    ls.addEventListener("change", async () => {
      LANG = ls.value;
      try { localStorage.setItem("wa_lang", LANG); } catch (_) {}
      if (CFG.ui) { CFG.ui.language = LANG; applyPrefs(); }
      applyLang();
      buildNav();
      render();
      try { await persistPrefs(); } catch (e) { toast(t("fail_restart", "Failed to save") + ": " + e.message, "err"); }
    });
  }
  const ts = $("themeSel");
  if (ts) {
    ts.value = CFG.ui && CFG.ui.theme || "dawn";
    ts.addEventListener("change", async () => {
      CFG.ui.theme = ts.value;
      applyPrefs();
      try { await persistPrefs(); } catch (e) { toast("Palette not saved: " + e.message, "err"); }
    });
  }
  $("btnRestart").addEventListener("click", async () => {
    if (!confirm("Restart the edge now? Unsaved page edits are lost; the persisted config is used.")) return;
    $("btnRestart").disabled = true;
    try {
      await api("/-/api/restart", { method:"POST" });
      toast("Restarting…", "ok");
      const rb = $("restartBadge");
      if (rb) rb.classList.remove("show");
    }
    catch (e) { toast("Restart failed: " + e.message, "err"); $("btnRestart").disabled = false; }
  });
  await render();
}
async function persistPrefs() {
  const clone = JSON.parse(JSON.stringify(CFG));
  stripMaskedSecrets(clone);
  const resp = await api("/-/api/config", { method:"PUT",
    headers:{"Content-Type":"application/json"}, body: JSON.stringify(clone) });
  CFG = resp.config;
  normalize(CFG);
  applyPrefs();
  buildNav();
}
boot().catch(e => toast("Load failed: " + e.message, "err"));
</script>
</body>
</html>`
