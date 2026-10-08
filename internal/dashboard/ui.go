package dashboard

import "text/template"

var challengePageTemplate = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         background:#0b0b0f; color:#d7d7e0; display:flex; align-items:center;
         justify-content:center; min-height:100vh; }
  .card { background:#14141b; border:1px solid #262633; border-radius:12px;
          padding:32px 40px; width:min(480px,90vw); text-align:center; }
  .logo { color:#7c6cff; font-weight:700; font-size:18px; letter-spacing:.5px; }
  .spinner { width:34px; height:34px; margin:22px auto; border:3px solid #262633;
             border-top-color:#7c6cff; border-radius:50%; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .muted { color:#8a8a9c; font-size:13px; line-height:1.6; margin-top:8px; }
  .err { color:#ff6b6b; display:none; margin-top:12px; font-size:13px; }
  code { color:#9fe8a1; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">OpenWAAP&nbsp;Shield</div>
  <div class="spinner" id="spinner"></div>
  <div>Checking your browser before accessing</div>
  <div class="muted">Sit tight — a proof-of-work puzzle is being solved in your
    browser. This only takes a moment and verifies the request comes from a
    real visitor.</div>
  <div class="muted">Difficulty <code id="diff"></code> &middot; SHA-256</div>
  <div class="err" id="err"></div>
</div>
<script>
const CH = {{.Data}};
const target = "0".repeat(CH.difficulty);
const enc = new TextEncoder();
document.getElementById("diff").textContent = CH.difficulty;

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function solve() {
  for (let n = 0; ; n++) {
    const hex = toHex(await crypto.subtle.digest("SHA-256", enc.encode(CH.cleartext + ":" + n)));
    if (hex.startsWith(target)) return n;
    if (n % 1024 === 0) await new Promise(r => setTimeout(r, 0));
  }
}

(async () => {
  try {
    const nonce = await solve();
    const body = new URLSearchParams({
      cleartext: CH.cleartext,
      signature: CH.signature,
      nonce: String(nonce),
      next: CH.next
    });
    const res = await fetch("/-/challenge/verify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      redirect: "follow"
    });
    if (!res.ok) throw new Error("verify failed (" + res.status + ")");
    window.location.href = CH.next;
  } catch (e) {
    document.getElementById("spinner").style.display = "none";
    document.getElementById("err").style.display = "block";
    document.getElementById("err").textContent = "Verification failed. Reload to try again.";
    console.error(e);
  }
})();
</script>
</body>
</html>`))

const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenWAAP — Sign in</title>
<style>
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background: radial-gradient(1200px 500px at 85% -10%, #fde7cf 0%, transparent 55%),
                     radial-gradient(900px 420px at -10% 110%, #dbe6ff 0%, transparent 55%),
                     linear-gradient(180deg,#f6f8fb 0%,#ebeff5 100%);
         color:#1c2733; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { background:rgba(255,255,255,.9); backdrop-filter:blur(6px); border:1px solid #e2e8f0;
          border-radius:16px; box-shadow:0 18px 50px rgba(16,44,87,.10); padding:36px 40px;
          width:min(400px,100%); }
  .brand { display:flex; align-items:center; margin-bottom:4px; }
  .brand .name { font-weight:800; font-size:20px; letter-spacing:.2px; }
  .tagline { color:#718096; font-size:13px; margin:0 0 20px; }
label { display:block; font-size:13px; font-weight:600; color:#2d3748; margin:16px 0 6px; }
  input { width:100%; padding:11px 13px; border-radius:9px; border:1px solid #cbd5e0;
           background:#fbfcfe; color:#1c2733; font:inherit; }
   input:focus { outline:none; border-color:#f6821f; box-shadow:0 0 0 3px rgba(246,130,31,.15); }
  button { margin-top:24px; width:100%; padding:12px; border:0; border-radius:9px;
           background:linear-gradient(135deg,#f6821f,#ed6f0c); color:#fff; font:inherit; font-weight:700;
           cursor:pointer; box-shadow:0 4px 14px rgba(215,120,15,.28); }
  button:hover { filter:brightness(1.05); }
  button:disabled { opacity:.6; cursor:wait; }
  .err { color:#c53030; font-size:13px; margin-top:14px; display:none; text-align:center; }
  .foot { position:fixed; bottom:18px; left:0; width:100%; text-align:center; color:#9aa7b8; font-size:12px; }
  .lock { text-align:center; margin-top:18px; color:#9aa7b8; font-size:12px; }
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="name">OpenWAAP</div>
  </div>
  <div class="tagline" data-i18n="tagline">Security for your web applications &amp; APIs</div>
  <form id="f">
    <label for="user" data-i18n="username">Username</label>
    <input id="user" name="user" autocomplete="username" required>
    <label for="password" data-i18n="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit" id="submit" data-i18n="signin">Sign in</button>
  </form>
  <div class="err" id="err"></div>
  <div class="lock" data-i18n="lock">&#128274;&nbsp;Authorized operators only</div>
</div>
<div class="foot" data-i18n="foot">OpenWAAP &middot; operator console</div>
<script>
const LTR = {
  tagline: ["Security for your web applications &amp; APIs", "Web uygulamalarınız ve API'leriniz için güvenlik"],
  username: ["Username", "Kullanıcı adı"],
  password: ["Password", "Şifre"],
  signin: ["Sign in", "Giriş yap"],
  signing: ["Signing in…", "Giriş yapılıyor…"],
  lock: ["&#128274;&nbsp;Authorized operators only", "&#128274;&nbsp;Yetkili operatörler"],
  foot: ["OpenWAAP &middot; operator console", "OpenWAAP &middot; operatör konsolu"],
  bad: ["Invalid credentials.", "Geçersiz kullanıcı bilgileri."]
};
let li = 0;
try { li = localStorage.getItem("wa_lang") === "tr" ? 1 : 0; } catch (_) {}
document.querySelectorAll("[data-i18n]").forEach(el => {
  const k = el.getAttribute("data-i18n");
  if (LTR[k]) el.innerHTML = LTR[k][li];
});
const t = k => (LTR[k] ? LTR[k][li] : k);
document.getElementById("user").focus();
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("submit");
  btn.disabled = true;
  btn.textContent = t("signing");
  try {
    const res = await fetch("/-/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user: document.getElementById("user").value,
        password: document.getElementById("password").value
      })
    });
    if (res.ok) { window.location.href = "/-/"; return; }
    const err = document.getElementById("err");
    err.style.display = "block";
    err.textContent = t("bad");
  } finally { btn.disabled = false; btn.textContent = t("signin"); }
});
</script>
</body>
</html>`
