<div align="center">

# 🛡️ OpenWAAP — Açık Kaynak, Self-Hosted WAF, Bot Yönetimi ve API Güvenliği Platformu

**Go ile yazılmış, tek binary, kendi sunucunda çalışan Web Application Firewall (WAF) + Bot Yönetimi + API Güvenliği + L7 DDoS Koruması.**
Trafiğini üçüncü parti bir bulut proxy'sine yönlendirmeden, **kendi VDS'inde ve kendi public IP'inde** korunmasını sağlar.

*Open-source, self-hosted Web Application Firewall (WAF), bot management, API security gateway and Layer-7 DDoS protection written in Go. Single static binary, zero runtime dependencies, built-in admin console.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](go.mod)
[![Single Binary](https://img.shields.io/badge/deploy-single%20static%20binary-informational)](#-kurulum)
[![Version](https://img.shields.io/badge/version-1.0-brightgreen)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blueviolet.svg)](#-katkıda-bulunma)

[Nedir?](#-openwaap-nedir) •
[Özellikler](#-öne-çıkan-özellikler) •
[Mimari](#-mimari) •
[Kurulum](#-kurulum) •
[Yapılandırma](#-yapılandırma) •
[Yönetim Paneli](#-yönetim-paneli) •
[Sorun Giderme](#-sorun-giderme) •
[SSS](#-sık-sorulan-sorular-sss)

</div>

---

## 📌 OpenWAAP Nedir?

**OpenWAAP (Web Application & API Protection)**, ModSecurity, Cloudflare WAF veya AWS WAF gibi ürünlerin sunduğu koruma katmanını **kendi altyapında** çalıştırmanı sağlayan, Go ile yazılmış açık kaynak bir güvenlik platformudur. Reverse proxy, WAF kural motoru, bot tespiti, API güvenliği, davranışsal analiz, L7 DDoS koruması ve tam donanımlı bir yönetim paneli **tek bir process** içinde çalışır.

**Neden self-hosted WAF?**

- 🔒 **Trafik senin sunucundan çıkmaz.** Üçüncü parti bir proxy ağına DNS yönlendirmesi yapmazsın, veri egemenliğini korursun.
- 💸 **İstek başına ücret / abonelik yok.** Kur, çalıştır, sınırsız istek.
- ⚙️ **Tam kontrol.** Kural motorundan HMAC secret'lara kadar her şey senin config dosyanda.
- 🚀 **Tek binary.** Harici runtime, container orkestrasyonu ya da bağımlılık yönetimi gerekmez.
- 🔍 **Açıklanabilir kararlar.** Her ALLOW / CHALLENGE / BLOCK kararı puan dökümüyle birlikte loglanır.

---

## ✨ Öne Çıkan Özellikler

| Kategori | Yetenekler |
|---|---|
| **WAF Motoru** | SQL Injection, XSS, RCE, LFI ve Path Traversal için managed ruleset, `paranoia_level` ayarı, `IF … AND … THEN …` söz dizimli **custom rule DSL**, form ve JSON gövde (body) denetimi, açıklanabilir engelleme |
| **Bot Yönetimi** | User-Agent heuristikleri, verified bot muafiyeti (Googlebot, Bingbot vb.), **davranışsal bot skorlama** (çerez uyumu, UA kararlılığı, navigasyon sırası, header yeterliliği, burstiness), HMAC imzalı client fingerprint çerezi |
| **API Güvenliği** | JWT auth gate (HS256 / RS256), `iss` / `aud` / `exp` / `nbf` doğrulama, route bazlı **JSON Schema** request validasyonu, deterministik 401 / 403 |
| **L7 DDoS Koruması** | IP başına saniyelik limit, site geneli burst algılama ve otomatik **defense mode**, CIDR allowlist |
| **Rate Limiting** | 5 scope (`ip`, `path`, `ip_path`, `ip_method`, `header`), sliding-window sayaç, iki kademeli throttling, **Redis** ile dağıtık sayaç |
| **Proof-of-Work Challenge** | SHA-256 tabanlı, tarayıcıda çözülen challenge sayfası; sunucu tarafı session tutmayan HMAC imzalı, IP'ye bağlı erişim çerezi |
| **Honeypot** | `/wp-admin`, `/.env` gibi otomatik sahte endpoint'ler ile saldırgan tespiti, sonucu IP itibar motoruna besler |
| **IP İtibar Motoru** | Zamanla sönümlenen (time-decay) puanlama; veritabanı gerektirmeyen "saldırılardan öğrenen" döngü |
| **Gözlemlenebilirlik** | Prometheus `/-/metrics`, `/-/healthz`, `/-/readyz`, yapılandırılmış JSONL event log, hassas veri maskeleme, boyut bazlı log rotation |
| **SIEM / Audit** | HMAC imzalı HTTP batch forwarder, syslog (UDP / TCP) sink, GeoIP / ASN zenginleştirme (MaxMind `.mmdb`) |
| **Yönetim Paneli** | Web konsolu, canlı config API, **live-apply**, self-restart, 6 tema, EN / TR dil desteği, IP allowlist |
| **Kurulum Sihirbazı** | `/-/setup` üzerinden 5 adımda kurulum: TLS, origin, koruma profili, yönetici hesabı, HMAC üretimi |
| **Hardening** | HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, CSP başlıkları; edge son yazar olduğu için origin bunları zayıflatamaz |
| **Operasyon** | `-validate` ve `-backup` CLI komutları, graceful shutdown (10 sn drain), fail-open / fail-closed seçeneği |

---

## 🏗️ Mimari

```
Ziyaretçi
   │  HTTPS
   ▼
┌───────────────────────────────────────────────────────────────┐
│                  OpenWAAP Edge (tek binary)                   │
│                                                               │
│  TLS sonlandırma                                              │
│   → L7 DDoS Guard → Honeypot → IP İtibar → Bot Tespiti        │
│   → Rate Limiting → JWT / API Güvenliği                       │
│   → Managed WAF (SQLi / XSS / RCE / LFI / Path Traversal)     │
│   → Custom Rule DSL → Davranışsal Analiz                      │
│   → Karar Motoru (ALLOW / CHALLENGE / BLOCK)                  │
│   → Hardening Response Header'ları                            │
│                                                               │
│  Event Pipeline → JSONL log · Prometheus · SIEM · Panel (/-/) │
└───────────────────────────────────────────────────────────────┘
   │  HTTP (127.0.0.1)
   ▼
Origin sunucun (Apache / Nginx / LiteSpeed / PHP-FPM / Node ...)
```

Pipeline **"ucuz olan önce"** prensibiyle çalışır: ucuz ve deterministik kapılar (DDoS, honeypot, itibar, bot, rate limit) isteği WAF derin denetimine ulaşmadan reddedebilir. Böylece saldırganlar pahalı kural denetimine ancak ucuz kapılardan geçtikten sonra ulaşır.

---

## 🚀 Kurulum

Bu doküman kurulum için ihtiyacın olan **her şeyi** içerir; ayrı bir kurulum dosyasına gerek yoktur.

### Gereksinimler

- **Derlemek için:** Go **1.22+**
- Bir sunucu / VDS (public IP + alan adı)
- *(Opsiyonel)* Redis: dağıtık rate limit için
- *(Opsiyonel)* MaxMind GeoLite2 `.mmdb`: GeoIP / ASN zenginleştirme için

### Kurulum yolunu seç

OpenWAAP web sunucunun **önünde** durur: TLS'i sonlandırır, korumayı uygular ve istekleri arkadaki origin'e iletir.

```
ziyaretçi ──TLS──▶ OpenWAAP (WAF + DDoS) ──http:127.0.0.1──▶ Apache / Nginx / PHP-FPM
```

| Yol | Ne zaman | Gerekenler |
|---|---|---|
| **[Yol 1 — cPanel](#yol-1--cpanel-ile-kurulum-terminal-gerekmez)** | Root / SSH erişimin yok, yalnızca cPanel var | Dosya Yöneticisi + Cron + tarayıcı sihirbazı |
| **[Yol 2 — SSH + systemd](#yol-2--ssh--systemd-ile-kurulum)** | Root SSH erişimin var (Debian / Ubuntu / RHEL) | systemd + firewall + TLS + yedekleme |

> **Subdomain gerekmez.** İki yolda da sihirbazdaki `hostname` alanına ana alan adını (örn. `ornek.com`) yazman yeterlidir. cPanel'de site `https://ornek.com:8443`, SSH yolunda `https://ornek.com` üzerinden OpenWAAP'tan geçer.
>
> **Neden cPanel'de 8443?** cPanel'in Apache'i 80 / 443 portlarını ve Let's Encrypt'i sahiplenir. OpenWAAP onlara dokunmaz ve kendi yetkisiz portunda (**8443**) durur. Root + systemd olan SSH yolunda doğrudan **443**'te çalışır.

---

### Adım 0 — Binary'yi derle (her iki yol için ortak)

```bash
git clone https://github.com/cveburak/openwaap.git
cd openwaap

# Statik, küçültülmüş Linux binary (CGO yok, glibc bağımlılığı yok)
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o openwaap ./cmd/openwaap

./openwaap -version
```

Başka mimari için: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o openwaap ./cmd/openwaap`

**Config ve TLS sertifikasını elle hazırlamana gerek yok.** Config dosyası yoksa OpenWAAP **kurulum modunda** açılır, self-signed bir boot sertifikası üretir ve `/-/setup` adresinde 5 adımlı sihirbazı sunar. Sihirbaz config'i yazar ve process kendini normal modda yeniden başlatır.

### Kurulum sihirbazının 5 adımı (iki yol için de ortak)

1. **Dinleyiciler / TLS:** Port ve TLS dosya yolları. Ekrandaki hazır yolları değiştirme (cPanel'de `:8443` / `:8080`, SSH'de `:443` / `:80`).
2. **Origin:** Hostname alanına ana alan adın, origin olarak `http://127.0.0.1:80` (cPanel Apache) veya `http://127.0.0.1:8080` (SSH'de ayarladığın web sunucusu).
3. **Koruma profili:** Basic / Standard / Strict ve istediğin modüller (DDoS, challenge vb.).
4. **Yönetici:** Panel kullanıcı adı ve şifresi. **Admin access** alanına kendi **sabit IP**'ni yaz (örn. `203.0.113.77/32`). Böylece login ve konsol yalnızca sana açılır, diğerlerine 404 döner. Boş bırakırsan konsol dinleyiciye ulaşan herkese görünür (veriler yine şifreyle korunur).
5. **Özet:** `install` → config yazılır, sertifika bağlanır, self-restart olur. `/-/setup` otomatik kapanır.

---

### Yol 1 — cPanel ile Kurulum (terminal gerekmez)

`https://SUNUCU_IP:2083` adresinden cPanel'e gir.

**1.1 Klasörler ve binary**

1. **Dosya Yöneticisi** → home dizinine gir.
2. **+ Klasör** ile `openwaap` klasörünü oluştur.
3. Klasöre girip **Karşıya Yükle** ile `openwaap` binary'sini yükle.
4. Binary'ye sağ tık → **İzinleri Değiştir** → `755`.
5. Aynı klasörde `certs` ve `config` klasörlerini **elle aç**. (OpenWAAP `config/` klasörünü otomatik oluşturmaz. `logs/` otomatik oluşur, onu açma.)

**1.2 Cron ile başlat (sunucu yeniden başlayınca da çalışsın)**

**Cron İşleri** → **Yeni Cron İşi Ekle** → Dakika alanına `@reboot`, Komut alanına:

```bash
cd $HOME/openwaap && ./openwaap -config config/openwaap.yaml -log logs/events.jsonl &
```

> ⚠️ `cd` zorunludur. Config'teki sertifika yolları göreli (`certs/edge.pem`) ve process'in çalıştığı klasöre göre çözülür. `cd` olmazsa cron `$HOME`'dan başlatır ve OpenWAAP hiç açılmaz.

Ekledikten sonra config olmadığı için OpenWAAP kurulum modunda başlar.

**1.3 Sihirbazı tamamla**

```
https://ornek.com:8443/-/setup
```

Self-signed sertifika uyarısını "Devam et" ile geç (normaldir). Yukarıdaki 5 adımı doldur. Origin adımında:
- **Hostname:** `ornek.com`
- **Origin:** `http://127.0.0.1:80`

**1.4 Firewall (CSF / LFD)**

Sunucu 8443'ü kapatıyorsa: **WHM → ConfigServer & Firewall (CSF) → Firewall Configuration** → `TCP_IN` listesine `8443` ekle → değişiklikleri uygula. WHM erişimin yoksa hosting firmasından "8443 portunu açın" diye talep et.

**1.5 Kontrol**

- Konsol: `https://ornek.com:8443/-/login`
- Saldırı testi: `https://ornek.com:8443/?q=%3Cscript%3Ealert(1)%3C/script%3E` → **403** dönmeli (normal istek 200).
- Mobil şebekeden (allowlist dışı IP) `/-/login` → **404**.
- `/-/healthz`, `/-/readyz`, `/-/metrics` herkese açıktır (sır içermez).

**1.6 Yükseltme:** Yeni binary'yi aynı dosyanın üzerine yaz → **Cron İşleri** → işi **Düzenle** → **Güncelle**. `certs/` ve `config/openwaap.yaml` aynı kalır.

**1.7 Kaldırma:** Cron satırını sil → `openwaap` klasörünü sil → (WHM'deyse) 8443'ü firewall'da geri kapat.

---

### Yol 2 — SSH + systemd ile Kurulum

Root SSH'li herhangi bir Linux'ta çalışır (özel kullanıcı + systemd + firewall).

**2.1 Konum ve binary**

```bash
sudo mkdir -p /opt/openwaap/{config,certs,logs}
sudo useradd -r -d /opt/openwaap -s /usr/sbin/nologin openwaap
sudo install -m 0755 ./openwaap /opt/openwaap/openwaap
sudo chown -R openwaap:openwaap /opt/openwaap
```

**2.2 Config: iki seçenek**

**Seçenek A: Kurulum sihirbazı (önerilen).** Config yokken edge `8443 / 8080` portlarında kurulum modunda açılır. `/-/setup` sihirbazı sertifikayı üretir, config'i yazar ve yeniden başlar.

**Seçenek B: Elle yapılandırma.**

```bash
sudo cp config/openwaap.example.yaml /opt/openwaap/config/openwaap.yaml
```

Minimum örnek:

```yaml
server:
  listen_https: ":443"
  listen_http: ":80"            # yalnızca HTTP→HTTPS (308) yönlendirmesi için
  tls_cert_file: "certs/edge.pem"
  tls_key_file: "certs/edge.key"
domains:
  - hostname: ornek.com         # ana alan adın, subdomain gerekmez
    origin:
      scheme: http              # arkada TLS'li origin için https
      host: 127.0.0.1
      port: "8080"
    waf:
      mode: block
```

Doğrula:

```bash
sudo -u openwaap /opt/openwaap/openwaap -config /opt/openwaap/config/openwaap.yaml -validate
```

**2.3 Arkadaki web sunucusunu yalnızca 127.0.0.1'de dinlet**

Apache:

```apache
# /etc/apache2/ports.conf + vhost
Listen 127.0.0.1:8080
<VirtualHost 127.0.0.1:8080>
  ServerName ornek.com
  DocumentRoot /var/www/ornek
  <Directory /var/www/ornek>
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
```

Nginx:

```nginx
# /etc/nginx/conf.d/openwaap-origin.conf
server {
  listen 127.0.0.1:8080;
  server_name ornek.com;
  root /var/www/ornek;
  index index.php index.html;
}
```

> 🔒 Origin'i **yalnızca 127.0.0.1**'de dinlet ve firewall'da 8080'i asla dışarı açma. Aksi halde saldırganlar OpenWAAP'ı atlayıp origin'e doğrudan ulaşır.

**2.4 systemd servisi**

`/etc/systemd/system/openwaap.service`:

```ini
[Unit]
Description=OpenWAAP edge (WAF + DDoS + API security)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openwaap
Group=openwaap
WorkingDirectory=/opt/openwaap
ExecStart=/opt/openwaap/openwaap -config /opt/openwaap/config/openwaap.yaml -log /opt/openwaap/logs/openwaap-events.jsonl
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWritePaths=/opt/openwaap
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

> 1024 ve üzeri bir port (örn. `:8443`) kullanıyorsan `AmbientCapabilities` satırını silebilirsin.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openwaap

curl -k https://127.0.0.1/-/healthz
curl -k https://127.0.0.1/-/readyz
curl -s https://127.0.0.1/-/metrics
```

DNS A kaydını sunucuya çevir. `Host` başlığı config'teki hostname ile birebir eşleşmelidir (yanlış host → 404, fail-closed).

**2.5 Firewall**

```bash
# ufw
sudo ufw allow 80,443/tcp

# firewalld
sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload
```

**2.6 TLS sertifikası**

- **Test:** İlk boot sihirbazı `certs/` altına self-signed sertifika üretir.
- **Üretim (Let's Encrypt):** Origin 8080'de olduğu için 80 portu boştadır:

```bash
sudo certbot certonly --webroot -w /var/www/ornek -d ornek.com \
  --post-hook "cp /etc/letsencrypt/live/ornek.com/fullchain.pem /opt/openwaap/certs/edge.pem && cp /etc/letsencrypt/live/ornek.com/privkey.pem /opt/openwaap/certs/edge.key && chown openwaap:openwaap /opt/openwaap/certs/* && systemctl restart openwaap"
```

Yenilemede aynı kopyalama + restart komutu `--post-hook` / `renew_hook` ile otomatik çalışır.

**2.7 Güncelleme ve yedekleme**

```bash
# Güncelleme
sudo systemctl stop openwaap
sudo install -m 0755 ./openwaap /opt/openwaap/openwaap
sudo systemctl start openwaap

# Yedek: config + event log + sertifikalar → tar.gz + manifest.json
sudo -u openwaap /opt/openwaap/openwaap \
  -config /opt/openwaap/config/openwaap.yaml \
  -backup -out /srv/backups/openwaap.tar.gz
```

**2.8 Kaldırma**

```bash
sudo systemctl disable --now openwaap && sudo rm /etc/systemd/system/openwaap.service
sudo rm -rf /opt/openwaap
```

---

### Kurulum sonrası

**Yönetim panelini dışarıdan gizle (`admin_allowlist`).** Varsayılanda panel, dinleyiciye ulaşan herkese açıktır (veriler şifreyle korunur). Login sayfasına bile dışarıdan erişilmesin istiyorsan:

```yaml
dashboard:
  enabled: true
  admin_allowlist: ["203.0.113.77/32"]   # yalnızca senin sabit IP'n / alt ağın
  console_path: "/-"                      # farklı bir değer (örn. "/ops-8x3h") paneli gizler
```

- Allowlist **boş = herkese açık**. Doluyken listede olmayan IP'ler `/-/login`, `/-/`, `/-/api/*` için **404** alır.
- **En sıkı yol:** `["127.0.0.1"]` yapıp SSH tüneliyle gir:
  ```bash
  ssh -L 7443:127.0.0.1:443 kullanici@sunucu   # sonra https://127.0.0.1:7443/-/
  ```

**Çalıştığını doğrula:**

```bash
curl -sk https://ornek.com/-/healthz                       # {"status":"ok",...}

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://ornek.com/?q=%3Cscript%3Ealert(1)%3C/script%3E" # → 403 (WAF BLOCK)

curl -skI https://ornek.com/                               # hardening başlıkları
# Strict-Transport-Security / X-Frame-Options / X-Content-Type-Options ...
```

> cPanel yolunda adreslere `:8443` ekle.

---

## ⚙️ Yapılandırma

Tüm ayarlar tek bir YAML dosyasında ([`config/openwaap.example.yaml`](config/openwaap.example.yaml)) toplanır: alan adı yönlendirme, WAF paranoia seviyesi, rate limit scope'ları, JWT / API güvenliği, DDoS eşikleri, SIEM hedefleri, tema ve dil tercihleri.

**Secret'lar config'e düz metin yazılmaz.** `hmac_secret`, `admin_password`, JWT anahtarı, Redis parolası ve SIEM token'ı `${ENV_VAR}` referanslarıyla dışarıda tutulur. Boş bırakılan HMAC secret boot sırasında rastgele üretilir.

Örnek domain yapılandırması:

```yaml
domains:
  - hostname: ornek.com
    origin: { scheme: http, host: 127.0.0.1, port: "8080" }

    waf:
      mode: block                # detection = yalnızca logla | block = uygula | disabled = atla
      managed:
        paranoia_level: 2
        categories:
          SQL_INJECTION: true
          XSS: true
          RCE: true
          LFI: true
          PATH_TRAVERSAL: true
      custom_rules:
        - id: block-admin-abroad
          enabled: true
          dsl: 'IF path starts_with "/admin" AND country != "TR" THEN BLOCK'
        - id: challenge-low-bot
          enabled: true
          dsl: 'IF path == "/login" AND bot_score < 20 THEN CHALLENGE'

    rate_limits:
      enabled: true
      limits:
        - id: login-rate
          scope: ip_path         # ip | path | ip_path | ip_method | header
          path: /login
          max: 10                # 0..max: izin
          throttle_max: 40       # max..throttle_max: yavaşlat, ötesi: action
          window: 60s
          action: BLOCK

    bot:
      enabled: true
      challenge_below: 20
      block_below: 5
      verified_bots: [googlebot, bingbot]

    api_security:
      enabled: true
      jwt:
        algorithm: HS256
        secret: ${WAAP_JWT_SECRET}
        issuer: benim-api
        audiences: [api.ornek.com]
      routes:
        - path: /api/v1/orders
          method: POST
          request_schema: '{"type":"object","properties":{"qty":{"type":"integer","minimum":1}},"required":["qty"]}'
        - path: /api/v1/health
          auth_none: true
      policy: { authn_required: true, validate_schema: true }

security:
  engine_fail_mode: fail_open    # güvenlik-kritik uygulamalar için fail_closed
  ddos:
    enabled: true
    per_ip_rate: 50
    per_ip_action: challenge
    site_burst_rps: 500
  headers:
    hsts: true
    frame_options: DENY
```

**Custom rule DSL** alanları arasında `path`, `country`, `bot_score` gibi değerler ve `==`, `!=`, `<`, `starts_with` gibi operatörler bulunur. Tam liste ve örnekler için `config/openwaap.example.yaml` dosyasına bak.

> **Önemli:** `challenge` aksiyonlarının çalışması için `security.challenge.enabled: true` olmalıdır. Kapalıyken challenge, düz bir red (deny) gibi davranır.

**Panelden yapılan değişiklikler** doğrulanır, atomik olarak kaydedilir ve `domains.*` ile `security.engine_fail_mode` gibi alanlar restart olmadan **canlı uygulanır**. `server.*`, `security.store`, `security.siem`, `security.geoip`, `security.challenge`, `security.hmac_secret`, `dashboard.*` ve `log.*` değişiklikleri kontrollü bir self-restart gerektirir; panel bunu `restart_required` listesinde bildirir.

---

## 🖥️ Yönetim Paneli

`/-/` altında açılan web konsolu:

- **Overview:** canlı event akışı, en çok saldırı yapan IP / path / ülke / kural, zaman serisi grafikler, koruma durumu rozetleri
- **WAF & Rules · Rate Limiting · Bot & Reputation · API Security · Challenge · DDoS Guard · Hardening · Origin & Domains · GeoIP/ASN · SIEM/Audit · Settings**
- **6 tema** (Dawn, Emerald, Sapphire, Amethyst, Coral, Graphite + koyu Night) ve **EN / TR** dil seçici
- **Config API:** `GET /-/api/config`, `PUT /-/api/config`, `POST /-/api/restart`

---

## 📊 Gözlemlenebilirlik ve SIEM

```bash
curl -k https://localhost/-/healthz    # liveness + sürüm
curl -k https://localhost/-/readyz     # Redis ve GeoIP probları; hazır değilse 503
curl -k https://localhost/-/metrics    # Prometheus scrape hedefi
```

Ops uçları dashboard kapalıyken bile aktiftir. Başlıca Prometheus metrikleri: `waap_requests_total{action}`, `waap_requests_denied_total{action,domain}`, `waap_request_latency_seconds`, `waap_active_requests`, `waap_rule_triggers_total{rule_id}`.

SIEM entegrasyonu için HTTP (Bearer token + HMAC-SHA256 imzalı `X-OpenWAAP-Signature`) ve syslog (UDP / TCP) hedefleri config'ten eklenir. Toplayıcı çökse bile teslimat asenkron olduğundan istek yolu asla bloklanmaz.

---

## 🧪 Test ve Geliştirme

```bash
go build ./...              # derleme
go vet ./...                # statik analiz
go test ./...               # birim + e2e + simülatör testleri
go test -race -count=1 ./...  # yarış (race) testleri
go test ./test/e2e/ -v      # uçtan uca saldırı simülasyonu raporu
```

Test kapsamı: WAF kural motoru, rate limit yarış testleri, bot / itibar motoru, JWT ve schema doğrulama, davranışsal analiz, GeoIP zenginleştirme, SIEM forwarder'ları ve uçtan uca saldırı senaryoları (`test/e2e`, `test/simulate`).

CLI komutları:

```bash
./openwaap -config config/openwaap.yaml              # çalıştır
./openwaap -validate -config config/openwaap.yaml    # config'i doğrula ve çık
./openwaap -backup -config config/openwaap.yaml -out backup.tar.gz
./openwaap -version
```

---

## 📁 Proje Düzeni

```
cmd/openwaap/          tek binary giriş noktası (edge + yönetim paneli), backup komutu
internal/config/       YAML yükleme, doğrulama, JSON round-trip
internal/proxy/        edge: TLS, origin proxy, domain routing, graceful shutdown
internal/pipeline/     istek pipeline'ı (cheap-first), body argüman çözümleme
internal/rules/        managed ruleset, custom DSL, kural yaşam döngüsü
internal/decision/     karar motoru + açıklanabilir engelleme
internal/scoring/      saldırı skoru
internal/ratelimit/    sliding-window + Redis backend
internal/bot/          bot skorlama + verified bot muafiyeti
internal/behavior/     davranışsal analiz + client fingerprint
internal/reputation/   IP itibar motoru (time-decay)
internal/honeypot/     sahte endpoint otomasyonu
internal/apisec/       JWT doğrulayıcı + JSON Schema doğrulayıcı
internal/ddos/         L7 DDoS guard
internal/dashboard/    yönetim paneli UI + REST API + setup sihirbazı + PoW challenge
internal/siem/         HTTP batch + syslog forwarder
internal/geo/          MaxMind GeoIP / ASN
internal/metrics/      Prometheus exposition
internal/ops/          healthz / readyz / metrics
internal/events/       event şeması + emitter
internal/logging/      JSONL sink, rotation, redaction
test/                  test origin, saldırı simülatörü, e2e testler
```

---

## 🔐 Güvenlik Notları

- TLS private key, JWT signing key ve token'lar **asla** repoya eklenmemelidir. `.gitignore` bunu `*.key`, `*.pem`, `certs/`, `secrets/`, `.env` desenleriyle zaten engeller.
- Secret'ları yalnızca `${ENV_VAR}` referanslarıyla ver.
- Log katmanı varsayılan olarak `Authorization`, `token`, `cookie`, `password` değerlerini maskeler.
- Origin sunucuyu **yalnızca 127.0.0.1**'de dinlet ve yönetim paneli için `admin_allowlist` kullan.
- Bir güvenlik açığı bulursan lütfen public issue açmadan önce depo sahibiyle özel olarak iletişime geç.

---

## ⚠️ Bilinen Sınırlar

Dürüst olmak gerekirse:

- **L3 / L4 DDoS koruması yoktur.** OpenWAAP uygulama katmanı (L7) hacmini soğurur. Ağ katmanı volumetrik saldırılar için hosting sağlayıcının veya bir CDN'in koruması gerekir.
- **Ziyaretçi IP'si doğrudan bağlantıdan (`RemoteAddr`) alınır.** `CF-Connecting-IP` veya `X-Forwarded-For` gibi başlıklar şu an okunmaz. Bu yüzden OpenWAAP'ı **Cloudflare gibi bir proxy'nin arkasına** koyarsan tüm ziyaretçiler proxy IP'leri gibi görünür; IP bazlı rate limit, DDoS, itibar, honeypot ve GeoIP doğru çalışmaz. Şu an en doğru kullanım, OpenWAAP'ın **doğrudan internete bakan** edge olduğu senaryodur. Trusted-proxy desteği yol haritasındadır.

---

## 🆚 Neden OpenWAAP?

| | OpenWAAP (self-hosted) | Bulut tabanlı WAF servisleri |
|---|---|---|
| Trafiğin geçtiği yer | Kendi sunucun | Üçüncü parti proxy ağı |
| Maliyet modeli | Tek seferlik kurulum | Genellikle istek / bant genişliği bazlı abonelik |
| Veri kontrolü | Tamamen sende | Sağlayıcının politikasına bağlı |
| Özelleştirme | Kaynak koduna tam erişim (Go) | Sağlayıcının sunduğu kadar |
| Dağıtım | Tek statik binary | Sağlayıcıya bağlı |

---

## ❓ Sık Sorulan Sorular (SSS)

**OpenWAAP nedir, ModSecurity'den farkı ne?**
OpenWAAP; managed ruleset, bot yönetimi, API güvenliği, L7 DDoS koruması ve yönetim panelini **tek bir Go binary'sinde** birleştiren self-hosted bir Web Application & API Protection platformudur. Ayrı bir web sunucusu modülü gerektirmez, reverse proxy olarak önünde durur.

**Cloudflare yerine kullanabilir miyim?**
Evet. Trafiğini üçüncü parti bir proxy ağına yönlendirmeden, kendi VDS'inde WAF + bot + API güvenliği + L7 DDoS koruması istiyorsan tam olarak bunun için tasarlandı. Cloudflare'in arkasında birlikte kullanım için [Bilinen Sınırlar](#️-bilinen-sınırlar) bölümüne bak.

**Nginx veya Apache ile birlikte çalışır mı?**
Evet. OpenWAAP bu sunucuların önünde durur; onlar `127.0.0.1` üzerinde origin olarak çalışır.

**WordPress / PHP siteleri için uygun mu?**
Evet. Origin'in ne olduğu fark etmez (PHP-FPM, Node, Python, statik site). Honeypot `/wp-admin` ve `/.env` gibi tarama yollarını otomatik yakalar.

**Root erişimim yok, kurabilir miyim?**
Evet. [Yol 1 (cPanel)](#yol-1--cpanel-ile-kurulum-terminal-gerekmez) yalnızca Dosya Yöneticisi ve Cron ile kurulur.

**Yüksek erişilebilirlik / yatay ölçekleme?**
`security.store.type: redis` ile birden fazla edge aynı sliding-window sayaçlarını paylaşabilir.

**Hangi işletim sistemlerinde çalışır?**
Go'nun desteklediği her platformda derlenebilir; üretim kurulum rehberi Linux / VDS odaklıdır.

**Ticari kullanım serbest mi?**
Evet, [MIT Lisansı](LICENSE) kapsamındadır.

---

## 🩺 Sorun Giderme

| Belirti | Olası sebep / çözüm |
|---|---|
| `openwaap starting domains=0` | Domain `enabled: false` ya da eksik; `-validate` ile kontrol et. |
| `:443 address already in use` | Apache / Nginx hâlâ 443'e bağlı. SSH yolunda origin'i 8080'e taşı, cPanel yolunda `:8443` kullan. |
| Her istek 404 dönüyor | `Host` başlığı config'teki hostname ile eşleşmiyor. **IP ile değil alan adıyla** test et. |
| Origin 502 `origin unavailable` | Origin ayakta değil ya da yalnızca global IP'ye dinliyor; `ss -lnt` ile kontrol et. |
| Cron'dan hiç başlamıyor (Yol 1) | `cd $HOME/openwaap && ...` öneki eksik. Cron `$HOME`'dan çalıştırır, göreli yollar kırılır. |
| `fail_closed` + engine hatası | Güvenlik-kritik mod istekleri reddeder. Test için `fail_open`, üretim için bilinçli seç. |
| Panel 401 | `/-/login`'e form ile gir (JSON değil). Kullanıcı bilgileri config'teki `dashboard` alanlarındadır. |
| Panel "Save failed / invalid config" | Eski (v0.2) binary'den kaynaklanır; v1.0'a güncelle. |
| Tarayıcıda sertifika uyarısı (8443) | Self-signed sertifika normaldir. Gerçek sertifika için Yol 2'de certbot kullan. |
| DDoS `challenge` çalışmıyor | Sihirbazda / config'te **Challenge modülü** kapalı; açık değilse challenge deny gibi davranır. |

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. Ticari ve kişisel projelerde özgürce kullanabilirsin.

---

<div align="center">

⭐ Projeyi faydalı bulduysan yıldız vermeyi unutma!

</div>
