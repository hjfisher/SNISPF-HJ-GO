
# SNISPF-HJ-GO

### ابزار خط‌فرمان دور زدن DPI روی همه پلتفرم‌ها (پورت Go) — Pool تطبیقی چند IP/SNI

```
███████╗███╗   ██╗██╗███████╗██████╗ ███████╗    ██╗  ██╗     ██╗       ██████╗  ██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝    ██║  ██║     ██║      ██╔════╝ ██╔═══██╗
███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗█████╗███████║     ██║█████╗██║  ███╗██║   ██║
╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝╚════╝██╔══██║██   ██║╚════╝██║   ██║██║   ██║
███████║██║ ╚████║██║███████║██║     ██║         ██║  ██║╚█████╔╝      ╚██████╔╝╚██████╔╝
╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝         ╚═╝  ╚═╝ ╚════╝        ╚═════╝  ╚═════╝ 
```

**[EN README](README.md)**

**SNISPF-HJ-GO** پورت **Go** از [SNISPF-HJ](https://github.com/hjfisher/SNISPF-HJ) است، با **uTLS درون‌پروسه** — بدون نیاز به باینری سایدکار. هندشیک TLS بالادست (فینگرپرینت مرورگر ClientHello) مستقیماً در Go با استفاده از کتابخانه [uTLS](https://github.com/refraction-networking/utls) اجرا می‌شود — همان کتابخانه‌ای که xray استفاده می‌کند.

روی **Windows، macOS، Linux و Android (Termux)** کار می‌کند و برای روش پیش‌فرض نیازی به root ندارد.

پیشنهاد یا سؤال؟ → **[SNISPF/discussions](https://github.com/Rainman69/SNISPF/discussions)**

کانفیگ ساز تحت وب → **[SNISPF-HJ-Config-Studio](https://hjfisher.github.io/SNISPF-HJ-Config-Studio/)**

**⭐️ فراموش نشه ⭐️**

---

## چه چیزی جدید است در پورت Go

| ویژگی | SNISPF-HJ (Python) | SNISPF-HJ-GO (Go) |
|---|---|---|
| فینگرپرینت TLS بالادست | باینری سایدکار (`snispf-tls`) | **uTLS درون‌پروسه** — بدون سایدکار |
| رله MITM | سایدکار + رله Python | **uTLS درون‌پروسه** روی سیم واقعی |
| باینری | Python + PyInstaller (~15 MB) | **باینری Go تکی** (~14 MB) |
| وابستگی‌ها | Python 3.8+ | **هیچ** — کامپایل استاتیک |
| زمان کامپایل | ~30 ثانیه (PyInstaller) | ~10 ثانیه (`go build`) |
| مصرف حافظه | ~30 MB (Python) | ~10 MB (Go) |
| زمان راه‌اندازی | ~2 ثانیه (استخراج PyInstaller) | **Instant** |

تمام ویژگی‌های اصلی (pool، discovery، fragment، fake-SNI، combined، domain checker، raw injection، finalmask) کاملاً حفظ شده‌اند.

---

## چطور کار می‌کند؟

وقتی یک سایت HTTPS باز می‌کنی، دستگاهت یک **TLS ClientHello** می‌فرستد که نام سایت به‌صورت متن خام داخل آن است — این **SNI** نام دارد. DPI همین نام را می‌بیند و تصمیم می‌گیرد.

SNISPF-HJ-GO بین برنامه‌ات و اینترنت می‌نشیند و آن سلام را یا **قطعه‌قطعه می‌کند** یا **یک سلام جعلی** قبل از آن می‌فرستد.

```
┌──────────┐     ┌──────────────────┐     ┌──────────┐     ┌──────────────┐
│  برنامه  ├────>│   SNISPF-HJ-GO   ├────>│  DPI /   ├────>│ سرور واقعی   │
│          │     │  (پروکسی محلی)   │     │ فایروال  │     │ (Cloudflare) │
│          │     │                  │     │          │     │              │
│          │     │ ① pool بهترین    │     │ SNI جعلی │     │              │
│          │     │   (IP,SNI) انتخاب│     │ یا تکه‌تکه│     │              │
│          │     │ ② discovery IPهای│     │          │     │              │
│          │     │   جدید اضافه می‌کند│    │          │     │              │
└──────────┘     └──────────────────┘     └──────────┘     └──────────────┘
```

### Pool اتصال

ابزار با جستجوی تصادفی جفت‌های `(IP, SNI)` با یک **TLS handshake واقعی** شروع می‌کند — فقط TCP connect نیست، بلکه یک هندشیک TLS کامل انجام می‌شود زیرا سرور می‌تواند TCP را قبول کند اما لایه TLS را رد یا حذف کند. جفت‌هایی که به خوبی پاسخ می‌دهند وارد **pool فعال** می‌شوند. یک پس‌زمینه به طور دوره‌ای pool را هر ~15-30 ثانیه دوباره بررسی می‌کند و جفت‌های تخریب شده را چرخش می‌دهد. هر اتصال جدید با **انتخاب وزنی تصادفی** یک جفت دریافت می‌کند — امتیاز پایین‌تر به احتمال انتخاب بالاتر.

### uTLS فینگرپرینت درون‌پروسه

در حالت MITM، هندشیک TLS بالادست **مستقیماً در Go** با استفاده از [uTLS](https://github.com/refraction-networking/utls) اجرا می‌شود — همان کتابخانه‌ای که xray استفاده می‌کند. این یک ClientHello با فیدلیتی JA3/JA4 کامل ارسال می‌کند. نیازی به باینری سایدکار خارجی نیست.

فینگرپرینت‌های پشتیبانی شده: `chrome`، `firefox`، `safari`، `ios`، `android`، `edge`، `360`، `qq`، `random`، `randomized`، `randomizednoalpn`، `unsafe`، به علاوه نسخه‌های ثابت مانند `hellochrome_120`، `hellofirefox_105` و غیره.

---

## پیش‌نیازها

- **Go 1.24** یا جدیدتر (برای کامپایل از سورس)
- هیچ وابستگی خارجی برای باینری کامپایل شده نیاز نیست

---

## نصب

### روش ۱ — دانلود باینری (پیشنهادی)

آخرین نسخه را از [GitHub Releases](https://github.com/hjfisher/SNISPF-HJ-GO/releases) دانلود کنید.

### روش ۲ — کامپایل از سورس

```bash
git clone https://github.com/hjfisher/SNISPF-HJ-GO.git
cd SNISPF-HJ-GO
go build -o snispf.exe .
snispf.exe --info
```

### روش ۳ — کامپایل آفلاین (بدون اینترنت)

اگر نمی‌توانید ماژول‌های Go را دانلود کنید، از اسکریپت کامپایل آفلاین استفاده کنید:

```bash
# ویندوز
build.bat

# لینوکس / macOS
chmod +x build.sh && ./build.sh
```

---

## شروع سریع

```bash
# با config.json پیش‌فرض (pool + discovery فعال)
snispf.exe --config config.json

# حالت تک‌جفت (بدون pool)
snispf.exe --listen 0.0.0.0:40443 --connect 172.66.41.252:443 --sni github.com --method fragment
```

خروجی مورد انتظار:

```
Connection pool active — 418 pair(s), 3 active slot(s)
Dynamic IP discovery active — batch=100  interval=120s
Upstream selection: POOL (multi-IP / multi-SNI)
Bypass strategy: combined
Listening on 0.0.0.0:40443
Ready! Configure your application to use:
  Address: 127.0.0.1:40443
```

کلاینت خود (`v2ray`، `xray`، افزونه پروکسی مرورگر، ...) را روی **`127.0.0.1:40443`** تنظیم کن.

---

## پیکربندی

پرچم‌های CLI همیشه مقادیر فایل کانفیگ را override می‌کنند.

```jsonc
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_PORT": 443,
  "BYPASS_METHOD": "combined",
  "FRAGMENT_STRATEGY": "sni_split",
  "FRAGMENT_DELAY": 0.1,
  "FAKE_SNI_METHOD": "prefix_fake",

  // -- Pool ---------------------------------------------------------------
  "ACTIVE_SLOTS": 3,
  "HEALTH_CHECK_INTERVAL": 30,
  "HEALTH_CHECK_TIMEOUT": 3,
  "PROBE_COUNT": 5,
  "LOSS_THRESHOLD": 0.20,
  "DEAD_THRESHOLD": 0.80,
  "DRAIN_TIMEOUT": 30,
  "MAX_DRAINING": 5,

  // -- Eviction & recycling -----------------------------------------------
  "EVICT_EVERY": 3,
  "EVICT_COUNT": 2,
  "RECYCLE_ENABLED": true,
  "RECYCLE_EVERY": 6,
  "RECYCLE_BATCH": 2,
  "RECYCLE_MIN_COOLDOWN": 180,
  "RECYCLE_MAX_QUARANTINE": 100,
  "QUARANTINE_SCOPE": "both",

  "CONNECT_IPS": ["172.66.41.252", "108.162.196.145"],
  "FAKE_SNIS": ["github.com", "google.com"],

  // -- Dynamic IP discovery -----------------------------------------------
  "DYNAMIC_IP_DISCOVERY": true,
  "DISCOVERY_BATCH": 100,
  "DISCOVERY_INTERVAL": 120,
  "DISCOVERY_PROBE_TRIES": 3,
  "DISCOVERY_TIMEOUT": 2.0,
  "DISCOVERY_MIN_SUCCESS": 0.50,
  "DISCOVERY_MAX_IPS": 200,

  // -- SNI eviction & recycling -------------------------------------------
  "SNI_EVICT_EVERY": 3,
  "SNI_EVICT_COUNT": 1,
  "SNI_RECYCLE_ENABLED": true,
  "SNI_RECYCLE_EVERY": 6,
  "SNI_RECYCLE_BATCH": 2,
  "SNI_RECYCLE_MIN_COOLDOWN": 180,
  "SNI_RECYCLE_MAX_QUARANTINE": 100,
  "SNI_QUARANTINE_SCOPE": "both",

  // -- Dynamic SNI discovery ----------------------------------------------
  "DYNAMIC_SNI_DISCOVERY": true,
  "SNI_DISCOVERY_BATCH": 50,
  "SNI_DISCOVERY_INTERVAL": 120,
  "SNI_SOURCE_REFRESH_INTERVAL": 21600,
  "SNI_DISCOVERY_PROBE_TRIES": 3,
  "SNI_DISCOVERY_TIMEOUT": 2.0,
  "SNI_DISCOVERY_MIN_SUCCESS": 0.50,
  "MAX_DYNAMIC_SNIS": 100,
  "SNI_DISCOVERY_DOMAINS_PER_SOURCE": 5000
}
```

---

## تنظیمات Pool

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `CONNECT_IPS` | `[]` | لیست IP های upstream ثابت |
| `FAKE_SNIS` | `[]` | لیست نام‌های میزبان جعلی |
| `ACTIVE_SLOTS` | `3` | تعداد جفت‌های همزمان فعال |
| `HEALTH_CHECK_INTERVAL` | `30` | ثانیه بین دورهای بررسی |
| `HEALTH_CHECK_TIMEOUT` | `3` | تایم‌اوت TLS handshake هر probe |
| `PROBE_COUNT` | `5` | تعداد probe TLS در هر دور |
| `LOSS_THRESHOLD` | `0.20` | امتیاز loss برای drain کردن جفت |
| `DEAD_THRESHOLD` | `0.80` | امتیاز loss برای مرده اعلام کردن جفت |
| `DRAIN_TIMEOUT` | `30` | ثانیه تا بستن اجباری کانکشن‌های draining |
| `MAX_DRAINING` | `5` | حداکثر جفت‌های همزمان در draining؛ قدیمی‌ترین force-close می‌شود |

**حالت تک‌جفت:** اگر هر دو لیست `CONNECT_IPS`/`FAKE_SNIS` فقط یک عنصر داشته باشند (یا کلیدهای قدیمی `CONNECT_IP`/`FAKE_SNI` استفاده شوند)، pool غیرفعال می‌شود و ابزار در حالت مستقیم بدون سربار کار می‌کند.

---

## امتیازدهی: سلامت یک جفت چطور سنجیده می‌شود؟

هر جفت `(IP, SNI)` با یک **TLS handshake واقعی** probe می‌شود — یک TCP connect ساده کافی نیست.

### ردیابی Loss — میانگین متحرک نمایی

به‌جای یک شمارنده تمام‌عمر، هر جفت یک **EMA (میانگین متحرک نمایی)** از loss نگه می‌دارد:

```
ema_loss_new = alpha x loss_this_event + (1 - alpha) x ema_loss_previous
```

### امتیاز ترکیبی

```
score = 0.60 x combined_loss_rate
      + 0.20 x latency_score
      + 0.20 x probe_loss_rate
```

امتیاز کمتر یعنی بهتر. جفت مرده امتیاز `+inf` می‌گیرد (هرگز انتخاب نمی‌شود). جفتی که هنوز probe نشده امتیاز `0.5` می‌گیرد.

---

## حذف، قرنطینه و بازیافت IP

IP های ضعیف برای همیشه حذف نمی‌شوند — به یک لیست **قرنطینه** منتقل و دوره‌ای دوباره تست می‌شوند.

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `EVICT_EVERY` | `3` | هر چند چرخه یک‌بار eviction اجرا شود |
| `EVICT_COUNT` | `2` | تعداد IP حذف‌شده در هر دور eviction |
| `RECYCLE_ENABLED` | `true` | فعال/غیرفعال کردن مکانیزم بازیافت |
| `RECYCLE_EVERY` | `6` | هر چند چرخه یک‌بار تلاش بازیافت اجرا شود |
| `RECYCLE_BATCH` | `2` | چند IP قرنطینه در هر تلاش دوباره تست شوند |
| `RECYCLE_MIN_COOLDOWN` | `180` | حداقل ثانیه بین دو تلاش روی همان IP |
| `RECYCLE_MAX_QUARANTINE` | `100` | سقف اندازه قرنطینه؛ قدیمی‌ترها برای همیشه حذف می‌شوند |
| `QUARANTINE_SCOPE` | `"both"` | کدام مبدأ IP واجد شرایط است: `"static"`، `"dynamic"` یا `"both"` |

---

## کشف خودکار IP

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `DYNAMIC_IP_DISCOVERY` | `false` | فعال‌سازی کشف خودکار (`true` برای فعال) |
| `DISCOVERY_BATCH` | `100` | تعداد IP نمونه‌گیری‌شده در هر دور |
| `DISCOVERY_INTERVAL` | `120` | ثانیه بین دورهای اسکن |
| `DISCOVERY_PROBE_TRIES` | `3` | تعداد TLS handshake برای هر کاندیدا |
| `DISCOVERY_TIMEOUT` | `2.0` | تایم‌اوت هر TLS handshake (ثانیه) |
| `DISCOVERY_MIN_SUCCESS` | `0.50` | حداقل نرخ موفقیت برای پذیرش IP (۰–۱) |
| `DISCOVERY_MAX_IPS` | `200` | سقف تعداد IPهای داینامیک |

---

## کشف خودکار SNI

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `DYNAMIC_SNI_DISCOVERY` | `false` | فعال‌سازی کشف خودکار SNI (`true` برای فعال) |
| `SNI_DISCOVERY_BATCH` | `50` | تعداد دامنهٔ کاندیدا نمونه‌گیری‌شده در هر دور |
| `SNI_DISCOVERY_INTERVAL` | `120` | ثانیه بین دورهای کشف |
| `SNI_SOURCE_REFRESH_INTERVAL` | `21600` | ثانیه بین دانلود مجدد Tranco/Umbrella/Majestic |
| `SNI_DISCOVERY_PROBE_TRIES` | `3` | تعداد تلاش TLS handshake برای هر کاندیدا |
| `SNI_DISCOVERY_TIMEOUT` | `2.0` | تایم‌اوت هر TLS handshake (ثانیه) |
| `SNI_DISCOVERY_MIN_SUCCESS` | `0.50` | حداقل نرخ موفقیت برای پذیرش SNI (۰–۱) |
| `MAX_DYNAMIC_SNIS` | `100` | سقف تعداد SNIهای داینامیک |
| `SNI_DISCOVERY_DOMAINS_PER_SOURCE` | `5000` | حداکثر دامنه دریافتی از هر منبع رتبه‌بندی |

---

## حذف، قرنطینه و بازیافت SNI

همان چرخهٔ حذف/قرنطینه/بازیافتی که بالاتر برای IP توضیح داده شد، به‌طور مستقل روی SNI هم اعمال می‌شود.

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `SNI_EVICT_EVERY` | `3` | هر چند چرخه یک‌بار ضعیف‌ترین SNI حذف شود |
| `SNI_EVICT_COUNT` | `1` | تعداد SNI حذف‌شده در هر دور eviction |
| `SNI_RECYCLE_ENABLED` | `true` | فعال/غیرفعال کردن بازیافت SNI |
| `SNI_RECYCLE_EVERY` | `6` | هر چند چرخه یک‌بار تلاش بازیافت SNI اجرا شود |
| `SNI_RECYCLE_BATCH` | `2` | چند SNI قرنطینه در هر تلاش دوباره تست شوند |
| `SNI_RECYCLE_MIN_COOLDOWN` | `180` | حداقل ثانیه بین دو تلاش روی همان SNI |
| `SNI_RECYCLE_MAX_QUARANTINE` | `100` | سقف اندازهٔ قرنطینهٔ SNI |
| `SNI_QUARANTINE_SCOPE` | `"both"` | کدام مبدأ SNI واجد شرایط است: `"static"`، `"dynamic"` یا `"both"` |

---

## مود MITM، cipherSuites و finalmask

### رلهٔ MITM (`BYPASS_METHOD: "mitm"`)

`mitm` یک روش دور زدن مثل `direct` / `combined` است — اما به‌جای فوروارد TCP ساده، ابزار **SSL مخصوص خودش را می‌سازد** با استفاده از uTLS درون‌پروسه: session TLS کلاینت را با یک گواهی self-signed خودکار ساخته‌شده خاتمه می‌دهد، سپس یک اتصال TLS *تازه* به upstream واقعی با یک ClientHello کاملاً جدید باز می‌کند.

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `BYPASS_METHOD` | `"fragment"` | `"mitm"` = رلهٔ قطع‌کنندهٔ TLS |
| `MITM_CERT_FILE` / `MITM_KEY_FILE` | `null` | مسیر گواهی/کلید موجود؛ اگر نبود خودکار ساخته می‌شود |
| `MITM_CERT_CN` | `"SNISPF-HJ"` | Common Name گواهی ساخته‌شده |
| `MITM_ALPN` | `["h2", "http/1.1"]` | ALPN پیشنهادشده بالادست وقتی کلاینت ALPN نفرستد |
| `MITM_USE_CLIENT_SNI` | `false` | استفاده از SNI خود کلاینت برای TLS بالادست |
| `FINGERPRINT` | `null` | فینگرپرینت مرورگر: `chrome`، `firefox`، `safari`، `ios`، `android`، `edge`، `360`، `qq`، `random`، `randomized`، `randomizednoalpn`، `unsafe` |

### `FINGERPRINT` — اثر انگشت TLS مرورگر (JA3/JA4)

در پورت Go، هندشیک TLS بالادست **مستقیماً در Go** با استفاده از [uTLS](https://github.com/refraction-networking/utls) اجرا می‌شود. نیازی به باینری سایدکار خارجی نیست.

| `FINGERPRINT` | preset ی uTLS | توضیح |
| --- | --- | --- |
| `chrome` | `HelloChrome_Auto` (Chrome 133) | پیش‌فرض |
| `firefox` | `HelloFirefox_Auto` (Firefox 120) | |
| `safari` | `HelloSafari_Auto` (Safari 16.0) | |
| `ios` | `HelloIOS_Auto` (iOS 14) | |
| `android` | `HelloAndroid_11_OkHttp` | |
| `edge` | `HelloEdge_Auto` (Edge/Chromium 85) | |
| `360` | `Hello360_Auto` (Qihoo 360 7.5) | |
| `qq` | `HelloQQ_Auto` (QQ 11.1) | |
| `random` | انتخاب تصادفی از موارد بالا | |
| `randomized` | `HelloRandomizedALPN` | hello ی تصادفی در هر اتصال |
| `randomizednoalpn` | `HelloRandomizedNoALPN` | بدون افزونه ALPN |
| `unsafe` | `HelloGolang` | Go ی استاندارد |

### `CIPHER_SUITES`

کدام‌سوئیت‌های TLS برای ClientHello بالادست، در قالب xray:

```
"CIPHER_SUITES": "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### `FINALMASK_TCP` — قطعه‌بندی TCP به سبک finalmask

`null` برای غیرفعال‌سازی، یا یک آرایهٔ JSON از قوانین `fragment`:

```json
"FINALMASK_TCP": [
  { "type": "fragment", "settings": { "packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0" } },
  { "type": "fragment", "settings": { "packets": "1-1",      "lengths": ["109", "1"],    "delays": ["1"], "maxSplit": "355" } }
]
```

---

## پرچم‌های CLI

```
--config, -C FILE         مسیر فایل کانفیگ JSON
--generate-config PATH    ساخت کانفیگ پیش‌فرض و خروج
--listen, -l HOST:PORT     آدرس گوش‌دادن (پیش‌فرض: 0.0.0.0:40443)
--connect, -c IP:PORT      آدرس سرور مقصد (حالت تک‌جفت)
--sni,    -s HOSTNAME      نام میزبان جعلی (حالت تک‌جفت)
--method, -m METHOD        direct | fragment | fake_sni | combined | mitm
--cipher-suites LIST       کدام‌سوئیت‌های TLS بالادست
--fingerprint PROFILE      اثر انگشت TLS مرورگر
--fragment-strategy STR    sni_split | half | multi | tls_record_frag
--fragment-delay  SEC      فاصله بین قطعات (ثانیه)
--no-raw                   غیرفعال‌سازی raw socket
--check-domains FILE       بررسی گروهی دامنه‌ها برای Cloudflare
--check-workers N          تعداد ورکر موازی (پیش‌فرض: ۵۰)
--check-timeout SEC        تایم‌اوت هر دامنه (پیش‌فرض: ۳ ثانیه)
--output FILE              ذخیرهٔ دامنه‌های تأییدشده
--check-http                تأیید HTTP هم در حین بررسی دامنه
--verbose, -v               لاگ کامل (debug)
--quiet,   -q               فقط هشدارها
--version, -V               نمایش نسخه و خروج
--info                      نمایش قابلیت‌های سیستم و خروج
```

---

## روش‌های دور زدن

| روش | نحوه کار | نیاز به دسترسی |
|---|---|---|
| `fragment` | شکستن ClientHello در مرز SNI به چند بخش TCP | هیچ |
| `fake_sni` | ارسال ClientHello جعلی قبل از واقعی | root برای raw socket؛ بدون آن fragmentation |
| `combined` | هر دو همزمان — توصیه‌شده | مثل fake_sni |

---

## استراتژی‌های قطعه‌بندی

| استراتژی | کار |
|---|---|
| `sni_split` (پیش‌فرض) | شکستن دقیقاً روی هاست‌نیم SNI |
| `half` | دو نیمهٔ تقریباً مساوی |
| `multi` | چند قطعهٔ ۵–۱۰ بایتی |
| `tls_record_frag` | شکستن در لایهٔ رکورد TLS |

---

## بررسی‌گر دامنه

```bash
snispf.exe --check-domains domains.txt
snispf.exe --check-domains domains.txt --output verified.txt --check-http -v
```

---

## پشتیبانی از پلتفرم‌ها

| پلتفرم | وضعیت | یادداشت |
|---|---|---|
| Linux | کامل | raw socket با `sudo` یا `CAP_NET_RAW` |
| macOS | کامل | fragmentation + fake-SNI |
| Windows 10 / 11 | کامل | fragment/combined |
| Android روی Termux | پشتیبانی | بدون root؛ fragmentation + fake-SNI |

برای دیدن قابلیت‌های دقیق سیستم: `snispf.exe --info`

---

## رفع اشکال

**پورت اشغال است**
```bash
snispf.exe --listen :40444 --config config.json
```

**Pool همهٔ جفت‌ها را dead نشان می‌دهد**
- مطمئن شو `CONNECT_IPS` روی پورت ۴۴۳ یک TLS handshake واقعی را قبول می‌کنند.
- `HEALTH_CHECK_TIMEOUT` را به `6` افزایش بده.
- `DEAD_THRESHOLD` را به `0.90` افزایش بده.

**کانکشن‌ها به‌طور غیرمنتظره بسته می‌شوند**
- احتمالاً `DRAIN_TIMEOUT` فعال شده — مقدار را بیشتر کن: `"DRAIN_TIMEOUT": 60`

**Discovery هیچ IP ای پیدا نمی‌کند**
- `DISCOVERY_TIMEOUT` را افزایش بده: `4.0`
- آستانه را شل‌تر کن: `"DISCOVERY_MIN_SUCCESS": 0.34`

---

## ساختار پروژه

```
SNISPF-HJ-GO/
├── main.go                     # نقطهٔ ورود (go build -o snispf.exe .)
├── config.json                 # کانفیگ پیش‌فرض
├── go.mod / go.sum             # فایل‌های ماژول Go
├── build.bat / build.sh        # اسکریپت‌های کامپایل آفلاین
├── README.md / README_FA.md
└── internal/
    ├── certs/                  # ساخت گواهی self-signed + اثر انگشت SHA-256
    ├── config/                  # بارگذارندهٔ کانفیگ (JSON، getters تایپ‌شده)
    ├── discovery/               # کشف خودکار IP + SNI + CIDR های Cloudflare
    ├── finalmask/               # قطعه‌بندی TCP finalmask در xray (پورت وفادار)
    ├── forward/                 # فوروردر TCP + استراتژی‌های bypass + raw injection
    ├── mitm/                    # رلهٔ MITM (هندشیک uTLS درون‌پروسه)
    ├── pool/                    # PairStats، CombinationExplorer، ActivePool
    ├── scanner/                 # بررسی گروهی دامنه‌های Cloudflare
    ├── tlsutil/                 # سازندهٔ ClientHello + تجزیه‌گر + resolver فینگرپرینت
    └── utils/                   # تشخیص پلتفرم، کمک‌های IP/port
```

---

## تشکر و منابع

- **[@Rainman69](https://github.com/Rainman69)** — معماری اصلی SNISPF
- **[@patterniha](https://github.com/patterniha)** — ایدهٔ اولیهٔ SNI spoofing
- **[@hjfisher](https://github.com/hjfisher)** — pool، discovery، امتیازدهی EMA، پورت Go
- **[@bia-pain-bache](https://github.com/bia-pain-bache)** — روش اسکن IP Cloudflare
- **[@refraction-networking](https://github.com/refraction-networking)** — کتابخانه uTLS

---

## لایسنس

[MIT](LICENSE) © Rainman69, hjfisher
