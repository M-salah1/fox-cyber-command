# 🦊 FOX CYBER COMMAND v2.01

**مركز قيادة سيبراني دفاعي موحّد — Red Team + Blue Team — لهاتفك (Termux)**

Developer: **Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY**

> أداة واحدة تجمع **45 أداة أخلاقية** في 11 فريقاً، وتشغّلها معاً على الهاتف
> حيثما أمكن — **بصدق**: الأداة الغائبة تُبلَّغ غائبة مع أمر تثبيتها،
> وأدوات الحاسوب فقط لا يُدَّعى أنها تعمل على الهاتف أبداً، بل لكلٍّ
> منها بديل مدمج يعمل فعلاً على Termux.
>
> One unified defensive command centre: 45 ethical tools, 11 teams,
> honest Termux status for each, built-in fallbacks that really run
> on the phone. No invented results — ever.

---

## ⚠️ القاعدة الأولى — النطاق الموقّع (إلزامي)

**لا فحص بلا نطاق موقّع.** كل فحص يتطلب نطاقاً موقّعاً HMAC-SHA256
للأداة نفسها: موقعك أنت، أو هدف لديك **تصريح مكتوب** لفحصه.

```text
foxcc > scope create https://example.com
foxcc > scope verify
foxcc > mission https://example.com
```

بدون نطاق نشط صالح، تُرفَض الأوامر `recon / web / network / mobile /
cloud / blue / forensics / mission` برسالة `BLOCKED`.

## 🚫 حدود دفاعية (لا تُكسَر)

- لا حمولات استغلال (SQLi / XSS / CSRF / SSRF / IDOR)، لا تخمين كلمات
  مرور (brute force)، لا تجاوز تسجيل دخول، لا جمع بيانات اعتماد.
- **لا تُجمَع ولا تُعرَض قيم كلمات المرور أو كوكيز الجلسة أبداً.**
  الكوكيز بالاسم والأعلام والسياق فقط.
- تدقيق كلمات المرور بوضع التحقق فقط: قيمة يقدّمها المالك عبر
  `getpass`، والنتيجة YES/NO + قوة فقط — لا تُحفَظ ولا تُسجَّل.
- تحليل APK لتطبيقاتك أنت أو لتطبيق مختبر فقط، وتحت نطاق موقّع.
- لا نتائج مختلقة: الأداة الغائبة تُبلَّغ غائبة.

## 🚀 التشغيل على Termux

```bash
pkg update && pkg install python git
git clone https://github.com/M-salah1/fox-cyber-command.git
cd fox-cyber-command
python3 foxcc.py --doctor     # فحص البيئة وكل الأدوات الـ 45
python3 foxcc.py --simple     # الوضع البسيط: 3 أوامر فقط
```

## 🟢 الوضع البسيط — Simple Mode (الجديد في v2.01)

**أداة عادية تعمل دون عناء.** 3 أوامر فقط تحتاجها:

```text
foxcc > go https://example.com      # فحص كامل بكل الطبقات (أمر واحد)
foxcc > check https://example.com   # فحص سريع (~30 ثانية)
foxcc > report list                 # قائمة التقارير
```

- `go` هو نفسه `run` وهو نفسه `mission` — كلها تشغّل الطبقات السبع
  بالترتيب: Recon ← Web ← Network ← Secrets ← OSINT ← Vulnerability
  ← Blue/Forensics، ثم ملخص المحلل المحلي ونقاط المخاطر.
- إن لم يوجد نطاق موقّع للهدف، **سؤال واحد قصير فقط**:
  `هذا الهدف لك أو لديك تصريح بفحصه؟ [y/N]` — وعند الموافقة يُنشأ
  النطاق تلقائياً ويستمر الفحص. عند الرفض يُحظَر الفحص.
- كل طبقة تطبع سطراً واحداً: اسمها، حالتها (ok / partial / failed)،
  وعدد نتائجها. أداة خارجية مفقودة لا توقف الفحص أبداً — المحرك
  المدمج يغطيها والسطر يقول ذلك بصراحة.
- في النهاية ملخص من شاشة واحدة: النقاط + الدرجة، والثقة/التغطية/
  نسبة التحقق كأربعة أرقام منفصلة، وأعداد الخطورة، وأهم 5 نتائج
  مع إصلاح لكل منها، والأدوات التي عملت مقابل الفاشلة/المفقودة —
  ويُنشأ تقرير JSON + HTML + PDF حقيقي تلقائياً في `reports/`.
- الحارس الوحيد هو النطاق الموقّع الواحد. بلا قضايا، بلا تفويض
  قانوني، بلا موافقات مشرف، بلا أدوار.
- `mode simple | mode full` للتبديل بين الوضعين داخل وحدة التحكم.
  في الوضع البسيط تعرض `help` الأوامر العشرة فقط؛ الأوامر المتقدمة
  ما زالت تعمل لكنها غير مدرجة.

> Simple Mode: one command (`go <target>`) runs all layers, one
> confirmation line auto-creates the scope, one screen summarises
> everything. / Mode simple : une seule commande lance toutes les
> couches, une confirmation crée le périmètre, un écran résume tout.

داخل وحدة التحكم (الوضع الكامل):

```text
foxcc > scope create https://example.com
foxcc > mission https://example.com
foxcc > report list
foxcc > evidence show 1 F-001
foxcc > coverage 1
```

النواة **stdlib فقط** — لا `pip install` مطلوب لتشغيلها.

## 🧰 الفرق (45 أداة)

| الفريق | الأدوات |
|---|---|
| Recon — الاستطلاع | Subfinder, Amass, theHarvester, SpiderFoot |
| Network — الشبكات | Nmap, RustScan, Wireshark, NetExec |
| Web — أمن الويب | Burp Suite, OWASP ZAP, Nuclei, Nikto |
| Password — كلمات المرور (مختبر فقط) | John the Ripper, Hashcat, KeePassXC |
| Lab — المختبرات | Metasploit, BloodHound CE, OpenVAS, Sliver |
| Mobile — التطبيقات | MobSF, JADX, Ghidra, Frida |
| Cloud & Code — السحابة والكود | Prowler, ScoutSuite, Trivy, Semgrep, Checkov |
| Blue — الدفاع والتحقيق | Autopsy, Volatility 3, YARA, Wazuh, Suricata, Zeek, OSSEC, Sleuth Kit, hashdeep |
| Secret Hunter — صيد الأسرار | TruffleHog, Gitleaks, detect-secrets |
| OSINT — الاستخبارات المفتوحة | Sherlock, Maigret |
| OS — أنظمة التشغيل (معلومات) | Kali Linux, Parrot Security OS, Kali NetHunter |

## 📊 مصفوفة Termux الصادقة

| الحالة | العدد | المعنى |
|---|---|---|
| مدعوم على Termux | 15 | يعمل بـ pkg / go / pip على الهاتف |
| جزئي على Termux | 12 | يعمل جزئياً: headless فقط، CPU فقط، يحتاج root، يحتاج مفاتيح سحابية منك، أو ثقيل |
| حاسوب/Kali فقط | 15 | واجهة رسومية / خادم / Neo4j / بطاقة شبكة — **لا يعمل على الهاتف أبداً**، ولكلٍّ بديل مدمج + تعليمات تثبيت الحاسوب |
| معلومات فقط | 3 | أنظمة تشغيل (Kali / Parrot / NetHunter)، ليست أدوات |

تحقق بنفسك: `foxcc > doctor` يفحص كل ثنائية بـ `shutil.which`
ولا يدّعي تثبيت أي أداة دون فحص حقيقي.

## 🎯 الأمر الواحد: `mission`

```text
foxcc > mission https://example.com
```

يشغّل Recon + Web + Network + Blue تحت النطاق نفسه، يدمج النتائج
(إزالة تكرار حسب `finding_key`)، ويرفق حزمة دليل لكل نتيجة
(طلب + رد مُحجَّبان)، ويحسب **أربعة أرقام منفصلة**:

- **Score** — النقاط (100 ناقص أوزان النتائج المؤكدة/المشتبهة)
- **Confidence** — الثقة (نسبة النتائج المعاد تأكيدها)
- **Coverage** — التغطية (المحركات التي عملت فعلاً / المخطط لها)
- **Verification rate** — نسبة التحقق

المنافذ بمستويين (من WEBDON v5.1): `tcp_open` (معلومة فقط، لا تُحتسَب)
مقابل `service_confirmed` (بانر/بروتوكول مؤكد).


## 🆕 الجديد في v2.01 — الوضع البسيط (Simple Mode)

- **`go` / `run` / `mission`** — نفس الفحص الكامل، بكل الطبقات السبع.
- **`check <target>`** — فحص سريع: DNS + HTTP + TLS + WAF + منافذ.
- **سؤال تصريح واحد** ينشئ النطاق تلقائياً عند الموافقة؛ الرفض يحظر.
- **سطر تقدّم لكل طبقة** (ok / partial / failed + عدد النتائج)، وملخص
  نهائي من شاشة واحدة (أهم 5 نتائج مع إصلاح + تقرير PDF تلقائي).
- **`mode simple | mode full`** و `foxcc.py --simple` للتبديل.
- الاختبارات: 233/233 (208 من v2.00 + 25 جديدة للوضع البسيط).

## 🆕 الجديد في v2.00

- **AuthorizationGuard** — النطاق الموقّع + سجل موافقة موثّق (`consent_ref`/`consent_text`) + انتهاء صلاحية؛ HMAC يحمي سلامة السجل فقط ولا يثبت الموافقة.
- **Plugin Manager** — حالة حية لكل أداة (فحص ثنائية حقيقي؛ الغائبة لا تُبلَّغ مثبّتة أبداً) + `PLUGIN_STATUS`.
- **Execution Engine** — تشغيل آمن (list-args فقط، بلا `shell=True`)، قائمة عمليات من `/proc`، تتبّع مهام.
- **Audit Logger** — سجل تدقيق بسلسلة تجزئة SHA-256 وكشف التلاعب (`verify_chain`).
- **Risk Engine** — مخاطر صادقة: الأدوات الفاشلة تخفض التغطية (سقف 90٪) ولا ترفعها أبداً، والثقة لا تصل 100٪ بلا دليل موثّق.
- **AI Analyst (محلي)** — محلل قواعدي محلي فقط، ليس LLM ولا شبكة؛ يجيب من قاعدة البيانات المحلية فقط.
- **Local API** — REST + JSON-RPC على `127.0.0.1:8765` فقط، برمز `X-FOXCC-Token` (ملف `.foxcc_api_token` بصلاحية 0600)، وكتابة المهام محمية بالنطاق (403 خارج النطاق). راجع `docs/API.md`.
- **Platform detection** — كشف Termux/Windows/WSL/Docker وحدود صادقة لكل منصة.
- **تقارير CSV + PDF حقيقي** (كاتب PDF بـ stdlib — ليس HTML باسم pdf)، وحقول v2 في التقارير (mission_id, authorization_ref, risk_score...).
- **Secrets store** — أسرار محجّبة فقط (أول 4 + `**************` + آخر 4 + SHA-256)؛ القيمة الكاملة لا تُحفَظ ولا تُعرَض أبداً.
- **Update Manager** — فحص فقط، لا تثبيت تلقائي ولا تنزيل، والتحقق SHA-256 للملفات.

## 🆕 الجديد في v2.00 — المرحلة 2 (Phase 2)

### 🔴 Red Team — مختبر فقط (lab only)

Sliver وMetasploit **حاسوب/خادم مختبر فقط** — لا يعملان على Termux
أبداً. الوحدة `foxcc/teams/redteam.py` تبلّغ حالتهما بصدق
(`sliver_status()` / `metasploit_status()`: مثبّت/غائب + الإصدار
عبر `--version`) وتشرح كيف تصل الهاتف بخادم Linux مختبر
(`sliver-server` و`msfrpcd` على المختبر). جلسات المختبر تُسرد
فقط من خادم مختبر تشغّله أنت؛ بلا خادم تكون القائمة فارغة مع
ملاحظة صريحة. نطاق مختبر إلزامي (`127.0.0.1` أو CIDR المختبر
داخل النطاق الموقّع)، وإنهاء جلسة يرفض بلا تأكيد بشري صريح
(`confirm=True`). لا سرقة بيانات، لا انتشار تلقائي، لا ثبات،
لا تجاوز حماية، لا استغلال تلقائي، لا توليد حمولات — نتائج
`redteam` معلوماتية فقط عن حالة المختبر، وليست نتائج استغلال.

```text
foxcc > scope create 127.0.0.1
foxcc > redteam https://example.com
foxcc > lab info
```

### 🔍 Vulnerability Scanner — فحص سلبي فقط

`foxcc/teams/vuln.py` يعيد استخدام محركات HTTP/TLS/WAF المدمجة
( GET/HEAD حميدة فقط) ويبلّغ حالة Nuclei / Nikto / ZAP /
Semgrep / Trivy / Checkov / Prowler بصدق. قائمة برامج منتهية
الدعم (EOL) مضمّنة صغيرة فقط (Apache/2.2, PHP/5.6, OpenSSL/1.0.1
…). **لا تُختلَق معرّفات CVE أبداً**: أي CVE ليس في القائمة
المضمّنة يُبلَّغ «CVE lookup needs a user-provided NVD key —
not checked». كل نتيجة تحمل إصلاحاً. لا استغلال تلقائي.

```text
foxcc > vuln https://example.com
```

### 🗺️ Network Intelligence — طوبولوجيا واكتشاف خدمات

`network.topology(target, scopes)` يبني عقداً (المضيف + النطاقات
الفرعية + الخدمات المكتشفة) وحوافّ موسومة بالدليل
(`dns` / `tcp_open` / `service_confirmed`) — عقد مراقَبة فقط،
لا عقد مختلقة. و`network.service_discovery()` يعيد استخدام محرك
المنافذ المدمج + محوّل Nmap عند وجوده (غائب ← بديل مدمج موسوم).

```text
foxcc > topology https://example.com
foxcc > services https://example.com
```

### 📊 Dashboard — لوحة قيادة HTML

`foxcc/core/dashboard.py` يولّد `reports/dashboard.html` من
بيانات قاعدة البيانات الحقيقية فقط (فحوصات، مهام، أسرار محجّبة،
حوادث، نطاقات، سجل الأدوات، ملخص doctor) — **بلا بيانات تجريبية**:
قاعدة فارغة تعني «no missions yet — run scope create + mission».
13 قسماً: Dashboard, New Mission, Red Team, Blue Team, Secret
Hunter, OSINT, Vulnerability Scanner, Network Intelligence,
Digital Forensics, Plugin Manager, AI Analyst, Reports,
Authorization Center. ألوان: أسود `#000000`، غرافيت `#111827`،
برتقالي FOX `#f59e0b`، أحمر `#dc2626`، أزرق `#2563eb`؛ شعار
ثعلب نصي 🦊 بلا صور؛ عربي RTL + إنجليزي. كل زر/رابط يشير إلى
ملف تقرير حقيقي أو أمر حقيقي، أو يُوسَم «غير متاح» مع السبب
(مثلاً «Sliver — PC/lab only»).

```text
foxcc > dashboard
```

### 🎯 `mission` الموسَّعة

تشمل الآن أيضاً OSINT + Vuln + Red Team (حالة مختبر فقط) +
فحص أسرار لأصل ويب (`/main.js` داخل النطاق؛ فشل الشبكة = صف
تغطية «failed» لا انهيار). المحركات المخطط لها صارت 20
(`osint`, `vuln`, `redteam`, `secrets-web` مضافة)، والتغطية
تبقى ≤ 100٪، وإزالة التكرار تشمل الأسرار حسب SHA-256.

### 🧪 اختبارات المرحلة 2

`tests/test_foxcc_v2.py` — 61 اختباراً تغطي 16 معيار قبول:
doctor/mission بلا أدوات إضافية، كشف التثبيت، أداة غائبة،
TruffleHog/Gitleaks على مستودع اصطناعي مملوك، كشف الأسرار
الاصطناعية، الحجب في كل المخرجات، رفض خارج النطاق، مختبر
Sliver/Metasploit وهمي (mock) موسوم، Nmap على 127.0.0.1،
تقارير HTML+JSON+CSV+PDF حقيقي، سجل التدقيق وسلسلة التجزئة
وكشف التلاعب، انقطاع الاتصال، فشل الأدوات، سلامة الأدلة،
إضافة إلى لوحة القيادة بلا بيانات تجريبية، سقوف محرك المخاطر،
محلل AI من قاعدة البيانات فقط، رفض النطاق المنتهي، وصدق مدير
الإضافات. المجموع الكلي: **208 اختبارات** (v1 ‏70 + core v2 ‏36
+ secrets v2 ‏41 + phase 2 ‏61) — كلها خضراء.

## 📋 الأوامر

```text
help, about, doctor, env
tools [team] | tool <id> | install <id> | status
project create <name> | project list | project use <id>
team create <name> [kind] | team list
scope create <target> | scope list | scope use <id> | scope verify
recon <target> | web <target> | network <target>
mobile <apk> | cloud <path> | blue <target> | forensics <file> [rules]
mission <target> | password verify
redteam <target> | vuln <target> | osint <target>
topology <target> | services <target> | lab info | dashboard | ask <question>
secrets scan <path> | secrets repo <path> | secrets web <url>
plugins | plugin <id> | audit list | audit verify | risk <scan-id>
auth create <target> [type] [owner] [consent] | auth show
api token | api serve [port]
report list | report generate <id>
evidence show <scan> <F-001> | coverage <id> | history | clear | exit
```

أوامر سطر الأوامر (غير التفاعلية):

```bash
python3 foxcc.py --version
python3 foxcc.py --doctor            # فحص البيئة والأدوات
python3 foxcc.py --doctor --json     # نفس الفحص بمخرجات JSON منظمة
python3 foxcc.py --dashboard         # توليد لوحة القيادة HTML والخروج
```

> ملاحظة تكامل: أمر `api serve` كان في v2.00 الأولى يعود فوراً
> دون تشغيل الخادم (الدالة `run_api_server` تعيد كائن الخادم
> والمتصل يشغّل `serve_forever`)؛ أُصلح في التكامل النهائي
> فصار `api serve` يخدم فعلياً حتى Ctrl+C.

## 📁 البنية

```text
foxcc.py                  # الدخول + وحدة التحكم (foxcc >)
foxcc/__init__.py         # الإصدار 2.00
foxcc/core/               # scope, guard, store, evidence, scoring,
                          # registry, doctor, adapters, report,
                          # plugin_manager, execution, audit, risk,
                          # ai_analyst, api, platform, update_manager
foxcc/engines/            # dns, tls, http, ports, waf, apk, forensics, secrets
foxcc/secrets/            # قواعد + محولات TruffleHog/Gitleaks/detect-secrets
foxcc/teams/              # recon, web, network, mobile, cloud, blue,
                          # mission, osint, redteam, vuln
tests/test_foxcc.py       # اختبارات v1 (unittest, stdlib فقط)
tests/test_core_v2.py     # اختبارات v2 للوحدات الجديدة
tests/test_secrets_v2.py  # اختبارات Secret Hunter (41)
tests/test_foxcc_v2.py    # اختبارات معايير القبول الـ 16 (61)
reports/                  # JSON + HTML + CSV + PDF لكل فحص + dashboard.html
plugins/                  # قالب إضافة (example_plugin.py)
foxcc.db                  # SQLite: scopes / projects / teams / scans /
                          # findings / evidence_bundles / secrets /
                          # audit_log / auth_evidence / incidents / missions
```

## 🧪 الاختبارات

```bash
python3 -m unittest discover -s tests -v
```

كل الاختبارات دون اتصال خارجي (خادم محلي 127.0.0.1 داخل الاختبار).

## 🐙 GitHub (أنشئ المستودع يدوياً أولاً)

تطبيق Muse GitHub لا يستطيع إنشاء مستودعات (403)، فأنشئ المستودع
بنفسك ثم:

```bash
cd fox-cyber-command
git init
git add .
git commit -m "FOX CYBER COMMAND v2.00 — defensive command centre (45 tools)"
git branch -M main
git remote add origin https://github.com/M-salah1/fox-cyber-command.git
git push -u origin main
```

## 🌍 English / Français (short)

**English:** FOX CYBER COMMAND v2.00 is a defensive, authorized-only
ethical-hacking command centre for Termux: 36 tools in 9 teams, signed
HMAC scope mandatory before any scan, honest per-tool Termux status
(10 supported / 10 partial / 13 PC-only / 3 info-only), built-in
stdlib fallbacks, evidence bundles (redacted), and four separate
metrics (score / confidence / coverage / verification rate).
No exploitation payloads, no brute force, no credential values —
ever. Stdlib only, no pip needed for the core.

**Français :** FOX CYBER COMMAND v2.00 est un centre de commande
défensif, autorisé uniquement, pour Termux : 36 outils en 9 équipes,
portée signée HMAC obligatoire avant tout scan, statut Termux honnête
par outil (10 supportés / 10 partiels / 13 PC uniquement / 3 infos),
repli intégrés en stdlib, preuves caviardées, et quatre métriques
séparées (score / confiance / couverture / taux de vérification).
Aucun payload d'exploitation, aucune force brute, aucune valeur
d'identifiant — jamais. Stdlib uniquement, aucun pip requis.

---

*FOX COMPANY — Hafed Mehdi Salah Eddine — Algeria — 2026.*
*دفاعي ومصرّح فقط — Defensive & authorized only.*
