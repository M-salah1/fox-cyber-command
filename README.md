# 🦊 FOX CYBER COMMAND v1.00

**مركز قيادة سيبراني دفاعي موحّد — Red Team + Blue Team — لهاتفك (Termux)**

Developer: **Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY**

> أداة واحدة تجمع **36 أداة أخلاقية** في 9 فرق، وتشغّلها معاً على الهاتف
> حيثما أمكن — **بصدق**: الأداة الغائبة تُبلَّغ غائبة مع أمر تثبيتها،
> وأدوات الحاسوب فقط لا يُدَّعى أنها تعمل على الهاتف أبداً، بل لكلٍّ
> منها بديل مدمج يعمل فعلاً على Termux.
>
> One unified defensive command centre: 36 ethical tools, 9 teams,
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
python3 foxcc.py --doctor     # فحص البيئة وكل الأدوات الـ 36
python3 foxcc.py              # وحدة التحكم: foxcc >
```

داخل وحدة التحكم:

```text
foxcc > scope create https://example.com
foxcc > mission https://example.com
foxcc > report list
foxcc > evidence show 1 F-001
foxcc > coverage 1
```

النواة **stdlib فقط** — لا `pip install` مطلوب لتشغيلها.

## 🧰 الفرق التسعة (36 أداة)

| الفريق | الأدوات |
|---|---|
| Recon — الاستطلاع | Subfinder, Amass, theHarvester, SpiderFoot |
| Network — الشبكات | Nmap, RustScan, Wireshark, NetExec |
| Web — أمن الويب | Burp Suite, OWASP ZAP, Nuclei, Nikto |
| Password — كلمات المرور (مختبر فقط) | John the Ripper, Hashcat, KeePassXC |
| Lab — المختبرات | Metasploit, BloodHound CE, OpenVAS |
| Mobile — التطبيقات | MobSF, JADX, Ghidra, Frida |
| Cloud & Code — السحابة والكود | Prowler, ScoutSuite, Trivy, Semgrep, Checkov |
| Blue — الدفاع والتحقيق | Autopsy, Volatility 3, YARA, Wazuh, Suricata, Zeek |
| OS — أنظمة التشغيل (معلومات) | Kali Linux, Parrot Security OS, Kali NetHunter |

## 📊 مصفوفة Termux الصادقة

| الحالة | العدد | المعنى |
|---|---|---|
| مدعوم على Termux | 10 | يعمل بـ pkg / go / pip على الهاتف |
| جزئي على Termux | 10 | يعمل جزئياً: headless فقط، CPU فقط، يحتاج root، يحتاج مفاتيح سحابية منك، أو ثقيل |
| حاسوب/Kali فقط | 13 | واجهة رسومية / خادم / Neo4j / بطاقة شبكة — **لا يعمل على الهاتف أبداً**، ولكلٍّ بديل مدمج + تعليمات تثبيت الحاسوب |
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
report list | report generate <id>
evidence show <scan> <F-001> | coverage <id> | history | clear | exit
```

## 📁 البنية

```text
foxcc.py                  # الدخول + وحدة التحكم (foxcc >)
foxcc/__init__.py         # الإصدار 1.00
foxcc/core/               # scope, store, evidence, scoring, registry,
                          # doctor, adapters, report
foxcc/engines/            # dns, tls, http, ports, waf, apk, forensics
foxcc/teams/              # recon, web, network, mobile, cloud, blue,
                          # mission
tests/test_foxcc.py       # اختبارات unittest (stdlib فقط)
reports/                  # JSON + HTML لكل فحص
foxcc.db                  # SQLite: scopes / projects / teams / scans /
                          # findings / evidence_bundles
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
git commit -m "FOX CYBER COMMAND v1.00 — defensive command centre (36 tools)"
git branch -M main
git remote add origin https://github.com/M-salah1/fox-cyber-command.git
git push -u origin main
```

## 🌍 English / Français (short)

**English:** FOX CYBER COMMAND v1.00 is a defensive, authorized-only
ethical-hacking command centre for Termux: 36 tools in 9 teams, signed
HMAC scope mandatory before any scan, honest per-tool Termux status
(10 supported / 10 partial / 13 PC-only / 3 info-only), built-in
stdlib fallbacks, evidence bundles (redacted), and four separate
metrics (score / confidence / coverage / verification rate).
No exploitation payloads, no brute force, no credential values —
ever. Stdlib only, no pip needed for the core.

**Français :** FOX CYBER COMMAND v1.00 est un centre de commande
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
