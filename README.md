# 🛡️ Compliance Platform

Automated cybersecurity compliance assessment and risk management platform. Runs multi-engine security scans (Nmap, OpenVAS, WhatWeb, testssl.sh) and maps findings directly to NCA ECC 2-2024 controls.

🚧 **Status:** Under active development

## Screenshots

![Dashboard](اسم_صورة_الواجهة.jpg)

![Assessment Service](اسم_صورة_الخدمات.jpg)

## Features

- Multi-engine scanning: Nmap, OpenVAS, WhatWeb, testssl.sh
- Automated mapping of scan results to NCA ECC compliance controls
- Risk scoring and remediation suggestions
- Exportable compliance reports

## Tech Stack

Python · Flask · REST APIs · Nmap · OpenVAS · HTML/CSS/JS

## Installation

\`\`\`bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
\`\`\`

## Usage

1. Enter a target domain or IP address
2. Select an assessment service (e.g. Nmap Standard Scan)
3. Click "Run Assessment"
4. Review results and export a compliance report

---

<div dir="rtl">

# 🛡️ منصة الامتثال (Compliance Platform)

منصة آلية لتقييم الامتثال الأمني وإدارة المخاطر السيبرانية. تشغّل فحوصات أمنية متعددة (Nmap، OpenVAS، WhatWeb، testssl.sh) وتربط النتائج مباشرة بضوابط الهيئة الوطنية للأمن السيبراني (NCA ECC 2-2024).

🚧 **الحالة:** المشروع تحت التطوير

## لقطات من الواجهة

![خدمات الفحص]
<img width="274" height="479" alt="image" src="https://github.com/user-attachments/assets/35930679-d450-4ead-93d1-181a66abdc1d" />

## المزايا

- فحص متعدد المحركات: Nmap، OpenVAS، WhatWeb، testssl.sh
- ربط تلقائي بين نتائج الفحص وضوابط الامتثال (NCA ECC)
- تقييم درجة الخطورة وتقديم مقترحات إصلاح
- تصدير تقارير امتثال جاهزة

## أدوات البناء

Python · Flask · REST APIs · Nmap · OpenVAS · HTML/CSS/JS

## طريقة التشغيل

</div>

\`\`\`bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
\`\`\`

<div dir="rtl">

## طريقة الاستخدام

1. أدخل الدومين أو عنوان IP المستهدف
2. اختر نوع الفحص (مثل Nmap Standard Scan)
3. اضغط "Run Assessment"
4. راجع النتائج وصدّر تقرير الامتثال

</div>
