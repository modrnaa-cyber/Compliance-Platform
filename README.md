# 🛡️ Compliance Platform

Automated cybersecurity compliance assessment and risk management platform. Runs multi-engine security scans (Nmap, OpenVAS, WhatWeb, testssl.sh) and maps findings directly to NCA ECC 2-2024 controls.

🚧 **Status:** Under active development

## Screenshots

<img width="721" height="1184" alt="image" src="https://github.com/user-attachments/assets/af3f5322-0fbb-43b3-aabc-7f1502111be4" />

![Assessment Service]
<img width="274" height="479" alt="image" src="https://github.com/user-attachments/assets/1c95c34a-c15c-4df9-86e9-25a7216788c2" />

<img width="978" height="611" alt="image" src="https://github.com/user-attachments/assets/7615cb15-6155-42e5-aa05-21f6efe5a46c" />


<img width="986" height="602" alt="image" src="https://github.com/user-attachments/assets/ca34c67a-4d7a-4871-9234-45bdbc7148dd" />
<img width="975" height="410" alt="image" src="https://github.com/user-attachments/assets/ec4004fa-95e7-4dec-8c84-b7efaf460103" />
<img width="749" height="119" alt="image" src="https://github.com/user-attachments/assets/7ca48c90-fba7-4ff6-9809-7dac0e3c74dc" />

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
