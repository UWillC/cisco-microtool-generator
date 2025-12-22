# Cisco Micro-Tool Generator

A **micro-SaaS–oriented backend + Web UI** for generating **secure Cisco IOS / IOS XE configurations**
and performing **lightweight security analysis** (CVE awareness).

This project is built publicly as an engineering-focused product prototype, with emphasis on:
- secure-by-default configuration patterns,
- repeatability via profiles,
- clean API design (FastAPI),
- and gradual evolution toward a SaaS-style architecture.

> ⚠️ **Disclaimer**  
> CVE data included in this project is **demo / curated only** and must not be treated as a production security authority.
> Always consult official Cisco advisories for real-world decisions.

---

## 🚀 Why this project exists

As network engineers, we often:
- copy-paste configuration snippets from old devices,
- re-type the same secure baselines again and again,
- rely on ad-hoc scripts with no UI or consistency,
- lack quick visibility into *“is this IOS XE version already known-bad?”*

Cisco Micro-Tool Generator aims to solve this by providing:
- opinionated but configurable secure defaults,
- reusable **device profiles**,
- a simple **Web UI** on top of a versioned API,
- and a clear path toward automation or SaaS deployment.

---

## ✨ Core Features

### 🔧 Configuration Generators

#### SNMPv3 Generator
- Secure defaults, balanced and legacy-compatible modes
- SHA / AES-based configuration
- CLI or one-line output formats

#### NTP Generator
- Primary and secondary servers
- Optional authentication
- Timezone configuration

#### AAA / TACACS+ Generator
- TACACS+ with local fallback
- Local-only mode
- Optional source-interface support

#### Golden Config Builder
- Combine SNMPv3 / NTP / AAA snippets
- Generate a baseline hardened device configuration
- Designed to evolve into compliance / drift detection workflows

---

## 🔐 CVE Analyzer (v0.2)

A lightweight CVE awareness engine focused on Cisco IOS XE.

**Capabilities:**
- Platform + software version matching
- Severity classification (critical / high / medium / low)
- Upgrade recommendations based on known fixed versions
- Structured JSON output via API

**Web UI features:**
- Text-based CVE report
- Collapsible CVE cards
- Severity badges
- Security posture summary panel

> ℹ️ CVE Analyzer currently uses a curated dataset for demonstration purposes only.

---

## 📁 Profiles v2 (UI + API)

Profiles allow you to **capture, reuse and reapply configuration intent**.

### What is a profile?
A profile is a named snapshot of:
- SNMPv3 configuration
- NTP configuration
- AAA / TACACS+ configuration

### What you can do
- Save current form values as a profile
- List available profiles
- Load a profile into the Web UI
- Delete profiles you no longer need

### API Endpoints
```
GET    /profiles/list
GET    /profiles/load/{name}
POST   /profiles/save
DELETE /profiles/delete/{name}
```

Profiles are stored on disk and can be persisted via Docker volumes.

---

## 🖥 Web UI v2

The Web UI provides a clean, distraction-free interface for daily use.

**Highlights:**
- Sidebar-based navigation
- Dedicated views for each generator
- CVE Analyzer with expandable CVE cards
- Profiles management UI (Profiles v2)
- Copy & download buttons for all outputs
- Persistent form state using `localStorage`

---

## 🧱 Architecture Overview

```
cisco-microtool-generator/
├── api/
│   ├── main.py
│   ├── routers/
│   │   ├── snmpv3.py
│   │   ├── ntp.py
│   │   ├── aaa.py
│   │   ├── golden_config.py
│   │   ├── cve.py
│   │   └── profiles.py
│   ├── services/
│   │   ├── cve_engine.py
│   │   ├── profile_service.py
│   │   └── utils.py
│   └── models/
│       ├── cve_model.py
│       ├── profile_model.py
│       └── meta.py
├── cve_data/
│   └── ios_xe/
├── profiles/
├── web/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── Dockerfile
└── README.md
```

---

## 🚀 Running locally (development)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Swagger UI:
```
http://127.0.0.1:8000/docs
```

---

## 🐳 Running with Docker

### Build image
```bash
docker build -t cisco-microtool-api .
```

### Run (ephemeral profiles)
```bash
docker run --rm -p 8000:8000 cisco-microtool-api
```

### Run with persistent profiles (recommended)
```bash
docker run --rm -p 8000:8000 \
  -v "$(pwd)/profiles:/app/profiles" \
  cisco-microtool-api
```

This ensures that profiles created via `/profiles/save`
are persisted across container restarts.

---

## 🧪 CVE Data Disclaimer (Important)

- CVE entries are **demo-only**
- Intended to showcase:
  - matching logic
  - severity aggregation
  - UI presentation
- This tool **must not** be used as a replacement for official Cisco advisories

---

## 🛣 Roadmap (high level)

- Profiles UX improvements (rename, duplicate, confirm modals)
- CVE Engine v0.3 (data enrichment, external feeds)
- Export reports (Markdown / JSON)
- Authentication & multi-user mode
- SaaS-ready deployment (cloud)

---

## 📄 License

MIT

---

## 👤 Author / Notes

Built as a public engineering project focused on:
- network automation,
- secure configuration practices,
- and SaaS-oriented backend design.

Contributions, feedback and discussion are welcome.
