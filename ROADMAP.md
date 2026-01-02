# ROADMAP — Cisco Micro-Tool Generator

Current version: **v0.3.3**
Last updated: 2026-01-01

---

## ✅ Completed (v0.1.0 → v0.3.3)

### v0.1.0 — MVP Release
- [x] FastAPI backend with SNMPv3, NTP, AAA, Golden Config generators
- [x] Initial CVE Analyzer (static demo dataset)
- [x] Dockerized API
- [x] Web UI with generators and CVE tab
- [x] Basic profiles (Lab / Branch / Datacenter)

### v0.2.0 — Product Shaping
- [x] CVE Engine v0.2 with JSON-based dataset
- [x] Web UI v2 (sidebar layout, CVE dashboard)
- [x] Profiles v2 (backend-driven, save/load/delete)
- [x] Security posture summary panel
- [x] Services and models layer architecture

### v0.3.x — External Integration
- [x] CVE Engine v0.3 with provider architecture
- [x] NVD API v2.0 enrichment (real external integration)
- [x] CVSS, CWE, references fields
- [x] Safe merge strategy (local JSON as source of truth)

---

## 🎯 Next: v0.3.4 — Stability & Performance

Focus: Make NVD enrichment production-ready.

### Planned features

#### 1. NVD Response Caching
- Cache NVD responses to avoid rate limiting
- Options: file-based cache or Redis
- TTL: 24 hours (CVE data doesn't change frequently)

#### 2. Profiles × CVE Integration
- "Which saved profiles are affected by known CVEs?"
- Cross-reference profile IOS versions with CVE database
- Alert panel in Profiles tab

#### 3. Security Score (0-100)
- Aggregate score based on:
  - Number of critical/high CVEs
  - Max CVSS score
  - Availability of fixes
- Visual indicator in Web UI

#### 4. Error Handling Improvements
- Better user-facing error messages
- Graceful degradation when NVD is unavailable
- Loading states in Web UI

---

## 🚀 v0.4.0 — SaaS Readiness

Focus: Multi-user support and cloud deployment.

### Authentication & Authorization
- [ ] User registration and login
- [ ] JWT-based authentication
- [ ] API key support for programmatic access

### Multi-tenant Architecture
- [ ] User-scoped profiles
- [ ] Isolated CVE analysis history
- [ ] Usage tracking per user

### Billing Integration
- [ ] Stripe integration
- [ ] Subscription tiers (Free / Pro)
- [ ] Usage-based billing option

### Cloud Deployment
- [ ] Railway / Render / Fly.io deployment
- [ ] Environment configuration
- [ ] Health monitoring

---

## 🔮 Future (v0.5.0+)

### External Data Providers
- [ ] Cisco PSIRT Advisory integration
- [ ] Tenable vulnerability scanner integration
- [ ] Custom CVE dataset upload

### Export & Reporting
- [ ] PDF security reports
- [ ] Markdown export
- [ ] Scheduled email reports

### CLI Tool
- [ ] Terminal-based interface for power users
- [ ] Scriptable config generation
- [ ] CI/CD integration support

### Advanced Features
- [ ] Config diff / drift detection
- [ ] Compliance checking (CIS benchmarks)
- [ ] Network topology awareness

---

## 📊 Success Metrics (Q1 2026)

| Metric | Target |
|--------|--------|
| Beta users | 10 |
| Discovery calls | 5 |
| API uptime | 99% |
| NVD cache hit rate | >80% |

---

_This roadmap is updated as priorities evolve. See CHANGELOG.md for release history._
