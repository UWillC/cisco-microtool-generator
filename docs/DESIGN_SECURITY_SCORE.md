# Security Score — Design Specification

**Version:** 1.0
**Date:** 2026-01-13
**Author:** @elon
**Status:** Ready for implementation

---

## Overview

Security Score to numeryczna ocena (0-100) bezpieczeństwa profilu urządzenia, oparta na analizie podatności CVE. Wyższy score = bezpieczniejsze urządzenie.

---

## Decyzje projektowe

| Aspekt | Decyzja |
|--------|---------|
| Modyfikatory | Włączone (exploited-in-wild, fixed_in, age) |
| Unknown profiles | `null` (brak score gdy brak platform/version) |
| Granularność | Per-CVE breakdown + sumaryczny |

---

## Algorytm

### Podstawowa formuła

```
BASE_SCORE = 100

For each CVE matching profile:
    base_penalty = SEVERITY_PENALTY[cve.severity]
    modifier = calculate_modifier(cve)
    penalty = base_penalty * modifier
    BASE_SCORE -= penalty

FINAL_SCORE = max(0, round(BASE_SCORE))
```

### Tabela kar bazowych (SEVERITY_PENALTY)

| CVSS Score | Severity | Base Penalty |
|------------|----------|--------------|
| 9.0 - 10.0 | critical | 25 |
| 7.0 - 8.9  | high     | 15 |
| 4.0 - 6.9  | medium   | 8  |
| 0.1 - 3.9  | low      | 3  |

### Modyfikatory (multipliers)

| Warunek | Modifier | Uzasadnienie |
|---------|----------|--------------|
| Tag "exploited-in-wild" | × 1.5 | Aktywne exploity = większe ryzyko |
| `fixed_in` is not null | × 0.7 | Patch dostępny = mniejsze ryzyko |
| CVE published > 365 dni temu | × 1.2 | Stare CVE = dłużej narażony |

**Kombinowanie modyfikatorów:** Mnożenie (multiplicative stacking)

```python
modifier = 1.0
if "exploited-in-wild" in cve.tags:
    modifier *= 1.5
if cve.fixed_in is not None:
    modifier *= 0.7
if cve_age_days(cve) > 365:
    modifier *= 1.2
```

---

## Kategorie wynikowe

| Score | Label | Color | CSS Class | Znaczenie |
|-------|-------|-------|-----------|-----------|
| 90-100 | Excellent | #22c55e | `score-excellent` | Minimalne ryzyko |
| 70-89 | Good | #84cc16 | `score-good` | Akceptowalne |
| 50-69 | Fair | #eab308 | `score-fair` | Wymaga uwagi |
| 25-49 | Poor | #f97316 | `score-poor` | Pilne działanie |
| 0-24 | Critical | #ef4444 | `score-critical` | Natychmiastowa reakcja |
| null | Unknown | #6b7280 | `score-unknown` | Brak danych |

---

## Struktury danych

### CVEScoreBreakdown (per-CVE detail)

```python
class CVEScoreBreakdown(BaseModel):
    cve_id: str
    cvss_score: Optional[float]
    severity: str
    base_penalty: float
    modifiers_applied: List[str]  # ["exploited-in-wild", "patch-available", "aged"]
    modifier_value: float         # e.g. 1.26 (1.5 * 0.7 * 1.2)
    final_penalty: float          # base_penalty * modifier_value
```

### ProfileSecurityScore (per-profile result)

```python
class ProfileSecurityScore(BaseModel):
    profile_name: str
    platform: Optional[str]
    version: Optional[str]

    score: Optional[int]          # 0-100 or null
    label: Optional[str]          # "Excellent" / "Good" / etc.

    cve_count: int
    cve_breakdown: List[CVEScoreBreakdown]

    # Summary penalties
    total_base_penalty: float
    total_final_penalty: float
```

### SecurityScoreResponse (API response)

```python
class SecurityScoreResponse(BaseModel):
    timestamp: str
    profiles_checked: int

    # Aggregated stats
    average_score: Optional[float]
    lowest_score: Optional[int]
    highest_score: Optional[int]

    results: List[ProfileSecurityScore]
```

---

## API Endpoint

```
GET /profiles/security-scores
```

**Response example:**

```json
{
  "timestamp": "2026-01-13T18:30:00Z",
  "profiles_checked": 3,
  "average_score": 62,
  "lowest_score": 19,
  "highest_score": 100,
  "results": [
    {
      "profile_name": "lab-router",
      "platform": "ios_xe",
      "version": "17.3.1",
      "score": 100,
      "label": "Excellent",
      "cve_count": 0,
      "cve_breakdown": [],
      "total_base_penalty": 0,
      "total_final_penalty": 0
    },
    {
      "profile_name": "dc-switch",
      "platform": "ios_xe",
      "version": "17.6.1",
      "score": 19,
      "label": "Critical",
      "cve_count": 3,
      "cve_breakdown": [
        {
          "cve_id": "CVE-2023-20198",
          "cvss_score": 10.0,
          "severity": "critical",
          "base_penalty": 25,
          "modifiers_applied": ["exploited-in-wild", "aged"],
          "modifier_value": 1.8,
          "final_penalty": 45
        },
        {
          "cve_id": "CVE-2023-20273",
          "cvss_score": 7.2,
          "severity": "high",
          "base_penalty": 15,
          "modifiers_applied": ["aged"],
          "modifier_value": 1.2,
          "final_penalty": 18
        },
        {
          "cve_id": "CVE-2025-20188",
          "cvss_score": 10.0,
          "severity": "critical",
          "base_penalty": 25,
          "modifiers_applied": ["patch-available"],
          "modifier_value": 0.7,
          "final_penalty": 17.5
        }
      ],
      "total_base_penalty": 65,
      "total_final_penalty": 80.5
    }
  ]
}
```

---

## Przykłady obliczeń

### Przykład 1: Clean profile
- CVE count: 0
- Score: **100** (Excellent)

### Przykład 2: 1× Critical (standard)
- CVE-2025-20188: CVSS 10.0, critical, no modifiers
- Penalty: 25 × 1.0 = 25
- Score: 100 - 25 = **75** (Good)

### Przykład 3: 1× Critical (exploited + old)
- CVE-2023-20198: CVSS 10.0, critical, exploited-in-wild, >365 days
- Modifier: 1.5 × 1.2 = 1.8
- Penalty: 25 × 1.8 = 45
- Score: 100 - 45 = **55** (Fair)

### Przykład 4: 1× Critical (patched + old)
- CVE-2023-20198: CVSS 10.0, critical, fixed_in exists, >365 days
- Modifier: 0.7 × 1.2 = 0.84
- Penalty: 25 × 0.84 = 21
- Score: 100 - 21 = **79** (Good)

### Przykład 5: Multiple CVEs (worst case)
- CVE-2023-20198: critical, exploited, old → 25 × 1.8 = 45
- CVE-2023-20273: high, old → 15 × 1.2 = 18
- CVE-2025-20188: critical, patched → 25 × 0.7 = 17.5
- Total penalty: 80.5
- Score: 100 - 80.5 = **19** (Critical)

---

## Implementation checklist

- [ ] Add models to `models/security_score.py`
- [ ] Add `calculate_security_score()` to `ProfileService`
- [ ] Add helper `cve_age_days(cve)` function
- [ ] Add endpoint `GET /profiles/security-scores`
- [ ] Add unit tests for edge cases
- [ ] Update UI with score display (badge + breakdown modal)
- [ ] Update CHANGELOG.md

---

## UI Considerations

### Score Badge
- Circular badge with score number
- Background color based on category
- Tooltip with label on hover

### Breakdown Modal
- Click on profile → modal with CVE breakdown table
- Columns: CVE ID, CVSS, Severity, Modifiers, Penalty
- Total at bottom

---

## Future enhancements (v2+)

1. **Weighted by device criticality** — DC core vs lab router
2. **Trend tracking** — score history over time
3. **Remediation impact** — "if you patch X, score improves by Y"
4. **Compliance mapping** — NIST, CIS benchmarks

---

**Document status:** APPROVED
**Next step:** Implementation by @coo
