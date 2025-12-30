from dataclasses import dataclass
from typing import List, Optional, Any


@dataclass
class NormalizedCVE:
    cve_id: str
    title: str
    severity: str
    description: str

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    references: Optional[List[str]] = None

    published: Optional[str] = None
    last_modified: Optional[str] = None


class NvdImporter:
    """
    Parse NVD v2 API response into NormalizedCVE objects.

    We only take enrichment fields, not version/platform logic.
    """

    source_name = "nvd"

    def parse(self, raw: Any) -> List[NormalizedCVE]:
        out: List[NormalizedCVE] = []

        vulns = (raw or {}).get("vulnerabilities") or []
        for item in vulns:
            cve = (item or {}).get("cve") or {}
            cve_id = cve.get("id") or ""
            if not cve_id:
                continue

            # Title/description
            desc = ""
            descriptions = cve.get("descriptions") or []
            for d in descriptions:
                if (d or {}).get("lang") == "en":
                    desc = (d or {}).get("value") or ""
                    break
            if not desc and descriptions:
                desc = (descriptions[0] or {}).get("value") or ""

            # Weakness (CWE)
            cwe = None
            weaknesses = cve.get("weaknesses") or []
            for w in weaknesses:
                descs = (w or {}).get("description") or []
                for wd in descs:
                    if (wd or {}).get("lang") == "en":
                        val = (wd or {}).get("value") or ""
                        if val and val.startswith("CWE-"):
                            cwe = val
                            break
                if cwe:
                    break

            # References
            refs = []
            references = cve.get("references") or []
            for r in references:
                url = (r or {}).get("url")
                if url:
                    refs.append(url)

            # Dates
            published = cve.get("published")
            last_modified = cve.get("lastModified")

            # CVSS
            cvss_score = None
            cvss_vector = None

            metrics = cve.get("metrics") or {}
            # Prefer CVSS v3.1 -> v3.0 -> v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if not arr:
                    continue
                first = arr[0] if isinstance(arr, list) else None
                if not first:
                    continue

                if key == "cvssMetricV2":
                    cvss = (first or {}).get("cvssData") or {}
                    cvss_score = cvss.get("baseScore")
                    cvss_vector = cvss.get("vectorString")
                else:
                    cvss = (first or {}).get("cvssData") or {}
                    cvss_score = cvss.get("baseScore")
                    cvss_vector = cvss.get("vectorString")
                break

            # Severity: map from score (simple heuristic)
            sev = "medium"
            try:
                if cvss_score is not None:
                    s = float(cvss_score)
                    if s >= 9.0:
                        sev = "critical"
                    elif s >= 7.0:
                        sev = "high"
                    elif s >= 4.0:
                        sev = "medium"
                    else:
                        sev = "low"
            except Exception:
                sev = "medium"

            out.append(
                NormalizedCVE(
                    cve_id=cve_id,
                    title=cve_id,
                    severity=sev,
                    description=desc,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe=cwe,
                    references=refs,
                    published=published,
                    last_modified=last_modified,
                )
            )

        return out
