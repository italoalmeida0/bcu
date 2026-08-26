"""
Vulnerability Auditor engine: cross-references installed applications against
offline curated CVE advisories and live OSV.dev vulnerability feeds.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Set

from bcu.models import (
    ApplicationEntry,
    SeverityLevel,
    VulnerabilityFinding,
    VulnerabilityReport,
)
from bcu.security.db import KNOWN_VULNERABILITIES
from bcu.security.version_matcher import match_version_constraint


class VulnerabilityAuditor:
    """Audits installed software for known security vulnerabilities and CVEs."""

    @classmethod
    def query_osv_online(cls, package_name: str, version: str) -> List[VulnerabilityFinding]:
        """Queries OSV.dev (Open Source Vulnerabilities API) for known CVEs/GHSAs."""
        findings: List[VulnerabilityFinding] = []
        if not version or not package_name:
            return findings

        # Clean name
        clean_name = package_name.lower().strip()
        for suffix in [" (store app)", " (scoop)", " (chocolatey)", " (winget)", " (steam)", " (directory)"]:
            clean_name = clean_name.replace(suffix, "")

        url = "https://api.osv.dev/v1/query"
        payload = json.dumps({"package": {"name": clean_name}, "version": version}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "BCU-Security-Auditor/1.0"},
        )

        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    vulns = data.get("vulns", [])
                    for v in vulns:
                        v_id = v.get("id", "UNKNOWN")
                        # Filter to relevant global CVEs, GitHub Advisories, Python/NPM advisories
                        if not v_id.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-")):
                            continue

                        summary = v.get("summary") or v.get("details", "")[:120]
                        details = v.get("details", "")

                        # Extract severity
                        severity = SeverityLevel.MEDIUM
                        cvss = None
                        if "database_specific" in v and "severity" in v["database_specific"]:
                            raw_sev = str(v["database_specific"]["severity"]).upper()
                            if "CRIT" in raw_sev:
                                severity = SeverityLevel.CRITICAL
                            elif "HIGH" in raw_sev:
                                severity = SeverityLevel.HIGH
                            elif "LOW" in raw_sev:
                                severity = SeverityLevel.LOW

                        # Extract fixed version from events if available
                        fixed_ver = None
                        affected_range = f"<= {version}"
                        for aff in v.get("affected", []):
                            for r in aff.get("ranges", []):
                                for ev in r.get("events", []):
                                    if "fixed" in ev:
                                        fixed_ver = ev["fixed"]
                                        affected_range = f"< {fixed_ver}"
                                        break

                        finding = VulnerabilityFinding(
                            id=v_id,
                            app_id=f"osv:{clean_name}:{v_id}".lower(),
                            app_name=package_name,
                            installed_version=version,
                            affected_range=affected_range,
                            fixed_version=fixed_ver,
                            severity=severity,
                            cvss_score=cvss,
                            title=summary or f"Vulnerability in {package_name}",
                            description=details or "Security advisory from OSV.dev database.",
                            references=[ref.get("url") for ref in v.get("references", []) if ref.get("url")],
                        )
                        findings.append(finding)
        except Exception:
            pass

        return findings

    @classmethod
    def audit_app(
        cls,
        app: ApplicationEntry,
        min_severity: SeverityLevel = SeverityLevel.LOW,
        online: bool = True,
    ) -> List[VulnerabilityFinding]:
        """Audits a single application against curated CVEs and live OSV.dev database."""
        findings: List[VulnerabilityFinding] = []
        ver = app.display_version
        if not ver:
            return findings

        app_name_lower = app.display_name_trimmed.lower()

        # 1. Offline Curated CVE Database
        for entry in KNOWN_VULNERABILITIES:
            # Check exclusions
            exclude_names = entry.get("app_exclude_names", [])
            if any(ex in app_name_lower for ex in exclude_names):
                continue

            match_names = entry.get("app_match_names", [])
            matches_app = False
            for m in match_names:
                # Use regex word boundaries so 'rar' doesn't match 'library' or 'git' match 'digital'
                pattern = r"(?:^|[\s\-_])" + re.escape(m) + r"(?:$|[\s\-_])"
                if re.search(pattern, app_name_lower):
                    matches_app = True
                    break

            if not matches_app:
                continue

            affected_range = entry.get("affected_range", "")
            if match_version_constraint(ver, affected_range):
                sev = entry.get("severity", SeverityLevel.MEDIUM)
                if sev >= min_severity:
                    finding = VulnerabilityFinding(
                        id=entry["id"],
                        app_id=app.id,
                        app_name=app.display_name_trimmed,
                        installed_version=ver,
                        affected_range=affected_range,
                        fixed_version=entry.get("fixed_version"),
                        severity=sev,
                        cvss_score=entry.get("cvss_score"),
                        title=entry.get("title", ""),
                        description=entry.get("description", ""),
                        references=entry.get("references", []),
                    )
                    findings.append(finding)

        # 2. Online OSV.dev Query (if enabled)
        if online and not findings:
            online_vulns = cls.query_osv_online(app.display_name_trimmed, ver)
            for ov in online_vulns:
                if ov.severity >= min_severity:
                    findings.append(ov)

        return findings

    @classmethod
    def audit_all(
        cls,
        apps: List[ApplicationEntry],
        min_severity: SeverityLevel = SeverityLevel.LOW,
        online: bool = False,
    ) -> VulnerabilityReport:
        """Audits all installed applications and generates a VulnerabilityReport."""
        all_findings: List[VulnerabilityFinding] = []
        vulnerable_apps: Set[str] = set()

        if online and len(apps) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                future_to_app = {
                    executor.submit(cls.audit_app, app, min_severity, online): app
                    for app in apps
                }
                for future in concurrent.futures.as_completed(future_to_app):
                    app = future_to_app[future]
                    try:
                        findings = future.result()
                        if findings:
                            vulnerable_apps.add(app.id)
                            all_findings.extend(findings)
                    except Exception:
                        pass
        else:
            for app in apps:
                findings = cls.audit_app(app, min_severity=min_severity, online=online)
                if findings:
                    vulnerable_apps.add(app.id)
                    all_findings.extend(findings)

        # Sort findings by severity (Critical -> High -> Medium -> Low)
        all_findings.sort(key=lambda f: f.severity.numeric_rank, reverse=True)

        breakdown: Dict[str, int] = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
        }
        for f in all_findings:
            breakdown[f.severity.value] = breakdown.get(f.severity.value, 0) + 1

        return VulnerabilityReport(
            total_scanned=len(apps),
            vulnerable_apps_count=len(vulnerable_apps),
            total_vulnerabilities=len(all_findings),
            findings=all_findings,
            severity_breakdown=breakdown,
        )
