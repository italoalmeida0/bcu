"""
Curated local database of high-profile Windows software CVEs and security advisories.
"""

from __future__ import annotations

from typing import Any, Dict, List
from bcu.models import SeverityLevel

# List of known CVE advisories for popular Windows desktop software
KNOWN_VULNERABILITIES: List[Dict[str, Any]] = [
    # WinRAR
    {
        "id": "CVE-2023-38831",
        "app_match_names": ["winrar"],
        "affected_range": "< 6.23",
        "fixed_version": "6.23",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 7.8,
        "title": "WinRAR Zero-Day Arbitrary Code Execution",
        "description": "Processing weaponized ZIP/RAR archives containing spoofed file extensions allows attackers to execute arbitrary code when opening a benign decoy file.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38831", "https://www.rarlab.com/rarnew.htm"],
    },
    {
        "id": "CVE-2023-40477",
        "app_match_names": ["winrar"],
        "affected_range": "< 6.23",
        "fixed_version": "6.23",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.8,
        "title": "WinRAR Recovery Volume Remote Code Execution",
        "description": "Improper validation of user-supplied data in recovery volumes allows remote attackers to execute code in the context of the current process.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-40477"],
    },

    # 7-Zip
    {
        "id": "CVE-2023-31102",
        "app_match_names": ["7-zip", "7zip"],
        "affected_range": "< 23.01",
        "fixed_version": "23.01",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.8,
        "title": "7-Zip SquashFS Out-of-Bounds Write Code Execution",
        "description": "SquashFS handler vulnerability allows attackers to execute arbitrary code or crash the application by enticing a user to extract a crafted archive.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-31102", "https://www.7-zip.org/history.txt"],
    },
    {
        "id": "CVE-2022-29072",
        "app_match_names": ["7-zip", "7zip"],
        "affected_range": "< 21.07",
        "fixed_version": "22.00",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.8,
        "title": "7-Zip Help Zero-Day Privilege Escalation",
        "description": "Dragging a crafted file to the 7-Zip Help window triggers Windows command execution in the context of the administrator.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-29072"],
    },

    # PuTTY
    {
        "id": "CVE-2024-31497",
        "app_match_names": ["putty"],
        "affected_range": ">= 0.68, < 0.81",
        "fixed_version": "0.81",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 8.1,
        "title": "PuTTY ECDSA Private Key Recovery",
        "description": "PuTTY generates biased ECDSA nonces using the NIST P-521 curve, allowing attackers with roughly 60 SSH signatures to recover the user's private key.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-31497", "https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html"],
    },

    # Notepad++
    {
        "id": "CVE-2023-40031",
        "app_match_names": ["notepad++", "notepad plus plus"],
        "affected_range": "< 8.5.7",
        "fixed_version": "8.5.7",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 7.8,
        "title": "Notepad++ Utf8_16_Read Heap Buffer Overflow",
        "description": "A heap-based buffer overflow flaw in Utf8_16_Read allows attackers to execute code via crafted UTF16 text files.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-40031", "https://notepad-plus-plus.org/news/v857-released/"],
    },
    {
        "id": "CVE-2023-40166",
        "app_match_names": ["notepad++", "notepad plus plus"],
        "affected_range": "< 8.5.7",
        "fixed_version": "8.5.7",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.8,
        "title": "Notepad++ SniffSlice Buffer Read Overflow",
        "description": "Buffer overflow in SniffSlice function allows memory corruption when parsing specific file encodings.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-40166"],
    },

    # VLC Media Player
    {
        "id": "CVE-2023-47359",
        "app_match_names": ["vlc media player", "vlc"],
        "affected_range": "< 3.0.19",
        "fixed_version": "3.0.19",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.8,
        "title": "VLC MMS Stream Double-Free / RCE",
        "description": "Double-free vulnerability in MMS access module allows attackers to cause denial of service or potential remote code execution via crafted media streams.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-47359", "https://www.videolan.org/security/sb-vlc3019.html"],
    },

    # Git for Windows
    {
        "id": "CVE-2024-32002",
        "app_match_names": ["git", "git for windows"],
        "affected_range": "< 2.45.1",
        "fixed_version": "2.45.1",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 9.0,
        "title": "Git Remote Code Execution on Clone with Submodules",
        "description": "Case-insensitive filesystem symlink exploitation allows remote code execution when cloning a repository with nested submodules.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-32002", "https://github.blog/2024-05-14-securing-git-addressing-5-new-cves/"],
    },

    # FileZilla Client
    {
        "id": "CVE-2023-46747",
        "app_match_names": ["filezilla"],
        "app_exclude_names": ["server"],
        "affected_range": "< 3.66.0",
        "fixed_version": "3.66.0",
        "severity": SeverityLevel.MEDIUM,
        "cvss_score": 5.5,
        "title": "FileZilla Client Path Traversal / Session Manipulation",
        "description": "FileZilla client vulnerability in response parsing allows remote servers to disclose local path layout or crash client.",
        "references": ["https://filezilla-project.org/"],
    },

    # Python / CPython
    {
        "id": "CVE-2023-40217",
        "app_match_names": ["python 3", "python"],
        "affected_range": ">= 3.11.0, < 3.11.5",
        "fixed_version": "3.11.5",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.5,
        "title": "Python SSL Handshake Bypass / TLS Stripping",
        "description": "Flaw in TLS handshake closure handling allows an attacker to inject data prior to encryption closure.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-40217"],
    },

    # Zoom
    {
        "id": "CVE-2024-24691",
        "app_match_names": ["zoom", "zoom meetings"],
        "affected_range": "< 5.16.5",
        "fixed_version": "5.16.5",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 9.6,
        "title": "Zoom Desktop Client Privilege Escalation / RCE",
        "description": "Improper input validation in Zoom Desktop Client allows an unauthenticated attacker to conduct privilege escalation via network access.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-24691"],
    },
]
