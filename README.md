# Cybershield — Diag Agent & SOC Suite 🕵️‍♂️🛡️

Welcome to the official documentation repository of **Cybershield Solutions, S.L.**

This repository hosts and deploys all the technical documentation for the **Diag Agent** project, pentesting evaluations, and SOC Dashboard infrastructure.

---

## 🚀 Access the Documentation

You can explore the full technical documentation, code architecture, and user manuals on our official GitHub Pages site:

👉 **[View Complete Documentation Here](https://chaminita94.github.io/diag_agent/)**

---

## 🛠️ About the Project

**Diag Agent** is a portable (monolithic) security diagnostic and auditing agent designed for critical server environments. It integrates:

| Feature | Description |
|---------|-------------|
| **Unified Discovery Scanner** | Multi-vector reconnaissance (DNS, SSL, WAF, Dirs, Shodan) with redirect heuristic correction |
| **Target OS Scan** | Cross-platform scanning for Windows, macOS, iOS, and Linux |
| **Web Pentesting** | Specialized engine for SQLi, XSS, LFI detection + Nikto & SQLMap integration |
| **AI Security** | Intelligent analysis with z.ai — Chat, Audit, and Autonomous Agent (beta) |
| **Network IDS Shield** | Real-time packet monitoring with Scapy and AI SOC assistant |
| **SOC Dashboard** | Live metrics, IP blocking, and alert analysis |
| **Audit Reports** | Digitally signed professional PDFs and CSV exports |
| **Telegram Integration** | Send PDF reports directly to your mobile |

---

## 📊 Project Statistics

| File | Lines | Description |
|------|-------|-------------|
| `diag_agent_single.py` | 14,789 | Main agent with web UI, SOC Dashboard and Unified Scanner |
| `pentest_agent.py` | 3,281 | Professional web pentesting engine |
| `audit_manager.py` | 624 | AI audit with z.ai, zero-days, and CVEs |
| `autonomous_agent.py` | 147 | Autonomous agent with safe command execution |
| `os_scanner.py` | 672 | Multi-OS scanning (Windows, macOS, iOS, Linux) |
| `setup_diag.sh` | 406 | Automated installation script |
| `uninstall_diag.sh` | 432 | Complete uninstall script |

**Total: ~20,000+ lines of code**

---

## 📁 Repository Structure

```
Diag agent/     → Full agent source code, setup scripts, and modules
mkdocs/         → Documentation source files (Markdown)
Website/        → Corporate landing page assets
```

---

## 🔧 Integrated Tools

- Trivy, Nmap, SSH-Audit, Enum4Linux
- Nikto, SQLMap, Hydra
- theHarvester, Subfinder
- Shodan, VirusTotal
- z.ai API (AI Analysis)
- WeasyPrint, PyHanko (PDF & Signing)

---

## 📜 License

MIT License

---

**Cybershield Solutions © 2026** — Professional Security Diagnostics

**Author**: Vitaliy Domin  
**Version**: 4.10.0 (February 2026)
