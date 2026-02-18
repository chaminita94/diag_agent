# Cybershield — Diag Agent & SOC Suite 🕵️‍♂️🛡️

Welcome to the official documentation repository of **Cybershield Solutions, S.L.**

This repository hosts and deploys all the technical documentation for the **Diag Agent** project, pentesting evaluations, and SOC Dashboard infrastructure.

---

## 🚀 Access the Documentation

You can explore the full technical documentation, code architecture, and user manuals on our official GitHub Pages site:

👉 **[View Complete Documentation Here](https://chaminita94.github.io/diag_agent/)**

🔴 **[Live Demo — Diag Agent](https://democshield.duckdns.org)** (read-only mode via Nginx reverse proxy)

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
| **Reverse Proxy Demo** | Nginx with SSL, rate limiting, and read-only demo mode |

---

## 📊 Project Statistics

| File | Lines | Description |
|------|-------|-------------|
| `diag_agent_single.py` | 15,275 | Main agent with web UI, SOC Dashboard and Unified Scanner |
| `pentest_agent.py` | 3,281 | Professional web pentesting engine |
| `os_scanner.py` | 672 | Multi-OS scanning (Windows, macOS, iOS, Linux) |
| `audit_manager.py` | 624 | AI audit with z.ai, zero-days, and CVEs |
| `uninstall_diag.sh` | 432 | Complete uninstall script |
| `setup_diag.sh` | 406 | Automated installation script |
| `autonomous_agent.py` | 147 | Autonomous agent with safe command execution |

| Website File | Lines | Description |
|--------------|-------|-------------|
| `index.html` | 1,708 | Corporate landing page |
| `custom.css` | 1,476 | Design system with glassmorphism and particles |
| `custom.js` | 765 | Interactivity engine (carousel, cursor, canvas) |
| `carousel.css` | 332 | Screenshot carousel styles |


| Deployment File | Lines | Description |
|-----------------|-------|-------------|
| `nginx.conf` | 89 | Main Nginx configuration |
| `sites-available/cshield` | 76 | Main site config (static) |
| `sites-available/democshield` | 78 | Demo app config (proxy) |
| `403demo.html` | 226 | Custom 403 demo page |

**Total: ~25,900+ lines of code & config**

---

## 📁 Repository Structure

```
Diag agent/     → Full agent source code, setup scripts, and modules
mkdocs/         → Documentation source files (Markdown)
Website/        → Corporate landing page assets
```

---

## 🌐 Live Deployment

| Environment | URL | Description |
|-------------|-----|-------------|
| **Website** | [cshield.duckdns.org](https://cshield.duckdns.org) | Corporate landing page |
| **Demo App** | [democshield.duckdns.org](https://democshield.duckdns.org) | Diag Agent in read-only mode |
| **Documentation** | [chaminita94.github.io/diag_agent](https://chaminita94.github.io/diag_agent/) | MkDocs technical docs |

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
**Version**: 4.11.0 (February 2026)
