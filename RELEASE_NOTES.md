# JABBER V 5.5.0 — Release Notes

## 🚀 Overview
JABBER V 5.5.0 is a milestone production release delivering a complete platform rebranding, optimized dual-architecture packaging, and significant UI/UX enhancements. This version marks the transition to a fully standardized offensive security framework.

## ✨ Key Features
- **Full Rebranding**: System-wide transition from JRTS to JABBER with normalized versioning (V 5.5.0).
- **Dual-Arch Support**: Production-ready Debian packages for both **AMD64** and **ARM64** architectures.
- **Enhanced UI/UX**:
    - Modernized responsive layout for Artifacts and Reports.
    - Centered high-fidelity JABBER+ branding.
    - Optimized mobile-first experience.
- **Reporting Engine**: Unified output management with improved multi-format exports.

## 🛠 Improvements
- **Filesystem Audit**: Optimized repository structure with all non-essential development artifacts removed.
- **Security**: Hardened input validation and standardized execution lifecycle for all 209 modules.
- **Performance**: Reduced frontend bundle size and improved backend startup time.

## 📦 Distribution
Debian packages are available for installation:
```bash
sudo dpkg -i jabber_5.5.0_amd64.deb
sudo dpkg -i jabber_5.5.0_arm64.deb
```

## 📝 Technical Specs
- **Backend**: Java 21, Spring Boot 3
- **Frontend**: React 19, Vite 8
- **Desktop**: Electron 41
- **Architecture**: amd64, arm64

---
**© 2026 Funbinet Inc. All Rights Reserved.**
