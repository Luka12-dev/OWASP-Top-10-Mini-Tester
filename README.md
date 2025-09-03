# OWASP Top 10 Mini Tester

**OWASP Top 10 Mini Tester** is a PyQt6 GUI application designed for quick, basic security testing against web applications. It provides an easy-to-use interface to run 10 common vulnerability checks and quickly spot potential security issues.

## Features
- Enter target URL (auto-adds HTTPS if missing)
- Run 10 basic OWASP Top 10 vulnerability checks:
  - SQL Injection (basic payload check)
  - Reflected XSS test
  - Insecure cookies (HttpOnly, Secure)
  - Insecure headers (missing CSP, X-Frame-Options)
  - Directory listing check
  - Open redirect pattern test
  - Sensitive info in response headers
  - Verbose error messages
  - HTTP methods allowed (PUT/DELETE)
  - Weak password form check (common names)
- Displays results in a table and log box
- Threaded execution (UI stays responsive)
- Modern, user-friendly CSS-style interface

## Installation
1. Clone or download this repository.
2. Install required Python packages:
   ```bash
   pip install PyQt6 requests validators
   ```

## Usage
```bash
python Owasp-Top10-Mini-Tester.py
```
- Enter the target URL.
- Click **Run Checks**.
- View results in the table and log.

## Build Executable with PyInstaller
```bash
pyinstaller --noconfirm --onefile --windowed --icon=web4.ico Owasp-Top10-Mini-Tester.py
```
- The executable will be located in the `dist/` folder.

## Screenshots
![Screenshot](ScreenShot.png)

## License
MIT License - use responsibly.

---

Created for educational and ethical security testing purposes.