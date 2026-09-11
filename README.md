# Desktop Sniffer 🚀

> **Cross-platform desktop HTTP/HTTPS sniffer and API mock debugger powered by PySide6 (Qt) and mitmproxy.**

Desktop Sniffer is a modern, developer-friendly graphical network inspector designed for intercepting, analyzing, and mocking HTTP/HTTPS traffic from desktop applications, browsers, and mobile devices (iOS / Android).

---

## ✨ Features

- 🌐 **Live Traffic Inspection**: Real-time packet capture, HTTP request/response headers, status codes, query parameters, and formatted JSON bodies.
- 🎭 **Visual Mock Rules**:
  - **Local Mock**: Return simulated responses immediately without contacting the upstream server.
  - **Response Patch**: Intercept server responses and modify only specific fields, headers, or status codes.
  - **Request Patch**: Intercept outgoing requests from clients and modify payloads/headers before reaching the server.
  - **Replace**: Completely swap the server response with a custom response or binary fixture.
- 📱 **Mobile & LAN Sniffing**: One-click LAN exposure (`0.0.0.0`) to inspect traffic from smartphones on the same Wi-Fi network with built-in CA certificate instructions (`http://mitm.it`).
- ⚡ **Windows System Proxy Toggle**: Seamless integration with Windows network proxy settings with auto-cleanup on exit.
- 🧠 **Advanced Matching & Scenarios**:
  - URL prefix, exact, and regex matching.
  - AND-condition filters (ideal for JSON-RPC methods on a single endpoint like `/rpc`).
  - Stateful mock scenarios (e.g., return `500 Server Error` on first hit, `200 Success` on retry).
  - Max hits limits and artificial network delay simulation.
- 🎨 **Modern Qt UI**: Syntax-highlighted JSON viewer, inline editable header tables, one-click clipboard copying, and non-blocking asynchronous architecture.

---

## 📦 Installation & Quick Start

### Requirements
- Python `>= 3.12`
- Windows 10/11, macOS, or Linux

### 1. Clone the repository
```bash
git clone https://github.com/your-username/desktop-sniffer.git
cd desktop-sniffer
```

### 2. Set up virtual environment
```bash
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -e .
```

### 4. Run the application
```bash
python -m desktop_sniffer
# or simply:
desktop-sniffer
```

---

## 🔒 Security & Privacy

When distributing or running this application:

1. **Root CA Certificates:**
   `mitmproxy` generates a unique local Certificate Authority (`~/.mitmproxy/mitmproxy-ca-cert.cer` and `mitmproxy-ca-cert.p12`) on your machine.
   > ⚠️ **NEVER commit or share your `mitmproxy-ca-key.pem` private key!** It is automatically excluded in `.gitignore`.

2. **Workspaces & Local Storage:**
   All captured flows, fixtures, and rules are saved locally in your user's AppData directory:
   - **Windows:** `%APPDATA%\LocalTools\DesktopSniffer\workspaces\`
   - **Linux / macOS:** `~/.local/share/DesktopSniffer/workspaces/`
   No personal data, authentication tokens, or capture databases are ever placed in the repository root.

3. **Auto-Cleanup:**
   The application intercepts window close events and restores your Windows System Proxy settings to prevent broken internet connections when shutting down.

---

## ⚖️ Third-Party Licenses & Compliance

This project is open-source under the **MIT License**. It leverages the following foundational libraries:

| Library | License | Usage / Compliance Notes |
|---|---|---|
| **mitmproxy** | [MIT License](https://github.com/mitmproxy/mitmproxy/blob/main/LICENSE) | Permissive open-source proxy engine used as a background worker. |
| **PySide6 (Qt)** | [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.html) | Used via dynamic linking (`import PySide6`). Under LGPLv3, user applications importing PySide6 can remain under MIT / Apache 2.0 without making your proprietary code LGPL. |
| **cryptography** | Apache 2.0 / BSD | Used for TLS certificate handling. |

---

## 🛠️ Development & Testing

Run unit tests with pytest:
```bash
pytest
```

Format and lint with Ruff:
```bash
ruff check .
ruff format .
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
