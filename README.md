# CodeGuard

**AI-assisted SBOM and dependency risk scanner.**

CodeGuard takes a software project (as a `.zip`), lists every third-party library it uses, checks them for known vulnerabilities, and uses AI to explain each risk in plain language and tell you what to fix first.

> CodeGuard is a **defensive** security tool (software composition analysis). It does not exploit anything. It only reads a project's dependency files and reports known issues.

---

## Purpose

Modern applications depend on dozens or hundreds of open-source packages. Any of them can contain a publicly known vulnerability (CVE), and checking them by hand is slow and error-prone.

CodeGuard automates the whole process:

- Builds a **Software Bill of Materials (SBOM)** for the project.
- Finds **known vulnerabilities** in each dependency.
- Uses **AI** to explain every finding, rate its risk, and suggest a fix.
- Presents everything in a **dashboard** and exports **PDF / Excel reports**.

**In one line:** CodeGuard finds vulnerable dependencies in a project and tells you which ones to fix first, and why.

---

## How it works

```
Upload .zip  ->  SBOM  ->  Vulnerability scan  ->  AI enrichment  ->  Dashboard + Reports
              (Syft)        (Snyk)                 (Gemini)           (Flask + Chart.js)
```

| Module | Role | Tool |
|---|---|---|
| **M1: SBOM** | Lists all components and versions in CycloneDX JSON format | [Syft](https://github.com/anchore/syft) |
| **M2: Scan** | Checks each dependency against a vulnerability database and normalizes results (package, version, CVE, CVSS, severity, fix version) | [Snyk CLI](https://snyk.io) |
| **M3: AI enrichment** | For each CVE: plain-English explanation, banking-context risk, priority tier, remediation advice | Google Gemini API |
| **M4: Dashboard** | Web UI with severity charts, findings table, scan history, and PDF / Excel report export | Flask, Tailwind, Chart.js |

Each scan runs in a background thread, and the UI shows live progress (SBOM, scanning, AI analysis).

---

## Features

- Upload a project as a `.zip` and scan it from the browser
- Supports **Node.js** (`package.json` / `package-lock.json`) and **Python** (`requirements.txt`) projects, including mixed projects
- Severity breakdown charts and a sortable findings table
- AI-generated explanation, priority tier, and remediation for every CVE
- Downloadable **PDF** and **Excel** reports
- History of previous scans
- Zip-slip protection when extracting uploads

---

## Requirements

- Python 3.10 or newer
- Node.js (needed to install the Snyk CLI)
- [Syft](https://github.com/anchore/syft#installation) on your `PATH`
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) and a free Snyk account
- A [Google Gemini API key](https://aistudio.google.com/)

Check your tools:

```bash
python --version
syft version
snyk --version
```

---

## Installation and running

**1. Clone the repository**

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>/main_application
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Install and authenticate Snyk**

```bash
npm install -g snyk
snyk auth
```

**4. Create your `.env` file**

Copy the example file and fill in your own keys:

```bash
cp .env.example .env
```

```env
GEMINI_API_KEY=your-gemini-api-key
SNYK_TOKEN=your-snyk-token      # optional if you already ran `snyk auth`
```

> Never commit your real `.env` file. It is already listed in `.gitignore`.

**5. Start the app**

```bash
python app.py
```

**6. Open the dashboard**

Go to **http://127.0.0.1:5000** in your browser.
Do **not** open `templates/index.html` directly, because the page needs the Flask server to work.

---

## Usage

1. Open the dashboard.
2. Upload a project `.zip` (try one from the `Apps_Vuln/` folder).
3. Click **Scan** and wait for the pipeline to finish.
4. Review the charts and findings, and read the AI explanation for each CVE.
5. Generate and download the **PDF** or **Excel** report.

### Test projects

The `Apps_Vuln/` folder contains projects with intentionally outdated dependencies for testing:

| File | Description |
|---|---|
| `vuln-node-app.zip` | Express app with old npm packages |
| `vuln-python-app.zip` | Flask app with old pip packages |
| `vuln-fullstack-app.zip` | Node frontend and Python backend together |
| `sample-app1.zip`, `sample-node-app.zip` | Original sample apps |

These are test fixtures only. **Do not deploy them.**

---

## Project structure

```
main_application/
├── app.py                  # Flask server and pipeline orchestration
├── modules/
│   ├── m1_sbom.py          # SBOM generation (Syft)
│   ├── m2_scan.py          # Vulnerability scan (Snyk) and result cleaning
│   ├── m3_enrich.py        # AI enrichment (Gemini)
│   └── report.py           # PDF / Excel report generation
├── templates/index.html    # Dashboard UI
├── static/                 # Chart.js
├── samples/                # Sample data for offline testing
├── scripts/                # Offline pipeline test
├── requirements.txt
└── .env.example
Apps_Vuln/                  # Vulnerable test projects
```

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Key for the AI enrichment step |
| `SNYK_TOKEN` | No | Snyk token (not needed if you ran `snyk auth`) |
| `CODEGUARD_SKIP_PIP_INSTALL` | No | Set to `1` to skip installing Python dependencies before scanning |

---

## Troubleshooting

- **"Failed to fetch" in the browser:** the Flask server is not running, or you opened the page from somewhere other than `http://127.0.0.1:5000`.
- **Syft or Snyk errors:** make sure both are installed and on your `PATH` (`syft version`, `snyk --version`), and that you ran `snyk auth`.
- **AI step fails:** check that `GEMINI_API_KEY` is valid and not rate-limited.

---

## Security notes

- Keep your API keys in `.env` only, and never commit them.
- Run CodeGuard locally. It is not hardened for public internet exposure.
- Only upload projects you trust and are allowed to scan.

---

## Tech stack

Python, Flask, Syft, Snyk CLI, Google Gemini API, HTML, Tailwind CSS, Chart.js, xhtml2pdf, openpyxl.

---

## Author

Built by **Omar**, Computer Science student at the Arab Academy for Science and Technology (AAST), as a cybersecurity project.
