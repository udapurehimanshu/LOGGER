# LogRadar:AI Log Investigator

LogRadar is a generic, technology-agnostic, and privacy-safe enterprise log investigation platform. It parses logs from any system, reconstructs transaction execution flows, detects risks, performs root cause analysis, and provides fix recommendations.

## Core Features

- 🔍 **Root Cause Analysis**: Classifies and isolates exceptions, DB errors, API timeouts, and validation issues with clear confidence levels.
- 🔒 **Privacy Mode**: One-click data masking to automatically redact emails, credentials, API keys, IPs, and user identifiers before rendering diagnostic info.
- ⚙️ **Execution Flow Reconstruction**: Dynamically tracks transactions across API, Database, Integration, and Script Engine components.
- 💬 **Ask AI Log Assistant**: Natural language querying to get L3 engineering guidance directly from your logs.
- 📈 **Performance Dashboard**: Real-time stats on error rates, slow API responses, query latencies, and total system health score.

## Deploying to GitHub Pages

Since LogRadar is a static web application built purely with HTML, CSS, and Client-Side Javascript, it is **100% serverless** and ready for instant deployment to GitHub Pages.

### Steps to Deploy:
1. Create a new public repository on GitHub (e.g., `logradar-investigator`).
2. Push the files in this folder to the repository:
   - `index.html`
   - `index.css`
   - `app.js`
   - `sample_logs.js`
   - `README.md`
3. Go to the repository **Settings** tab.
4. Under the **Code and automation** sidebar section, click on **Pages**.
5. Set **Source** to `Deploy from a branch`, choose `main` (or your default branch) and the `/ (root)` folder, then click **Save**.
6. GitHub will build the page in less than a minute and host it at:
   `https://<your-username>.github.io/<your-repo-name>/`
