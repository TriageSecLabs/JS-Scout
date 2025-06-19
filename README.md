# JS-Scout 🔭

A simple and fast command-line tool to perform reconnaissance on JavaScript files. Developed by Triage Security Labs.

`JS-Scout` automates the tedious process of finding and analyzing JavaScript files associated with a web application, extracting potential API endpoints, secrets, and other valuable information for security researchers.

---

### Features

- **JS File Discovery:** Crawls a target URL to find all linked JavaScript files.
- **Pattern Matching:** Scans JS content for common patterns:
  - API endpoints and paths (`/api/v1`, `/internal/`, etc.).
  - Other subdomains and URLs.
  - Potential secrets and sensitive keywords (`token`, `secret`, `api_key`).
- **Concurrent Analysis:** Uses multithreading to analyze multiple files quickly.
- **Clean & Structured Output:** Presents findings in a clear, organized format.
- **Supports Multiple Targets:** Scan a single URL or provide a list of URLs from a file.

---

### Installation

`JS-Scout` is a Python 3 tool.

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/TriageSecLabs/JS-Scout.git
    cd JS-Scout
    ```

2.  **Install the dependencies:**
    ```sh
    pip3 install -r requirements.txt
    ```

---

### Usage

You can scan a single URL or provide a file containing a list of URLs.

#### Scan a single URL:
```sh
python3 js-scout.py -u https://example.com
```

#### Scan a list of URLs from a file:
Create a file (e.g., `targets.txt`):
```
https://example.com
https://anotherexample.org
```
Then run the tool:
```sh
python3 js-scout.py -l targets.txt
```

#### Options

- `-u`, `--url`: A single URL to scan.
- `-l`, `--list`: A file containing a list of URLs (one per line).
- `-t`, `--threads`: Number of concurrent threads to use (default: 10).
- `-v`, `--version`: Show the tool's version.

---

### Disclaimer

This tool is intended for educational purposes and for use in authorized security assessments. The user is responsible for their own actions and must comply with all applicable laws and terms of service.

---

© Triage Security Labs
