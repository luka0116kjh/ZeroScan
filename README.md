# Web Security Scanner (Vaccine)

[English](README.md) | [한국어](README_KR.md)

A Flask-based web security auditing tool that analyzes target URLs for security headers, HTTPS enforcement, and general performance metrics. It provides an automated "AI-style" explanation and suggests learning modules based on the results.

## Key Features

- **Header Analysis**: Checks for essential security headers (HSTS, CSP, X-Frame-Options, etc.).
- **HTTPS Validation**: Verifies if the target site enforces encrypted connections.
- **Performance Benchmarking**: Measures response times to ensure security monitoring visibility.
- **Rule-based AI Explanations**: Generates a summary of security posture with positive findings and critical risks.
- **Personalized Learning Path**: Recommends specific security modules based on the scan's findings.
- **Scan Logging & Statistics**: Tracks historical scans and provides a dashboard-ready summary of grade distribution.

## Tech Stack

- **Backend**: Python, Flask, Requests
- **Analysis Logic**: Rule-based scoring (0-100) and grading (A-F)
- **Data Persistence**: JSONL-based local logging

## Quick Start

### 1. Install Dependencies

```powershell
pip install flask requests
```

### 2. Run the Application

```powershell
python app.py
```

The server will be available at `http://127.0.0.1:5000` (default Flask port).

## API Endpoints

- `GET /`: Serves the main UI.
- `GET /api/learn`: Returns the catalog of security learning modules.
- `GET /api/logs/summary`: Provides statistical overview of past scans.
- `POST /scan`: Audits a specific URL. 
  - Body: `{"url": "https://example.com"}`

## Project Structure

```text
백신/
|-- app.py             # Main application logic and API routes
|-- data/              # Stores scan logs (scan_logs.jsonl)
|-- templates/         # HTML templates for the UI
`-- static/            # CSS/JS assets (if applicable)
```

## Security Considerations

- **Server-Side Request Forgery (SSRF) Protection**: Includes logic to block scanning of private/internal IP ranges and localhosts.
- **Redirect Limits**: Prevents open redirect loops (Max 5 redirects).
- **Timeout Management**: All requests have a default timeout to prevent resource exhaustion.

## Disclaimer

This tool is designed for educational and basic auditing purposes. It acts as a "Vaccine" for web security awareness by highlighting common misconfigurations. It does not replace professional penetration testing or comprehensive vulnerability scanners.
