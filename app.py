from flask import Flask, jsonify, render_template, request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
import os
import requests
import socket
import time
import uuid
from urllib.parse import urlparse, urljoin, urlsplit, urlunsplit

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "scan_logs.jsonl"
REQUEST_TIMEOUT = 6
MAX_REDIRECTS = 5

SECURITY_HEADERS = {
    "strict-transport-security": {
        "display": "Strict-Transport-Security",
        "weight": 8,
        "recommendation": "Enable HSTS with a long max-age and includeSubDomains.",
    },
    "content-security-policy": {
        "display": "Content-Security-Policy",
        "weight": 8,
        "recommendation": "Add a restrictive CSP and allow only trusted sources.",
    },
    "x-frame-options": {
        "display": "X-Frame-Options",
        "weight": 6,
        "recommendation": "Set DENY or SAMEORIGIN to reduce clickjacking risk.",
    },
    "x-content-type-options": {
        "display": "X-Content-Type-Options",
        "weight": 6,
        "recommendation": "Set nosniff to block MIME sniffing.",
    },
    "referrer-policy": {
        "display": "Referrer-Policy",
        "weight": 6,
        "recommendation": "Set a strict referrer policy to avoid leaking URL data.",
    },
    "permissions-policy": {
        "display": "Permissions-Policy",
        "weight": 6,
        "recommendation": "Limit sensitive browser features to only what is needed.",
    },
}

LEARNING_MODULES = [
    {
        "id": "https-basics",
        "level": "beginner",
        "title": "HTTPS and TLS Basics",
        "summary": "Why HTTPS matters and how certificates protect traffic.",
        "outcome": "You can validate TLS setup and avoid mixed-content issues.",
    },
    {
        "id": "headers-core",
        "level": "beginner",
        "title": "Core Security Headers",
        "summary": "Purpose and safe defaults for HSTS, CSP, and frame protections.",
        "outcome": "You can deploy a baseline secure header set.",
    },
    {
        "id": "csp-hardening",
        "level": "intermediate",
        "title": "CSP Hardening Workshop",
        "summary": "Move from permissive CSP to nonce/hash based policies.",
        "outcome": "You can reduce XSS attack surface without breaking the app.",
    },
    {
        "id": "auth-and-access",
        "level": "intermediate",
        "title": "Auth, Access, and Bot Controls",
        "summary": "Why 401/403 responses happen and how to interpret them.",
        "outcome": "You can distinguish policy blocks from service outages.",
    },
    {
        "id": "security-observability",
        "level": "advanced",
        "title": "Security Observability",
        "summary": "Track score trends and prioritize fixes from recurring issues.",
        "outcome": "You can run a simple security improvement loop.",
    },
]


def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(raw_url):
    if not raw_url:
        return ""
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def sanitize_url_for_log(raw_url):
    parsed = urlsplit(raw_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def is_public_host(hostname):
    if not hostname:
        return False

    lowered = hostname.lower()
    if lowered == "localhost":
        return False

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

    return True


def ensure_safe_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http/https URLs are allowed."
    if not parsed.hostname:
        return False, "Invalid URL host."
    if not is_public_host(parsed.hostname):
        return False, "Target host is blocked by security policy."
    return True, None


def fetch_url_safely(url, headers):
    session = requests.Session()
    current_url = url

    for _ in range(MAX_REDIRECTS + 1):
        safe, reason = ensure_safe_target(current_url)
        if not safe:
            raise ValueError(reason)

        response = session.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers=headers,
        )

        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            current_url = urljoin(current_url, response.headers.get("Location"))
            continue

        return response

    raise ValueError("Too many redirects.")


def grade_from_score(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def build_request_headers():
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }


def analyze_headers(response_headers):
    score = 0
    logs = ["[V2] Security header analysis"]
    details = {}
    findings = []
    missing_headers = []
    lowered = {k.lower(): v for k, v in response_headers.items()}

    for key, meta in SECURITY_HEADERS.items():
        display_name = meta["display"]
        exists = key in lowered
        details[display_name] = {
            "present": exists,
            "value": lowered.get(key, ""),
            "weight": meta["weight"],
        }

        if exists:
            score += meta["weight"]
            logs.append(f"[OK] {display_name} is set")
        else:
            missing_headers.append(display_name)
            logs.append(f"[WARN] {display_name} is missing")
            findings.append(
                {
                    "severity": "medium",
                    "category": "security_headers",
                    "item": display_name,
                    "message": f"{display_name} header is missing.",
                    "recommendation": meta["recommendation"],
                }
            )

    return score, logs, details, findings, missing_headers


def generate_ai_explanation(total_score, grade, detail_scores, findings, status_code, final_scheme):
    positives = []
    risks = []
    priorities = []

    if final_scheme == "https":
        positives.append("Transport is protected by HTTPS.")
    else:
        risks.append("Traffic is not encrypted because HTTPS is not enforced.")
        priorities.append("Redirect all HTTP traffic to HTTPS and configure TLS correctly.")

    if 200 <= status_code < 300:
        positives.append("Target responded successfully to direct checks.")
    elif status_code in (401, 403):
        risks.append("The target is reachable but access is restricted by policy.")
        priorities.append("Treat this as access control behavior, not immediate downtime.")
    elif status_code >= 500:
        risks.append("Server-side stability issues may affect security controls.")
        priorities.append("Stabilize server errors before applying fine-grained hardening.")

    if detail_scores["security_headers"] >= 30:
        positives.append("Most baseline security headers are present.")
    elif detail_scores["security_headers"] < 20:
        risks.append("Multiple defensive headers are missing.")
        priorities.append("Deploy baseline header policy: HSTS, CSP, frame and type protections.")

    if detail_scores["speed"] < 10:
        risks.append("Slow responses can increase operational and monitoring blind spots.")

    if findings:
        top_findings = findings[:3]
        priorities.extend([f["recommendation"] for f in top_findings])

    overview = (
        f"Security posture is grade {grade} with score {total_score}/100. "
        "Use the priority actions to improve the next scan."
    )

    return {
        "model": "rule-based-ai-v1",
        "overview": overview,
        "positives": positives,
        "risks": risks,
        "priority_actions": list(dict.fromkeys(priorities))[:5],
    }


def recommend_learning_modules(scan_result):
    recommended_ids = []

    if scan_result["detail_scores"]["https"] < 20:
        recommended_ids.append("https-basics")

    if scan_result["detail_scores"]["security_headers"] < 30:
        recommended_ids.append("headers-core")

    missing_headers = set(scan_result.get("missing_headers", []))
    if "Content-Security-Policy" in missing_headers:
        recommended_ids.append("csp-hardening")

    if scan_result["status_code"] in (401, 403):
        recommended_ids.append("auth-and-access")

    recommended_ids.append("security-observability")

    module_by_id = {m["id"]: m for m in LEARNING_MODULES}
    ordered_unique = []
    for module_id in recommended_ids:
        if module_id in module_by_id and module_id not in ordered_unique:
            ordered_unique.append(module_id)

    return [module_by_id[module_id] for module_id in ordered_unique]


def append_scan_log(entry):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry, ensure_ascii=True) + "\n")


def read_scan_logs(limit=200):
    if not LOG_FILE.exists():
        return []

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    selected = lines[-limit:] if limit and limit > 0 else lines

    logs = []
    for line in selected:
        if not line.strip():
            continue
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return logs


def summarize_logs(logs):
    if not logs:
        return {
            "total_scans": 0,
            "average_score": 0,
            "grade_distribution": {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0},
            "top_missing_headers": [],
            "recent_targets": [],
            "last_scan_at": None,
        }

    total_scans = len(logs)
    avg_score = round(sum(log.get("score", 0) for log in logs) / total_scans, 1)

    grade_counter = Counter(log.get("grade", "F") for log in logs)
    grade_distribution = {g: grade_counter.get(g, 0) for g in ["A", "B", "C", "D", "F"]}

    missing_counter = Counter()
    for log in logs:
        missing_counter.update(log.get("missing_headers", []))

    top_missing_headers = [
        {"header": header, "count": count}
        for header, count in missing_counter.most_common(5)
    ]

    recent_targets = []
    seen_targets = set()
    for log in reversed(logs):
        target = log.get("target_url", "")
        if target and target not in seen_targets:
            seen_targets.add(target)
            recent_targets.append(target)
        if len(recent_targets) == 5:
            break

    return {
        "total_scans": total_scans,
        "average_score": avg_score,
        "grade_distribution": grade_distribution,
        "top_missing_headers": top_missing_headers,
        "recent_targets": recent_targets,
        "last_scan_at": logs[-1].get("timestamp"),
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/learn", methods=["GET"])
def learn_catalog():
    grouped = {"beginner": [], "intermediate": [], "advanced": []}
    for module in LEARNING_MODULES:
        grouped[module["level"]].append(module)

    return jsonify(
        {
            "status": "success",
            "catalog_version": "v1",
            "modules": grouped,
        }
    )


@app.route("/api/logs/summary", methods=["GET"])
def logs_summary():
    limit_raw = request.args.get("limit", "200")
    try:
        limit = max(1, min(int(limit_raw), 5000))
    except ValueError:
        limit = 200

    logs = read_scan_logs(limit=limit)
    return jsonify({"status": "success", "summary": summarize_logs(logs)})


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)
    if request.is_json and data is None:
        return jsonify({"status": "error", "message": "Invalid JSON body."}), 400

    data = data or {}
    url = normalize_url(data.get("url", ""))
    result_log = []

    if not url:
        return jsonify({"status": "error", "message": "URL is required."})

    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return jsonify({"status": "error", "message": "Invalid URL format."})

        total_score = 0
        findings = []
        detail_scores = {
            "availability": 0,
            "https": 0,
            "speed": 0,
            "security_headers": 0,
        }

        start_time = time.time()
        response = fetch_url_safely(url, headers=build_request_headers())
        duration = time.time() - start_time

        safe_target_url = sanitize_url_for_log(url)
        safe_final_url = sanitize_url_for_log(response.url)
        result_log.append(f"[*] Target URL: {safe_target_url}")

        if 200 <= response.status_code < 300:
            detail_scores["availability"] = 30
            result_log.append(f"[OK] Site is reachable (HTTP {response.status_code})")
        elif response.status_code in (401, 403):
            detail_scores["availability"] = 18
            result_log.append(
                f"[WARN] Site is reachable but access is restricted (HTTP {response.status_code})"
            )
            findings.append(
                {
                    "severity": "low",
                    "category": "access_control",
                    "item": "HTTP Access",
                    "message": f"Target returned HTTP {response.status_code}.",
                    "recommendation": "Validate scan path with proper authentication or allowed test endpoint.",
                }
            )
        else:
            detail_scores["availability"] = 10
            result_log.append(f"[WARN] Site responded with HTTP {response.status_code}")
            findings.append(
                {
                    "severity": "medium",
                    "category": "availability",
                    "item": "HTTP Status",
                    "message": f"Unexpected status code: {response.status_code}.",
                    "recommendation": "Investigate endpoint availability and routing behavior.",
                }
            )
        total_score += detail_scores["availability"]

        final_scheme = urlparse(response.url).scheme.lower()
        if final_scheme == "https":
            detail_scores["https"] = 20
            result_log.append("[OK] HTTPS is in use")
        else:
            result_log.append("[CRITICAL] Connection is not using HTTPS")
            findings.append(
                {
                    "severity": "high",
                    "category": "transport",
                    "item": "HTTPS",
                    "message": "Final URL is not using HTTPS.",
                    "recommendation": "Force HTTPS with redirect and HSTS.",
                }
            )
        total_score += detail_scores["https"]

        if duration <= 1.0:
            detail_scores["speed"] = 10
            result_log.append(f"[OK] Response speed is excellent ({duration:.2f}s)")
        elif duration <= 2.0:
            detail_scores["speed"] = 8
            result_log.append(f"[OK] Response speed is good ({duration:.2f}s)")
        elif duration <= 3.0:
            detail_scores["speed"] = 5
            result_log.append(f"[WARN] Response speed is moderate ({duration:.2f}s)")
        else:
            detail_scores["speed"] = 2
            result_log.append(f"[WARN] Response is slow ({duration:.2f}s)")
            findings.append(
                {
                    "severity": "low",
                    "category": "performance",
                    "item": "Response Time",
                    "message": f"Response time is {duration:.2f}s.",
                    "recommendation": "Improve server/network performance to keep scan confidence high.",
                }
            )
        total_score += detail_scores["speed"]

        header_score, header_logs, header_details, header_findings, missing_headers = analyze_headers(
            response.headers
        )
        detail_scores["security_headers"] = header_score
        total_score += header_score
        result_log.extend(header_logs)
        findings.extend(header_findings)

        grade = grade_from_score(total_score)
        result_log.append(f"[V3] Security score: {total_score}/100 (Grade {grade})")

        ai_explanation = generate_ai_explanation(
            total_score=total_score,
            grade=grade,
            detail_scores=detail_scores,
            findings=findings,
            status_code=response.status_code,
            final_scheme=final_scheme,
        )

        scan_id = str(uuid.uuid4())
        timestamp = now_utc_iso()

        scan_result = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "status": "success",
            "logs": result_log,
            "score": total_score,
            "grade": grade,
            "detail_scores": detail_scores,
            "header_details": header_details,
            "missing_headers": missing_headers,
            "findings": findings,
            "ai_explanation": ai_explanation,
            "final_url": safe_final_url,
            "response_time_sec": round(duration, 3),
            "status_code": response.status_code,
            "target_url": safe_target_url,
        }

        learning_path = recommend_learning_modules(scan_result)
        scan_result["learning_path"] = learning_path

        append_scan_log(
            {
                "scan_id": scan_id,
                "timestamp": timestamp,
                "target_url": safe_target_url,
                "final_url": safe_final_url,
                "status_code": response.status_code,
                "response_time_sec": round(duration, 3),
                "score": total_score,
                "grade": grade,
                "missing_headers": missing_headers,
            }
        )

        return jsonify(scan_result)

    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except requests.exceptions.RequestException as exc:
        return jsonify({"status": "error", "message": f"Request failed: {exc}"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)})


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
