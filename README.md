# Security Scanner v6

A Flask-based web security assessment tool.  
Current implementation level: `v1 ~ v6`.

Flask 기반 웹 보안 점검 도구입니다.  
현재 구현 범위는 `v1 ~ v6`입니다.

## Features

- `v1` Health check: reachability, status code, response time
- `v2` Security header analysis: checks baseline security headers
- `v3` Scoring: 100-point security score with grade (A~F)
- `v4` AI explanation: summary, risks, and prioritized actions
- `v5` Log analytics: stores scan logs and provides summary insights
- `v6` Learning platform: recommends learning modules based on scan results

## 기능

- `v1` 상태 체크: 접속 상태, 응답 코드, 응답 시간
- `v2` 보안 헤더 분석: 주요 보안 헤더 존재 여부 검사
- `v3` 점수 시스템: 100점 만점 점수 + 등급(A~F)
- `v4` AI 설명: 결과 요약, 위험 포인트, 우선 조치 제안
- `v5` 로그 분석: 누적 스캔 로그 저장/요약
- `v6` 보안 학습 플랫폼: 결과 기반 학습 모듈 추천

## Project Structure

```text
백신/
  app.py
  templates/
    index.html
  data/
    scan_logs.jsonl
```

## 프로젝트 구조

```text
백신/
  app.py
  templates/
    index.html
  data/
    scan_logs.jsonl
```

## Run

1. Install dependencies

```bash
pip install flask requests
```

2. Start app

```bash
cd 백신
python app.py
```

3. Open browser

```text
http://127.0.0.1:5000
```

## 실행 방법

1. 의존성 설치

```bash
pip install flask requests
```

2. 앱 실행

```bash
cd 백신
python app.py
```

3. 브라우저 접속

```text
http://127.0.0.1:5000
```

## API

- `GET /`: dashboard
- `POST /scan`: run scan (`{ "url": "example.com" }`)
- `GET /api/logs/summary`: aggregated scan summary
- `GET /api/learn`: learning module catalog

## 보안 정책

- `http/https` URL만 허용
- 내부/로컬 주소 차단 (`localhost`, 사설/루프백 대역)
- 리다이렉트 단계별 안전성 검사
- 로그 저장 시 URL의 query/fragment 제거
- 잘못된 JSON 요청은 `400` JSON 에러로 일관 응답

## Notes

- Debug mode is controlled by environment variable:
  - PowerShell:

```powershell
$env:FLASK_DEBUG="1"
python app.py
```
