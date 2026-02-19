# Attack Visualizer

A Python-based educational web app that visually simulates common attack patterns in a safe lab context.

## Screenshot
![Attack Visualizer Runtime](docs/runtime-screenshot.png)

## Simulations
- Brute force password guessing (capped attempt simulation)
- SQL injection behavior (unsafe query vs parameterized query)
- Attack/Defense mode switch that changes simulation flow
- Malware upload validation with static heuristic scoring
- AI prompt injection simulation with guardrail risk scoring
- Real-time charts and realistic terminal-style log scrolling
- Cyberpunk dark UI with ACCESS GRANTED animation
- WebSocket live telemetry feed for continuous effects
- Defensive guidance and mitigation checklist

## Important Safety Note
This project is for **education and defensive awareness only**.
It does not execute real attacks and should never be used for unauthorized activity.

## Usage & Copyright
Copyright (c) 2026 Attack Visualizer Contributors.
Licensed under the MIT License. See `LICENSE`.

Use this visualization only for education, security awareness, and authorized defensive training.
Do not use it for unauthorized testing, exploitation, or illegal activity.

## Security Notes
- Server defaults to local binding and can be configured via `HOST`/`PORT`.
- API accepts JSON only and enforces request size limits.
- WebSocket endpoint is same-origin (`/ws`) with origin checks.
- Frontend escapes rendered simulation output before inserting into HTML.
- Malware upload simulation is static text analysis only (no execution).

## Tech Stack
- Python 3 + `aiohttp` (HTTP + WebSocket on one port)
- HTML/CSS/JavaScript frontend with hacker-style UI

## Run
```bash
cd attack-visualizer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open:

`http://127.0.0.1:8000`

## Deploy on Render
This project is compatible with Render Web Services.

- A `render.yaml` blueprint is included.
- The app reads `PORT` from environment and can bind `0.0.0.0`.
- WebSocket works on the same public Render service via `/ws`.

### Quick steps
1. Push this repository to GitHub.
2. In Render, create a new Web Service from the repo.
3. Render will detect `render.yaml` and apply build/start settings.
4. Deploy and open your Render URL.

### Optional advanced setup
- Put Render behind your own domain and TLS policy if required by your organization.
- Keep origin restrictions and request limits enabled.

## Production Deployment Notes
Use this simple flow for production deployment on Render:

1. Push this repo to GitHub.
2. Create a new **Web Service** in Render from the repo.
3. Let Render use `render.yaml` automatically (build + start settings are included).
4. Click **Deploy** and open your Render URL.
