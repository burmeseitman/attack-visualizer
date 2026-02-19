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
- Server binds to `127.0.0.1` only (local machine).
- API accepts JSON only and enforces request size limits.
- WebSocket stream is restricted to local app origins.
- Frontend escapes rendered simulation output before inserting into HTML.
- Malware upload simulation is static text analysis only (no execution).

## Tech Stack
- Python 3 + `websockets` for live event streaming
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
