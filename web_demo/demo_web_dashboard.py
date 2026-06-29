from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request
import json
from datetime import datetime


HOST = "0.0.0.0"
PORT = 9090

BANK_IPS = [
    "10.0.1.100",
    "10.0.1.101",
    "10.0.1.102"
]


def check_ip(ip):
    url = f"http://{ip}:8080"

    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            body = response.read().decode(errors="ignore")

            if "Real Bank Server" in body:
                return {
                    "ip": ip,
                    "status": "ACTIVE",
                    "message": "Real Bank Server is reachable"
                }

            return {
                "ip": ip,
                "status": "UNKNOWN",
                "message": "Response received, but not recognized"
            }

    except Exception:
        return {
            "ip": ip,
            "status": "DROPPED",
            "message": "No response / dropped by P4 switch"
        }


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            results = [check_ip(ip) for ip in BANK_IPS]

            response = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "results": results
            }

            data = json.dumps(response).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return

        page = """
<!DOCTYPE html>
<html>
<head>
    <title>Bank IP Shuffling Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: white;
            padding: 40px;
        }

        h1 {
            color: #60a5fa;
        }

        .subtitle {
            color: #cbd5e1;
            margin-bottom: 30px;
        }

        .grid {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }

        .card {
            width: 280px;
            padding: 25px;
            border-radius: 14px;
            background: #1e293b;
            box-shadow: 0 8px 20px rgba(0,0,0,0.35);
        }

        .ip {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 15px;
        }

        .active {
            border: 3px solid #22c55e;
        }

        .dropped {
            border: 3px solid #ef4444;
            opacity: 0.75;
        }

        .unknown {
            border: 3px solid #facc15;
        }

        .status {
            font-size: 22px;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .ACTIVE {
            color: #22c55e;
        }

        .DROPPED {
            color: #ef4444;
        }

        .UNKNOWN {
            color: #facc15;
        }

        .message {
            color: #cbd5e1;
        }

        .time {
            margin-top: 30px;
            color: #93c5fd;
        }

        button {
            margin-top: 30px;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }
    </style>
</head>
<body>
    <h1>Moving Target Defense Demo</h1>
    <div class="subtitle">
        Only one virtual bank IP is active. Old IPs are dropped by the P4 switch.
        The active bank IP changes every 30 seconds.
    </div>

    <div id="cards" class="grid"></div>

    <div id="time" class="time"></div>

    <button onclick="loadStatus()">Refresh Now</button>

    <script>
        async function loadStatus() {
            const response = await fetch('/api/status');
            const data = await response.json();

            const cards = document.getElementById('cards');
            cards.innerHTML = '';

            data.results.forEach(item => {
                const card = document.createElement('div');

                let className = 'card unknown';
                if (item.status === 'ACTIVE') className = 'card active';
                if (item.status === 'DROPPED') className = 'card dropped';

                card.className = className;

                card.innerHTML = `
                    <div class="ip">${item.ip}</div>
                    <div class="status ${item.status}">${item.status}</div>
                    <div class="message">${item.message}</div>
                `;

                cards.appendChild(card);
            });

            document.getElementById('time').innerText =
                'Last update: ' + data.time;
        }

        loadStatus();
        setInterval(loadStatus, 5000);
    </script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, format, *args):
        print(f"[WEB DEMO] {self.client_address[0]} - {format % args}")


server = HTTPServer((HOST, PORT), DemoHandler)

print(f"Web Demo Dashboard running on http://{HOST}:{PORT}")
server.serve_forever()
