import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# Read PORT from Render's environment variable (defaults to 8000 for local testing)
PORT = int(os.environ.get("PORT", 8000))

class WorkWatchHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        # Enable CORS for cross-origin requests from GitHub Pages
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        if self.path == '/api/bootstrap':
            self._set_headers(200)
            response = {
                "status": "ok",
                "message": "WorkWatch backend is live and running on Render!",
                "projects": [],
                "revs": {}
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode('utf-8'))

    def do_POST(self):
        self._set_headers(200)
        self.wfile.write(json.dumps({"status": "success"}).encode('utf-8'))

def run():
    # Binds to 0.0.0.0 so external cloud services (Render) can route traffic to it
    server_address = ('0.0.0.0', PORT)
    httpd = HTTPServer(server_address, WorkWatchHandler)
    print(f"Server running on port {PORT}...")
    sys.stdout.flush()
    httpd.serve_forever()

if __name__ == '__main__':
    run()
