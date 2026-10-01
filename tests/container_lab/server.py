"""Log real requests without interpreting or executing their paths."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200 if self.path == "/" else 404
        self.send_response(status)
        self.end_headers()
        self.wfile.write(b"sentinel isolated lab\n")

    def log_message(self, fmt, *args):
        with open("/var/log/lab-access.log", "a") as log:
            log.write(f'{self.client_address[0]} - - [{self.log_date_time_string()}] {fmt % args}\n')


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
