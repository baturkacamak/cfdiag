import http.server
import socketserver
import time
import threading
from .reporting import print_header, print_info, Colors

class DiagnosticRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/timeout':
            time.sleep(10)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Timeout test complete")
        elif self.path == '/error':
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Simulated 500 Error")
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            response = ["Diagnostic Server Running.", ""]
            response.append("=== Request Headers ===")
            for k, v in self.headers.items():
                response.append(f"{k}: {v}")
            
            response.append("")
            response.append("=== Client Info ===")
            response.append(f"Client IP: {self.client_address[0]}")
            
            self.wfile.write("\n".join(response).encode('utf-8'))

    def log_message(self, format, *args):
        # Custom logging to match CLI style
        print_info(f"Request: {self.client_address[0]} - {format % args}")

def run_diagnostic_server(port: int = 8080):
    print_header("Diagnostic Server Mode")
    print_info(f"Listening on 0.0.0.0:{port}")
    print_info("Endpoints:")
    print_info("  GET /        - View Headers & IP (Verify CF-Connecting-IP)")
    print_info("  GET /timeout - Simulate 10s delay (Test 524/522)")
    print_info("  GET /error   - Simulate 5xx handling")
    print(f"\n{Colors.BOLD}Press Ctrl+C to stop{Colors.ENDC}")
    
    try:
        with socketserver.TCPServer(("", port), DiagnosticRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
