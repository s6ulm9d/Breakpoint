from http.server import HTTPServer, BaseHTTPRequestHandler

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Breakpoint Mock</h1></body></html>")

def run(server_class=HTTPServer, handler_class=MockHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting mock server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
