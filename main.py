import http.server
import http.client
import socketserver
from urllib.parse import urlparse
import base64

MONGOSYNC_PORT = 27182
PROXY_PORT = 8080
USERNAME = 'admin'  # Replace with your desired username
PASSWORD = 'password'  # Replace with your desired password

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.authenticate_and_proxy("GET")

    def do_POST(self):
        self.authenticate_and_proxy("POST")

    def do_PUT(self):
        self.authenticate_and_proxy("PUT")

    def do_DELETE(self):
        self.authenticate_and_proxy("DELETE")

    def authenticate_and_proxy(self, method):
        if not self.authenticate():
            self.send_authentication_failed()
            return
        self.proxy_request(method)

    def authenticate(self):
        auth_header = self.headers.get('Authorization')
        if auth_header is None or not auth_header.startswith('Basic '):
            return False

        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':', 1)

        return username == USERNAME and password == PASSWORD

    def send_authentication_failed(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Access to the proxy"')
        self.end_headers()

    def proxy_request(self, method):
        url = urlparse(self.path)
        conn = http.client.HTTPConnection("localhost", MONGOSYNC_PORT)
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else None

        headers = {key: value for key, value in self.headers.items()}
        # Remove the Authorization header to prevent forwarding sensitive info
        headers.pop('Authorization', None)

        conn.request(method, url.path, body, headers)
        response = conn.getresponse()

        self.send_response(response.status)
        for header in response.getheaders():
            self.send_header(header[0], header[1])
        self.end_headers()

        response_body = response.read()
        if response_body:
            self.wfile.write(response_body)

with socketserver.TCPServer(("", PROXY_PORT), Proxy) as httpd:
    print(f"Serving at port {PROXY_PORT}")
    httpd.serve_forever()


