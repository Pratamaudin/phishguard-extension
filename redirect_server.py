from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_DIR = Path(__file__).resolve().parent


class TestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            directory=str(PROJECT_DIR),
            **kwargs
        )

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/test.html")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        super().do_GET()


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8765),
        TestHandler
    )

    print("Buka http://127.0.0.1:8765/redirect")
    print("Tekan Ctrl+C untuk menghentikan server.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    finally:
        server.server_close()