import os
import logging
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

SEEDER_FILE_DIR = "tracker_directory"
SEEDER_FILE_NAME = "seeder_info.txt"
SEEDER_FILE_PATH = os.path.join(SEEDER_FILE_DIR, SEEDER_FILE_NAME)

class TrackerRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        client_ip = self.client_address[0]

        if path.startswith("/announce/upload"):
            self.handle_announce_upload(client_ip)
        elif path.startswith("/announce/download"):
            self.handle_announce_download()
        else:
            self.send_error(404, "Not Found")

    def handle_announce_upload(self, client_ip):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        info_hash = query_params.get('info_hash', [None])[0]
        port = query_params.get('port', [None])[0]

        if info_hash and port:
            self._update_seeder(port, info_hash, client_ip)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_error(400, "Bad Request")

    def handle_announce_download(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        info_hash = query_params.get('info_hash', [None])[0]

        if info_hash:
            response = self.find_and_print_line(SEEDER_FILE_PATH, info_hash)
            if response:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(response.encode())
            else:
                self.send_error(404, "Not Found")
        else:
            self.send_error(400, "Bad Request")

    def _update_seeder(self, port, info_hash, client_ip):
        try:
            seeder_info = f"{client_ip}:{port}"
            os.makedirs(SEEDER_FILE_DIR, exist_ok=True)
            seeder_line = f"{info_hash}: {seeder_info}\n"

            if os.path.isfile(SEEDER_FILE_PATH):
                with open(SEEDER_FILE_PATH, 'r') as file:
                    lines = file.readlines()
            else:
                lines = []

            seeder_exists = False
            for i, line in enumerate(lines):
                if info_hash in line:
                    seeder_ports = line.split(':')[1].strip().split(',')
                    if port in seeder_ports:
                        logging.info(f"Port {port} already exists for {info_hash}. Skipping update.")
                        return
                    else:
                        seeder_exists = True
                        lines[i] = line.rstrip() + f", {seeder_info}\n"
                        break

            if not seeder_exists:
                lines.append(seeder_line)

            with open(SEEDER_FILE_PATH, 'w') as file:
                file.writelines(lines)

            logging.info(f"Seeder information updated for {info_hash}.")
        except Exception as e:
            logging.error(f"Error updating seeder information: {e}")

    def find_and_print_line(self, file_path, target_string):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if target_string + ": " in line:
                        return line.split(": ", 1)[1]
            return None
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None

def get_local_ip():
    try:
        # Create a socket to test connectivity
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Use a public address to determine the local IP (doesn't actually connect)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return None

def start_tracker(port=6880):
    try:
        server_address = (get_local_ip(), port)
        httpd = HTTPServer(server_address, TrackerRequestHandler)
        logging.info(f"Tracker server is running on {server_address[0]}:{port}")

        # Start listening for requests
        httpd.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start tracker server: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        start_tracker()
    except KeyboardInterrupt:
        logging.info("Tracker server is shutting down.")