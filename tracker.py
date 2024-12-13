import os
import logging
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import bencodepy

# Constants
SEEDER_FILE_DIR = "tracker_directory"
SEEDER_FILE_NAME = "seeder_info.txt"
SEEDER_FILE_PATH = os.path.join(SEEDER_FILE_DIR, SEEDER_FILE_NAME)

LOG_DIR = "log_tracker"
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"tracker{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

class TrackerRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_get_request()

    def handle_get_request(self):
        path = urlparse(self.path).path
        client_ip = self.client_address[0]

        if path.startswith("/announce"):
            self.handle_announce(client_ip)
        elif path.startswith("/scrape"):
            self.handle_scrape()
        else:
            self.send_error(404, "Not Found")

    def handle_announce(self, client_ip):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        # Extract and decode parameters
        info_hash = query_params.get('info_hash', [None])[0]
        if info_hash:
            info_hash = unquote(info_hash)
        peer_id = query_params.get('peer_id', [None])[0]
        if peer_id:
            peer_id = unquote(peer_id)
        port = query_params.get('port', [None])[0]
        uploaded = query_params.get('uploaded', [0])[0]
        downloaded = query_params.get('downloaded', [0])[0]
        left = query_params.get('left', [0])[0]
        event = query_params.get('event', [None])[0]

        if info_hash and port and peer_id:
            self.update_peer_info(
                info_hash, peer_id, client_ip, port, uploaded, downloaded, left, event
            )
            # Prepare the response
            peers = self.get_peer_list(info_hash, exclude_peer_id=peer_id)
            response_data = {
                'interval': 1800,
                'peers': peers
            }
            encoded_response = bencodepy.encode(response_data)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(encoded_response)
        else:
            self.send_error(400, "Bad Request")

    def update_peer_info(self, info_hash, peer_id, ip, port, uploaded, downloaded, left, event):
        try:
            os.makedirs(SEEDER_FILE_DIR, exist_ok=True)
            entries = []

            if os.path.isfile(SEEDER_FILE_PATH):
                with open(SEEDER_FILE_PATH, 'r') as file:
                    entries = [eval(line.strip()) for line in file]

            # Remove the peer if the event is 'stopped'
            entries = [e for e in entries if not (e['info_hash'] == info_hash and e['peer_id'] == peer_id and event == 'stopped')]

            # Update or add the peer
            if event != 'stopped':
                updated = False
                for entry in entries:
                    if entry['info_hash'] == info_hash and entry['peer_id'] == peer_id:
                        entry.update({
                            'ip': ip,
                            'port': int(port),
                            'uploaded': int(uploaded),
                            'downloaded': int(downloaded),
                            'left': int(left),
                            'event': event,
                            'last_announce': datetime.now().timestamp()
                        })
                        updated = True
                        break
                if not updated:
                    entries.append({
                        'info_hash': info_hash,
                        'peer_id': peer_id,
                        'ip': ip,
                        'port': int(port),
                        'uploaded': int(uploaded),
                        'downloaded': int(downloaded),
                        'left': int(left),
                        'event': event,
                        'last_announce': datetime.now().timestamp()
                    })

            # Write back to the file
            with open(SEEDER_FILE_PATH, 'w') as file:
                for entry in entries:
                    file.write(f"{entry}\n")

            logging.info(f"Peer {peer_id} updated for {info_hash}. Event: {event}")
        except Exception as e:
            logging.error(f"Error updating peer information: {e}")

    def get_peer_list(self, info_hash, exclude_peer_id=None):
        peers = []
        try:
            if os.path.isfile(SEEDER_FILE_PATH):
                with open(SEEDER_FILE_PATH, 'r') as file:
                    for line in file:
                        entry = eval(line.strip())
                        if entry['info_hash'] == info_hash and entry['peer_id'] != exclude_peer_id:
                            peer_info = {
                                'peer id': entry['peer_id'],
                                'ip': entry['ip'],
                                'port': int(entry['port'])
                            }
                            peers.append(peer_info)
        except Exception as e:
            logging.error(f"Error retrieving peer list: {e}")
        return peers

    def handle_scrape(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        info_hash = query_params.get('info_hash', [None])[0]

        if info_hash:
            info_hash = unquote(info_hash)
            scrape_info = self.get_scrape_info(info_hash)
            if scrape_info:
                encoded_response = bencodepy.encode(scrape_info)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(encoded_response)
            else:
                self.send_error(404, "Not Found")
        else:
            self.send_error(400, "Bad Request")

    def get_scrape_info(self, info_hash):
        try:
            complete = 0
            incomplete = 0
            if os.path.isfile(SEEDER_FILE_PATH):
                with open(SEEDER_FILE_PATH, 'r') as file:
                    for line in file:
                        entry = eval(line.strip())
                        if entry['info_hash'] == info_hash:
                            if entry['left'] == 0:
                                complete += 1
                            else:
                                incomplete += 1
            return {
                'files': {
                    info_hash: {
                        'complete': complete,
                        'incomplete': incomplete,
                        'downloaded': 0  # This can be tracked if needed
                    }
                }
            }
        except Exception as e:
            logging.error(f"Error getting scrape info: {e}")
            return None

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return '127.0.0.1'

def start_tracker(port=6880):
    try:
        server_address = (get_local_ip(), port)
        httpd = HTTPServer(server_address, TrackerRequestHandler)
        logging.info(f"Tracker server is running on {server_address[0]}:{port}")
        httpd.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start tracker server: {e}")

if __name__ == "__main__":
    try:
        start_tracker()
    except KeyboardInterrupt:
        logging.info("Tracker server is shutting down.")