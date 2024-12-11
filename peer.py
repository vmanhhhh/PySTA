import socket
import os
import bencodepy
import threading
import torrent_utils
import requests
import hashlib
import math
import logging
import time
from datetime import datetime
from urllib.parse import urljoin

# Constants
PEER_DIRECTORY = "peer_directory"
INFO_FILE_PREFIX = "info_"
TORRENT_EXTENSION = ".torrent"
TRACKER_ANNOUNCE_PATH = "/announce"
TRACKER_SCRAPE_PATH = "/scrape"
BUFFER_SIZE = 1024

# Constants
LOG_DIR = "log_peer"
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"peer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging to write to a file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

class Peer:
    def __init__(self):
        self.listen_socket = None 
        self.port = None
        self.bytes = 0
    
    def find_available_port(self, start_port=6881, end_port=65535):
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind((get_local_ip(), port))
                return port
            except OSError:
                continue
        return None

    def store_file_path(self, string):
        file_name = f"{INFO_FILE_PREFIX}{self.port}.txt"
        file_path = os.path.join(PEER_DIRECTORY, file_name)
        os.makedirs(PEER_DIRECTORY, exist_ok=True)
        unique_strings = set()

        try:
            with open(file_path, 'r') as file:
                for line in file:
                    unique_strings.add(line.strip())
        except FileNotFoundError:
            pass

        unique_strings.add(string)

        with open(file_path, 'w') as file:
            for unique_string in unique_strings:
                file.write(unique_string + '\n')

    def generate_torrent_file(self, file_path, file_dir, tracker_url):
        file_name = os.path.basename(file_path)
        self.store_file_path(file_path)
        logging.info(f"Creating torrent file for {file_name}...")
        torrent_utils.create_torrent(file_path, tracker_url, os.path.join(file_dir, f'{file_name}{TORRENT_EXTENSION}'))

    def announce_torrent_to_tracker(self, file_path, tracker_url):
        try:
            with open(file_path, 'rb') as torrent_file:
                torrent_data = torrent_file.read()
            
            info_hash = str(hashlib.sha1(torrent_data).hexdigest())
            tracker_url = tracker_url.replace('/announce', '')
            tracker_url = f"{tracker_url}{TRACKER_ANNOUNCE_PATH}?info_hash={info_hash}"
            params = {"port": self.port}
            response = requests.get(tracker_url, params=params)
            if response.status_code == 200:
                logging.info("Announce to tracker successfully.")
                logging.info(f"Tracker response: {response.text}")
            else:
                logging.error(f"Failed to announce to tracker. Status code: {response.status_code}")
                logging.error(f"Tracker response: {response.text}")
        except Exception as e:
            logging.error(f"Error announceing torrent file: {e}")
    def check_peer_active(self, ip_address):
        peer_ip, peer_port = ip_address
        try:
            with socket.create_connection((peer_ip, peer_port), timeout=5) as sock:
                sock.sendall(b"PING")
                response = sock.recv(4)
                if response:
                    return True
        except Exception as e:
            logging.error(f"Error checking peer {ip_address}: {e}")
        return False
    def ping_peer(self, ip_address):
        peer_ip, peer_port = ip_address
        try:
            start_time = time.time()
            with socket.create_connection((peer_ip, peer_port), timeout=5) as sock:
                sock.sendall(b"PING")
                response = sock.recv(4)
                if response:
                    end_time = time.time()
                    response_time = end_time - start_time
                    logging.info(f"Ping to {peer_ip}:{peer_port} successful. Response time: {response_time:.4f} seconds.")
                    return response_time
        except Exception as e:
            logging.error(f"Error checking peer {peer_ip}:{peer_port}: {e}")
        logging.error(f"Ping to {peer_ip}:{peer_port} failed.")
        return None
    def start_multiple_downloads(self, torrent_files, destination):
        threads = []
        for torrent_file in torrent_files:
            thread = threading.Thread(target=self.retrieve_torrent_file, args=(torrent_file, destination))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def measure_bandwidth(self, ip_address):
        peer_ip, peer_port = ip_address
        try:
            start_time = time.time()
            with socket.create_connection((peer_ip, peer_port), timeout=5) as sock:
                sock.sendall(b"PING")
                response = sock.recv(1024)
                if response:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    bandwidth = len(response) / elapsed_time
                    logging.info(f"Measured bandwidth for {peer_ip}:{peer_port} is {bandwidth:.2f} bytes/second.")
                    return bandwidth
        except Exception as e:
            logging.error(f"Error measuring bandwidth for {peer_ip}:{peer_port}: {e}")
        return 0
    def retrieve_torrent_file(self, torrent_file_path, destination):
        torrent_file_name = os.path.basename(torrent_file_path)
        file_name_without_extension = os.path.splitext(torrent_file_name)[0]
        file_path = os.path.join(destination, file_name_without_extension)
        destination = file_path
        try:
            with open(torrent_file_path, 'rb') as torrent_file:
                torrent_data = torrent_file.read()
            
            decoded_torrent = bencodepy.decode(torrent_data)
            decoded_str_keys = {torrent_utils.bytes_to_str(k): v for k, v in decoded_torrent.items()}

            info_hash = str(hashlib.sha1(torrent_data).hexdigest())
            announce_url = decoded_torrent[b"announce"].decode()

                
            try:
                announce_url_down = announce_url.replace("/announce", "/scrape")
                response = requests.get(announce_url_down, params={"info_hash": info_hash})
                if response.status_code == 200:
                    ip_port_pairs = response.text.split(",")
                    formatted_ip_addresses = []
                    
                    for pair in ip_port_pairs:
                        ip, port = pair.strip().split(":")
                        if port != self.port:
                            formatted_ip_addresses.append((ip, int(port)))
                    logging.info("Formatted IP addresses: %s", formatted_ip_addresses)
                    active_peers = [ip for ip in formatted_ip_addresses if self.check_peer_active(ip)]
                    logging.info(f"Total peers: {len(formatted_ip_addresses)}")
                    logging.info(f"Active peers: {active_peers}")

                    if not active_peers:
                        logging.error("No active peers found.")
                        return
                    # Measure bandwidth for each active peer
                    peer_bandwidths = {ip: self.measure_bandwidth(ip) for ip in active_peers}
                    sorted_peers = sorted(peer_bandwidths.items(), key=lambda item: item[1], reverse=True)
                    logging.info(f"Peers sorted by bandwidth: {sorted_peers}")

                    threads = []
                    total_pieces = math.ceil(decoded_str_keys["info"][b"length"] / decoded_str_keys["info"][b"piece length"])
                    logging.info(f"Total pieces: {total_pieces}")
                    start_piece = 0
                    start_time = time.time()
                    for ip_address, bandwidth in sorted_peers:
                        pieces_per_thread = max(1, int(total_pieces * (bandwidth / sum(peer_bandwidths.values()))))
                        end_piece = start_piece + pieces_per_thread
                        if end_piece > total_pieces:
                            end_piece = total_pieces
                        thread = threading.Thread(target=self.download_range, args=(ip_address, torrent_data, destination, start_piece, end_piece, announce_url, total_pieces))
                        threads.append(thread)
                        start_piece = end_piece
                        thread.start()
                    # Wait for all threads to finish
                    for thread in threads:
                        thread.join()
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    logging.info(f"Time elapsed {elapsed_time:.2f} seconds")

                else:
                    logging.error("Error:", response.status_code)
            except Exception as e:
                logging.error(f"Error connecting to tracker: {e}")
        except Exception as e:
            logging.error(f"Error downloading torrent file: {e}")

    def download_range(self, ip_address, file_data, destination, start_piece, end_piece, announce_url, total_pieces):
        for piece in range(start_piece, end_piece):
            self.download_piece(ip_address, file_data, destination, str(piece), announce_url, total_pieces)

    def download_piece(self, ip_address, file_data, destination, piece, announce_url, total_pieces):
        peer_ip, peer_port = ip_address
        sock = socket.create_connection((peer_ip, peer_port))
        
        sha1 = str(hashlib.sha1(file_data).hexdigest())
        payload = sha1 + " " + announce_url
        sock.sendall(payload.encode('utf-8'))
        
        response = sock.recv(1024).decode('utf-8')
        if response == "OK":
            # send interested message
            interested_payload = (2).to_bytes(4, "big") + (2).to_bytes(1, "big")
            sock.send(interested_payload)
            # received unchoke message
            unchoke_msg = sock.recv(5)
            logging.info(f"Received unchoke message from {ip_address}: {unchoke_msg}")
            message_length, message_id = self.decode_peer_message(unchoke_msg)
            if message_id != 1:
                raise SystemError("Expecting unchoke id of 1")

            decoded_torrent = bencodepy.decode(file_data)
            decoded_str_keys = {torrent_utils.bytes_to_str(k): v for k, v in decoded_torrent.items()}
            
            bit_size = 16 * 1024
            final_block = b""
            piece_length = decoded_str_keys["info"][b"piece length"]
            total_length = decoded_str_keys["info"][b"length"]
            if int(piece) == math.ceil(total_length / piece_length) - 1:
                piece_length = total_length % piece_length
            
            piece_filename = f"{destination}_piece_{piece}"
            
            for offset in range(0, piece_length, bit_size):
                block_length = min(bit_size, piece_length - offset)
                request_data = (
                    int(piece).to_bytes(4, "big")
                    + offset.to_bytes(4, "big")
                    + block_length.to_bytes(4, "big")
                )
                request_payload = (
                    (len(request_data) + 1).to_bytes(4, "big")
                    + (6).to_bytes(1, "big")
                    + request_data
                )
                sock.send(request_payload)

                message_length = int.from_bytes(sock.recv(4), "big")
                message_id = int.from_bytes(sock.recv(1), "big")
                if message_id != 7:
                    logging.error(f"Unexpected message ID: {message_id}, expected 7 (piece)")
                    return
                int.from_bytes(sock.recv(4), "big")
                int.from_bytes(sock.recv(4), "big")
                received = 0
                full_block = b""
                size_of_block = message_length - 9
                while received < size_of_block:
                    block = sock.recv(size_of_block - received)
                    full_block += block
                    received += len(block)
                final_block += full_block
                logging.info(f"Downloading piece {piece}, offset {offset}, block length {block_length} from {ip_address}")
        
        try:
            with open(piece_filename, "wb") as f:
                f.write(final_block)
        except Exception as e:
            logging.error(e)

        downloaded_pieces = [f"{destination}_piece_{piece}" for piece in range(total_pieces)]
        d = len(list(piece_file for piece_file in downloaded_pieces if os.path.exists(piece_file)))

        logging.info(f"Downloaded {d} pieces out of {len(downloaded_pieces)}")
        if all(os.path.exists(piece_file) for piece_file in downloaded_pieces):
            self.combine_pieces_into_file(destination, total_pieces)
            self.bytes += total_length  # Cập nhật số byte đã tải
            logging.info("Download completed.")


    def fetch_piece_from_peer(self, ip_address, file_data, destination, piece, announce_url, total_pieces):
        peer_ip, peer_port = ip_address
        sock = socket.create_connection((peer_ip, peer_port))
        
        sha1 = str(hashlib.sha1(file_data).hexdigest())
        payload = sha1 + " " + announce_url
        sock.sendall(payload.encode('utf-8'))
        
        response = sock.recv(BUFFER_SIZE).decode('utf-8')
        if response == "OK":
            interested_payload = (2).to_bytes(4, "big") + (2).to_bytes(1, "big")
            sock.send(interested_payload)
            unchoke_msg = sock.recv(5)
            logging.info(f"Received unchoke message from {ip_address}: {unchoke_msg}")
            message_length, message_id = self.decode_peer_message(unchoke_msg)
            if message_id != 1:
                logging.error(f"Unexpected message ID: {message_id}, expected 1 (unchoke)")
                return

            decoded_torrent = bencodepy.decode(file_data)
            decoded_str_keys = {torrent_utils.bytes_to_str(k): v for k, v in decoded_torrent.items()}
            
            bit_size = 16 * 1024
            final_block = b""
            piece_length = decoded_str_keys["info"][b"piece length"]
            total_length = decoded_str_keys["info"][b"length"]
            if int(piece) == math.ceil(total_length / piece_length) - 1:
                piece_length = total_length % piece_length
            
            piece_filename = f"{destination}_piece_{piece}"
            
            for offset in range(0, piece_length, bit_size):
                block_length = min(bit_size, piece_length - offset)
                request_data = (
                    int(piece).to_bytes(4, "big")
                    + offset.to_bytes(4, "big")
                    + block_length.to_bytes(4, "big")
                )
                request_payload = (
                    (len(request_data) + 1).to_bytes(4, "big")
                    + (6).to_bytes(1, "big")
                    + request_data
                )
                sock.send(request_payload)

                message_length = int.from_bytes(sock.recv(4), "big")
                message_id = int.from_bytes(sock.recv(1), "big")
                if message_id != 7:
                    logging.error(f"Unexpected message ID: {message_id}, expected 7 (piece)")
                    return
                int.from_bytes(sock.recv(4), "big")
                int.from_bytes(sock.recv(4), "big")
                received = 0
                full_block = b""
                size_of_block = message_length - 9
                while received < size_of_block:
                    block = sock.recv(size_of_block - received)
                    full_block += block
                    received += len(block)
                final_block += full_block
                logging.info(f"Downloading piece {piece}, offset {offset}, block length {block_length} from {ip_address}")
        
        try:
            with open(piece_filename, "wb") as f:
                f.write(final_block)
        except Exception as e:
            logging.error(e)

        downloaded_pieces = [f"{destination}_piece_{piece}" for piece in range(total_pieces)]
        d = len(list(piece_file for piece_file in downloaded_pieces if os.path.exists(piece_file)))

        logging.info(f"Downloaded {d} pieces out of {len(downloaded_pieces)}")
        if all(os.path.exists(piece_file) for piece_file in downloaded_pieces):
            self.combine_pieces_into_file(destination, total_pieces)
            self.bytes += total_length
            logging.info("Download completed.")

    def decode_peer_message(self, peer_message):
        message_length = int.from_bytes(peer_message[:4], "big")
        message_id = int.from_bytes(peer_message[4:5], "big")
        return message_length, message_id

    def process_peer_request(self, client_socket, client_address):
        try:
            data = client_socket.recv(BUFFER_SIZE)
            logging.info(f"Received data from {client_address}: {data}")

            if data:
                decoded_data = data.decode('utf-8')
                parts = decoded_data.split(' ', 1)
                if len(parts) == 2:
                    data, url = parts
                    logging.info(f"Data: {data}")
                    logging.info(f"URL: {url}")
                else:
                    data = parts[0]
                    url = None
                    logging.info(f"Info hash: {data}")
                    logging.info("URL not provided")

                found_files = self.locate_file_by_infohash(data, url)
                logging.info(f"Found files: {found_files}")
                if found_files:
                    client_socket.sendall(b"OK")
                    client_socket.recv(BUFFER_SIZE).decode()
                    unchoke_payload = self.generate_unchoke_message()
                    client_socket.sendall(unchoke_payload)
                    while True:
                        request_length = int.from_bytes(client_socket.recv(4), "big")
                        request_id = int.from_bytes(client_socket.recv(1), "big")
                        logging.info(f"Received request ID: {request_id}")
                        if request_id != 6:
                            logging.info("Download completed. Closing connection.")
                            break
                        
                        request_data = client_socket.recv(request_length - 1)
                        piece_index = int.from_bytes(request_data[:4], "big")
                        offset = int.from_bytes(request_data[4:8], "big")
                        block_length = int.from_bytes(request_data[8:], "big")
                        
                        response_data = self.handle_piece_request(piece_index, offset, block_length, found_files[0])
                        
                        response_length = len(response_data) + 9
                        response_payload = (
                            response_length.to_bytes(4, "big")
                            + (7).to_bytes(1, "big")
                            + piece_index.to_bytes(4, "big")
                            + offset.to_bytes(4, "big")
                            + response_data
                        )
                        client_socket.sendall(response_payload)
                else:
                    client_socket.sendall(b"NOT FOUND")
            else:
                logging.error("Cannot extract info hash from handshake data.")
        except Exception as e:
            logging.error(f"Error handling peer request: {e}")

    def load_stored_file_paths(self):
        file_name = f"{INFO_FILE_PREFIX}{self.port}.txt"
        file_path = os.path.join(PEER_DIRECTORY, file_name)   
        strings = []

        try:
            with open(file_path, 'r') as file:
                for line in file:
                    strings.append(line.strip())
        except FileNotFoundError:
            pass

        return strings

    def locate_file_by_infohash(self, infohash, url):
        found_files = []
        file_paths = self.load_stored_file_paths()
        for file_path in file_paths:
            try:
                os.access(file_path, os.R_OK)
                calculated_infohash = torrent_utils.get_info_hash(file_path, url)
                logging.info(f"Calculated info hash: {calculated_infohash}")
                logging.info(f"Received info hash: {infohash}")
                if calculated_infohash == infohash:
                    found_files.append(file_path)
            except PermissionError:
                pass
            except FileNotFoundError:
                pass

        return found_files

    def generate_unchoke_message(self):
        message_length = (1).to_bytes(4, "big")
        message_id = (1).to_bytes(1, "big")
        unchoke_payload = message_length + message_id
        return unchoke_payload

    def handle_piece_request(self, piece_index, offset, block_length, file_path, piece_length=2**20):
        with open(file_path, "rb") as file:
            piece_start_position = piece_index * piece_length + offset
            file.seek(piece_start_position)
            logging.info(f"Reading piece {piece_index}, offset {offset}, block length {block_length}")
            data = file.read(block_length)
        return data

    def combine_pieces_into_file(self, destination, total_pieces):
        try:
            with open(destination, "wb") as f_dest:
                for piece_index in range(total_pieces):
                    piece_filename = f"{destination}_piece_{piece_index}"
                    if os.path.exists(piece_filename):
                        with open(piece_filename, "rb") as f_piece:
                            f_dest.write(f_piece.read())
                        os.remove(piece_filename)
                    else:
                        logging.error(f"Temporary file {piece_filename} not found")
            logging.info(f"Merged temporary files into {destination}")
        except Exception as e:
            logging.error(f"Error merging temporary files: {e}")

    def display_help(self):
        help_text = """
        Available commands:
        - create <file_path> <file_dir> <tracker_url>: Create a torrent file.
        - announce <torrent_file_path> <tracker_url>: Announce a torrent file to the tracker.
        - download <torrent_file_path> <destination>: Download a file using a torrent.
        - downloads <torrent_file1> <torrent_file2> ... <destination>: Download multiple files using torrents
        - scrape <torrent_file_path> <tracker_url>: Scrape the tracker for torrent information.
        - create_announce <file_path> <file_dir> <tracker_url>: Create a torrent file and announce it to the tracker.
        - ping <ip_address>: Ping a peer.
        - stop: Stop the peer and exit.
        - help: Display this help message.
        """
        print(help_text)

    def scrape_torrent_info(self, torrent_file_path, tracker_url):
        try:
            with open(torrent_file_path, 'rb') as torrent_file:
                torrent_data = torrent_file.read()
            
            info_hash = str(hashlib.sha1(torrent_data).hexdigest())
            if not tracker_url.endswith('/'):
                tracker_url += '/'
            scrape_url = urljoin(tracker_url, TRACKER_SCRAPE_PATH)
            scrape_url = f"{scrape_url}?info_hash={info_hash}"
            logging.info(f"Scraping tracker for torrent info: {scrape_url}")
            response = requests.get(scrape_url)
            if response.status_code == 200:
                logging.info(f"Scrape successful: {response.text}")
            else:
                logging.error(f"Failed to scrape tracker. Status code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error scraping torrent info: {e}")

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    peer = Peer()
    try:
        peer.port = peer.find_available_port()
        logging.info(f"Peer is listening on {get_local_ip()}:{peer.port}")
        peer.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.listen_socket.bind((get_local_ip(), peer.port))
        peer.listen_socket.listen(5)

        def handle_user_input():
            while True:
                command = input("\nEnter command: ")
                command_parts = command.split()

                if command.lower() == "stop":
                    logging.info(f"Number of bytes downloaded: {peer.bytes}")
                    logging.info(f"Number of megabytes downloaded: {peer.bytes / (1024 * 1024):.2f}")
                    peer.listen_socket.close()
                    break
                elif command.lower() == "help":
                    peer.display_help()
                elif command.startswith("downloads"):
                    if len(command_parts) >= 3:
                        torrent_files = [file.strip('"\'') for file in command_parts[1:-1]]
                        destination = command_parts[-1].strip('"\'')
                        peer.start_multiple_downloads(torrent_files, destination)
                    else:
                        logging.error("Invalid command: Missing arguments for downloads.")
                elif command.startswith("create_announce"):
                    if len(command_parts) >= 4:
                        file_path = command_parts[1].strip('"\'')
                        file_dir = command_parts[2].strip('"\'')
                        tracker_url = command_parts[3]
                        peer.generate_torrent_file(file_path, file_dir, tracker_url)
                        logging.info(f"Torrent file created for {file_path}")
                        torrent_file_path = os.path.join(file_dir, f'{os.path.basename(file_path)}{TORRENT_EXTENSION}')
                        if os.path.isfile(torrent_file_path):
                            peer.announce_torrent_to_tracker(torrent_file_path, tracker_url)
                        else:
                            logging.error("Error: Torrent file not found after creation.")
                    else:
                        logging.error("Invalid command: Missing arguments for create_announce.")
                elif command.startswith("create"):
                    if len(command_parts) >= 4:
                        file_path = command_parts[1].strip('"\'')
                        file_dir = command_parts[2].strip('"\'')
                        url = command_parts[3]
                        peer.generate_torrent_file(file_path, file_dir, url)
                        logging.info(f"Torrent file created for {file_path}")
                    else:
                        logging.error("Invalid command: Missing arguments for create.")
                elif command.startswith("announce"):
                    if len(command_parts) >= 3:
                        torrent_file_path = command_parts[1].strip('"\'')
                        tracker_url = command_parts[2]
                        if os.path.isfile(torrent_file_path):
                            peer.announce_torrent_to_tracker(torrent_file_path, tracker_url)
                        else:
                            logging.error("Error: Torrent file not found.")
                    else:
                        logging.error("Invalid command: Missing arguments for announce.")
                elif command.startswith("download"):
                    if len(command_parts) >= 3:
                        torrent_file_path = command_parts[1].strip('"\'')
                        destination = command_parts[2].strip('"\'')
                        if os.path.isfile(torrent_file_path):
                            peer.retrieve_torrent_file(torrent_file_path, destination)
                        else:
                            logging.error("Error: Torrent file not found.")
                    else:
                        logging.error("Invalid command: Missing arguments for download.")
                elif command.startswith("scrape"):
                    if len(command_parts) >= 3:
                        torrent_file_path = command_parts[1].strip('"\'')
                        tracker_url = command_parts[2]
                        if os.path.isfile(torrent_file_path):
                            peer.scrape_torrent_info(torrent_file_path, tracker_url)
                        else:
                            logging.error("Error: Torrent file not found.")
                    else:
                        logging.error("Invalid command: Missing arguments for scrape.")
                elif command.startswith("ping"):
                    if len(command_parts) == 2:
                        ip_address = command_parts[1]
                        peer_ip, peer_port = ip_address.split(':')
                        peer.ping_peer((peer_ip, int(peer_port)))
                    else:
                        logging.error("Invalid command: Missing IP address for ping.")
                else: 
                    logging.error("Invalid command. Type 'help' for a list of commands.")

        user_input_thread = threading.Thread(target=handle_user_input)
        user_input_thread.start()

        while True:
            client_socket, client_address = peer.listen_socket.accept()
            logging.info(f"Accepted connection from {client_address}")
            threading.Thread(target=peer.process_peer_request, args=(client_socket, client_address)).start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")