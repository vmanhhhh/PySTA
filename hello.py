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
                announce_url_down = announce_url + "/download"
                response = requests.get(announce_url_down, params={"info_hash": info_hash})
                if response.status_code == 200:
                    ip_port_pairs = response.text.split(",")
                    formatted_ip_addresses = []
                    
                    for pair in ip_port_pairs:
                        ip, port = pair.strip().split(":")
                        if port != self.port:
                            formatted_ip_addresses.append((ip, int(port)))
                    logging.info("Formatted IP addresses: %s", formatted_ip_addresses)

                    # Filter out inactive peers
                    active_peers = [ip for ip in formatted_ip_addresses if self.check_peer_active(ip)]
                    logging.info(f"Active peers: {active_peers}")

                    if not active_peers:
                        logging.error("No active peers found.")
                        return

                    threads = []
                    total_pieces = math.ceil(decoded_str_keys["info"][b"length"] / decoded_str_keys["info"][b"piece length"])
                    logging.info(f"Total pieces: {total_pieces}")
                    logging.info(f"Total active peers: {active_peers}")
                    pieces_per_thread = total_pieces // len(active_peers) + 1
                    logging.info(f"Pieces per thread: {pieces_per_thread}")
                    start_piece = 0

                    # Record the start time
                    start_time = time.time()

                    for ip_address in active_peers:
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

                    # Record the end time and calculate elapsed time
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    logging.info(f"Download completed in {elapsed_time:.2f} seconds.")
                else:
                    logging.error("Error: %s", response.status_code)
            except Exception as e:
                logging.error(f"Error connecting to tracker: {e}")
        except Exception as e:
            logging.error(f"Error downloading torrent file: {e}")