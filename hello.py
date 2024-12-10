    def process_peer_request(self, client_socket, client_address):
        try:
            data = client_socket.recv(BUFFER_SIZE)
            logging.info(f"Received data from {client_address}: {data}")

            if data:
                decoded_data = data.decode('utf-8')
                parts = decoded_data.split(' ', 1)
                if len(parts) == 2:
                    info_hash, url = parts
                    logging.info(f"Info hash: {info_hash}")
                    logging.info(f"URL: {url}")
                else:
                    info_hash = parts[0]
                    url = None
                    logging.info(f"Info hash: {info_hash}")
                    logging.info("URL not provided")

                found_files = self.locate_file_by_infohash(info_hash, url)
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