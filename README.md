# PySTA

PySTA is   Simple Torrent-like Application (STA) with the protocols defined by each group, using
the TCP/IP protocol stack and must support multi-direction data transfering (MDDT).

## Features

- The application includes the two types of hosts: tracker and peer.
- A centralized tracker keeps track of multiple peers and stores what pieces of files.
- Through tracker protocol, a peer informs the server as to what files are contained in its local
repository but does not actually transmit file data to the server.
- When a peer requires a file that does not belong to its repository, a request is sent to the
tracker.
- MDDT: The client can download multiple files from multiple source peer at once,
simultaneously.
## Run
To run Tracker
```
python3 tracker.py
```
Tracker URL is: `http://<your_tracker_ip>:6880/announce`
To run Peer
```
python3 peer.py
```
peer0.py is improved version for MDDT requirement.

## Usage
    Available commands:
    - create <file_path> <file_dir> <tracker_url>: Create a torrent file.
    - upload <torrent_file_path> <tracker_url>: Upload a torrent file to the tracker.
    - download <torrent_file_path> <destination>: Download a file using a torrent.
    - stop: Stop the peer and exit.
    - help: Display this help message.