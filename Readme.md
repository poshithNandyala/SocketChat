# SocketChat

SocketChat is a simple encrypted chat application written in C++ using TCP and UDP sockets. It enables multiple clients to communicate securely with a central server and supports automatic server discovery via UDP.

## Features

- **Encrypted Messaging:** All messages are XOR-encrypted and include a checksum for integrity.
- **Multi-client Support:** Multiple clients can connect and chat concurrently.
- **UDP Discovery:** Clients can automatically locate the server using UDP.
- **POSIX Sockets:** Compatible with Linux/macOS environments and WSL (Windows Subsystem for Linux).

## Project Structure

- `server.cpp` — Server application source code
- `client.cpp` — Client application source code
- `Readme.md` — Project documentation

## Building

Compile using g++ (on Linux or WSL):

```sh
g++ -std=c++11 -o server server.cpp -pthread
g++ -std=c++11 -o client client.cpp -pthread
```

## Usage

### Start the Server

```sh
./server
```
Listens on TCP port `5555` and UDP port `5556`.

### Start the Client

```sh
./client discover
```
Attempts UDP discovery.  
Or connect directly:

```sh
./client <server_ip> <port>
```

> **Note:** These commands are intended for Linux or WSL environments.

### Chatting

- Enter your username when prompted.
- Type messages and press Enter to send.
- Incoming messages are displayed in real time.

## Protocol

- **Encryption:** XOR with key `0x55` and checksum byte.
- **TCP:** Used for chat messages.
- **UDP:** Used for server discovery (`DISCOVER` message).
