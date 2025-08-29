#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static const uint8_t XOR_KEY = 0x55;
static const int TCP_PORT = 5555;
static const int UDP_PORT = 5556;

std::vector<int> clients;
std::map<int, std::string> client_names;
std::mutex clients_mtx;
std::mutex names_mtx;
std::atomic<bool> running(true);

ssize_t send_all(int fd, const void *buf, size_t len) {
    const char *p = static_cast<const char *>(buf);
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return (ssize_t)total;
}

bool recv_all(int fd, void *buf, size_t len) {
    char *p = static_cast<char *>(buf);
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

uint8_t checksum_bytes(const std::string &s) {
    uint32_t sum = 0;
    for (unsigned char c : s) sum += c;
    return (uint8_t)(sum & 0xFF);
}

void xor_inplace(std::string &s, uint8_t key) {
    for (size_t i = 0; i < s.size(); ++i) s[i] = s[i] ^ (char)key;
}

bool write_encrypted_message(int fd, const std::string &plaintext) {
    std::string payload = plaintext;
    payload.push_back((char)checksum_bytes(plaintext));
    xor_inplace(payload, XOR_KEY);
    uint32_t len = (uint32_t)payload.size();
    uint32_t len_be = htonl(len);
    if (send_all(fd, &len_be, sizeof(len_be)) <= 0) return false;
    if (len && send_all(fd, payload.data(), len) <= 0) return false;
    return true;
}

bool read_encrypted_message(int fd, std::string &out_plain) {
    uint32_t len_be;
    if (!recv_all(fd, &len_be, sizeof(len_be))) return false;
    uint32_t len = ntohl(len_be);
    if (len == 0) return false;
    std::string payload(len, 0);
    if (!recv_all(fd, &payload[0], len)) return false;
    xor_inplace(payload, XOR_KEY);
    if (payload.size() < 1) return false;
    uint8_t got_check = (uint8_t)payload.back();
    std::string msg = payload.substr(0, payload.size() - 1);
    if (checksum_bytes(msg) != got_check) {
        std::cerr << "Checksum mismatch on incoming message\n";
        return false;
    }
    out_plain = std::move(msg);
    return true;
}

void broadcast_message(int sender_fd, const std::string &msg) {
    std::vector<int> snapshot;
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        snapshot = clients;
    }

    std::string sender_name;
    {
        std::lock_guard<std::mutex> lock(names_mtx);
        sender_name = client_names[sender_fd];
    }

    std::string full_msg = sender_name + ": " + msg;

    for (int fd : snapshot) {
        if (fd == sender_fd) continue;
        if (!write_encrypted_message(fd, full_msg)) {
            close(fd);
            std::lock_guard<std::mutex> lock(clients_mtx);
            clients.erase(std::remove(clients.begin(), clients.end(), fd), clients.end());
        }
    }
}

void handle_client(int client_fd) {
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        clients.push_back(client_fd);
    }
    std::cerr << "Client connected (fd=" << client_fd << ")\n";

    std::string msg;
    // first message is username
    if (!read_encrypted_message(client_fd, msg)) {
        close(client_fd);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(names_mtx);
        client_names[client_fd] = msg;
    }
    std::cerr << "Client username: " << msg << "\n";

    while (running) {
        if (!read_encrypted_message(client_fd, msg)) break;
        broadcast_message(client_fd, msg);
    }

    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        clients.erase(std::remove(clients.begin(), clients.end(), client_fd), clients.end());
    }
    {
        std::lock_guard<std::mutex> lock(names_mtx);
        client_names.erase(client_fd);
    }
    close(client_fd);
    std::cerr << "Client disconnected (fd=" << client_fd << ")\n";
}

void udp_discovery_thread() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("udp socket"); return; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("udp bind");
        close(sock);
        return;
    }

    char buf[256];
    while (running) {
        sockaddr_in from{}; socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fromlen);
        if (n <= 0) continue;
        buf[n] = 0;
        if (std::string(buf) == "DISCOVER") {
            std::string reply = "127.0.0.1:" + std::to_string(TCP_PORT);
            sendto(sock, reply.c_str(), reply.size(), 0, (sockaddr*)&from, fromlen);
        }
    }
    close(sock);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        return 1;
    }

    std::thread udp_thread(udp_discovery_thread);
    udp_thread.detach();

    std::cerr << "Server listening on port " << TCP_PORT << "\n";
    while (running) {
        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(server_fd, (sockaddr*)&cli_addr, &cli_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        std::thread(handle_client, client_fd).detach();
    }

    close(server_fd);
    return 0;
}
