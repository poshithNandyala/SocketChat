// server.cpp (edited with usernames + private messaging)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static const int TCP_PORT = 5555;
static const int UDP_PORT = 5556;
static const uint8_t XOR_KEY = 0x55;
static const uint32_t MAX_MSG = 10 * 1024 * 1024; // 10 MB cap

std::mutex clients_mtx;
std::vector<int> clients;
std::map<int, std::string> usernames; // fd -> username
std::atomic<bool> running{true};

// ---------------- encryption helpers ----------------
ssize_t send_all(int fd, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return (ssize_t)total;
}

bool recv_all(int fd, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
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
    if (len > MAX_MSG) return false;
    uint32_t len_be = htonl(len);
    if (send_all(fd, &len_be, sizeof(len_be)) <= 0) return false;
    if (len && send_all(fd, payload.data(), len) <= 0) return false;
    return true;
}

bool read_encrypted_message(int fd, std::string &out_plain) {
    uint32_t len_be;
    if (!recv_all(fd, &len_be, sizeof(len_be))) return false;
    uint32_t len = ntohl(len_be);
    if (len == 0 || len > MAX_MSG) return false;
    std::string payload;
    payload.resize(len);
    if (!recv_all(fd, &payload[0], len)) return false;

    xor_inplace(payload, XOR_KEY);
    if (payload.size() < 1) return false;
    uint8_t got_check = (uint8_t)payload.back();
    std::string msg = payload.substr(0, payload.size() - 1);
    if (checksum_bytes(msg) != got_check) {
        std::cerr << "Checksum mismatch\n";
        return false;
    }
    out_plain = std::move(msg);
    return true;
}

// ---------------- chat logic ----------------
void broadcast_message(int sender_fd, const std::string &msg) {
    std::vector<int> snapshot;
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        snapshot = clients;
    }
    for (int fd : snapshot) {
        if (fd == sender_fd) continue;
        if (!write_encrypted_message(fd, msg)) {
            std::cerr << "Failed to write, closing fd " << fd << "\n";
            close(fd);
            std::lock_guard<std::mutex> lock(clients_mtx);
            clients.erase(std::remove(clients.begin(), clients.end(), fd), clients.end());
            usernames.erase(fd);
        }
    }
}

void private_message(int sender_fd, const std::string &target_user, const std::string &msg) {
    int target_fd = -1;
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        for (auto &kv : usernames) {
            if (kv.second == target_user) {
                target_fd = kv.first;
                break;
            }
        }
    }
    if (target_fd == -1) {
        write_encrypted_message(sender_fd, "[server]: user not found");
        return;
    }
    std::string fullmsg = "[" + usernames[sender_fd] + " -> you]: " + msg;
    write_encrypted_message(target_fd, fullmsg);
}

void handle_client(int client_fd) {
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        clients.push_back(client_fd);
    }
    std::cerr << "Client connected (fd=" << client_fd << ")\n";

    // First message = username
    std::string username;
    if (!read_encrypted_message(client_fd, username)) {
        close(client_fd);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        usernames[client_fd] = username;
    }
    broadcast_message(client_fd, "[server]: " + username + " joined the chat");

    std::string msg;
    while (running) {
        if (!read_encrypted_message(client_fd, msg)) break;

        // Private message?
        if (msg.rfind("/msg ", 0) == 0) {
            size_t sp1 = msg.find(' ', 5);
            if (sp1 != std::string::npos) {
                std::string target = msg.substr(5, sp1 - 5);
                std::string text = msg.substr(sp1 + 1);
                private_message(client_fd, target, text);
                continue;
            }
        }

        std::string fullmsg = "[" + username + "]: " + msg;
        broadcast_message(client_fd, fullmsg);
    }

    {
        std::lock_guard<std::mutex> lock(clients_mtx);
        clients.erase(std::remove(clients.begin(), clients.end(), client_fd), clients.end());
        usernames.erase(client_fd);
    }
    close(client_fd);
    broadcast_message(client_fd, "[server]: " + username + " left the chat");
    std::cerr << "Client disconnected (fd=" << client_fd << ")\n";
}

// ---------------- UDP discovery ----------------
void udp_discovery_thread() {
    int udpsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpsock < 0) { perror("udp socket"); return; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udpsock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("udp bind");
        close(udpsock);
        return;
    }
    std::cerr << "UDP discovery listening on port " << UDP_PORT << "\n";

    while (running) {
        char buf[256];
        sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(udpsock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fromlen);
        if (n <= 0) continue;
        buf[n] = 0;
        std::string req(buf);
        if (req == "DISCOVER") {
            std::string reply = "127.0.0.1:" + std::to_string(TCP_PORT);
            sendto(udpsock, reply.c_str(), reply.size(), 0, (sockaddr*)&from, fromlen);
            std::cerr << "Responded to discovery\n";
        }
    }
    close(udpsock);
}

int main() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(TCP_PORT);

    if (bind(listen_fd, (sockaddr*)&serv, sizeof(serv)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 128) < 0) { perror("listen"); return 1; }

    std::cerr << "SocketChat TCP server listening on port " << TCP_PORT << "\n";
    std::thread udp_thread(udp_discovery_thread);
    udp_thread.detach();

    while (running) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        std::thread t(handle_client, client_fd);
        t.detach();
    }

    close(listen_fd);
    return 0;
}
