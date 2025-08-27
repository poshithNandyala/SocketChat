// client.cpp
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

static const uint8_t XOR_KEY = 0x55;
static const int UDP_PORT = 5556;

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
    std::string payload;
    payload.resize(len);
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

void reader_thread_fn(int sock) {
    std::string msg;
    while (read_encrypted_message(sock, msg)) {
        std::cout << "\n[remote] " << msg << "\n> " << std::flush;
    }
    std::cerr << "Disconnected from server\n";
    exit(0);
}

void bot_sender_thread(int sock, int id) {
    int cnt = 0;
    while (true) {
        std::string msg = "bot#" + std::to_string(id) + " hello " + std::to_string(cnt++);
        if (!write_encrypted_message(sock, msg)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500 + (id % 50)));
    }
    exit(0);
}

// Simple UDP discovery: sends "DISCOVER" to localhost:UDP_PORT and waits for reply "ip:port"
bool do_udp_discovery(std::string &out_host, int &out_port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(UDP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

    const char* msg = "DISCOVER";
    sendto(sock, msg, strlen(msg), 0, (sockaddr*)&dest, sizeof(dest));
    // set timeout
    timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char buf[256];
    sockaddr_in from{}; socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fromlen);
    close(sock);
    if (n <= 0) return false;
    buf[n] = 0;
    std::string reply(buf);
    // expected format e.g. "127.0.0.1:5555"
    size_t colon = reply.find(':');
    if (colon == std::string::npos) return false;
    out_host = reply.substr(0, colon);
    out_port = atoi(reply.substr(colon + 1).c_str());
    return true;
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    int port = 5555;
    bool bot_mode = false;
    int bot_id = 1;

    // usage:
    // ./client discover          -> attempt UDP discovery then connect
    // ./client <host> <port>     -> connect to given host/port
    // add --bot [id] to make client send messages automatically for testing

    int argi = 1;
    if (argi < argc && std::string(argv[argi]) == "discover") {
        std::string discovered_host;
        int discovered_port;
        std::cout << "Trying UDP discovery...\n";
        if (do_udp_discovery(discovered_host, discovered_port)) {
            host = discovered_host;
            port = discovered_port;
            std::cout << "Discovered server at " << host << ":" << port << "\n";
        } else {
            std::cerr << "Discovery failed, falling back to " << host << ":" << port << "\n";
        }
        argi++;
    } else {
        if (argi < argc) host = argv[argi++];
        if (argi < argc) port = atoi(argv[argi++]);
    }

    // parse optional flags
    while (argi < argc) {
        std::string a(argv[argi++]);
        if (a == "--bot") {
            bot_mode = true;
            if (argi < argc) {
                bot_id = atoi(argv[argi++]);
                if (bot_id <= 0) bot_id = 1;
            }
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &serv.sin_addr);

    if (connect(sock, (sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("connect");
        return 1;
    }
    std::cout << "Connected to " << host << ":" << port << "\n";

    std::thread reader(reader_thread_fn, sock);
    reader.detach();

    if (bot_mode) {
        std::thread bot(bot_sender_thread, sock, bot_id);
        bot.detach();
        // keep main alive
        while (true) std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    std::string line;
    std::cout << "> " << std::flush;
    while (std::getline(std::cin, line)) {
        if (!write_encrypted_message(sock, line)) break;
        std::cout << "> " << std::flush;
    }

    close(sock);
    return 0;
}
