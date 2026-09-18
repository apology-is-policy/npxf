// npxf -- thin wrappers over the POSIX socket calls we need.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace npxf::net {

struct Addr {
    std::string host;  // empty means "any" for listen, "localhost" for connect
    std::string port;
};

// Accepts "host:port", "[::1]:port", ":port" and a bare "port".
Addr parse_addr(std::string_view s, std::string_view default_port);

// One listening socket per resolved family (typically v4 + v6).
std::vector<Fd> tcp_listen(const Addr &a, int backlog = 64);
Fd tcp_connect(const Addr &a, int timeout_ms = 15000);

// Created with a 0600 umask so only the owner can connect.
Fd unix_listen(const std::string &path, int backlog = 64);
Fd unix_connect(const std::string &path);

void set_nodelay(int fd);
void set_timeout(int fd, int ms);  // 0 clears; applies to both directions
void set_keepalive(int fd);

// Reads exactly n bytes.  Returns false only on a clean EOF before any byte of
// this call was read; a truncated read part-way through throws.
bool read_full(int fd, uint8_t *p, size_t n);
void write_full(int fd, const uint8_t *p, size_t n);

std::string peer_name(int fd);

}  // namespace npxf::net
