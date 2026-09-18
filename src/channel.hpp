// npxf -- authenticated, encrypted record channel.
//
// Handshake (three flights, one round trip):
//
//     psk = HMAC-SHA256("npxf token v1", token)
//     h0  = SHA256("npxf-handshake-v1")
//
//   c->s   "NPXF" | ver | rsv[3] | CE            (40 bytes)   h1 = SHA256(h0|msg1)
//   s->c   SE | HMAC(k_cfm, "server")            (64 bytes)   h2 = SHA256(h1|SE)
//   c->s   HMAC(k_cfm, "client")                 (32 bytes)
//
//     dh    = X25519(own ephemeral, peer ephemeral)
//     prk   = HKDF-Extract(salt = psk, ikm = dh)
//     k_c2s = HKDF-Expand(prk, "npxf c2s v1" | h2, 32)
//     k_s2c = HKDF-Expand(prk, "npxf s2c v1" | h2, 32)
//     k_cfm = HKDF-Expand(prk, "npxf cfm v1" | h2, 32)
//
// Properties this buys us:
//
//   * The token never appears on the wire, in any form, encrypted or not.
//     Both peers prove possession of it by producing a MAC that depends on it,
//     so there is no bearer credential for a middlebox or a malicious server
//     to capture and replay elsewhere.
//   * Mutual authentication.  A plain bearer token sent to an unauthenticated
//     server would be trivially harvested by an active attacker.
//   * Forward secrecy: the long-lived token cannot decrypt recorded traffic,
//     because the session keys also depend on two fresh ephemeral keys.
//   * Replay and transcript binding: both confirmation MACs cover h2, which
//     covers the protocol version and both ephemeral public keys.
//   * Contributory behaviour: an all-zero X25519 output (a small-order peer
//     key) aborts the handshake.
//
// Record layer, after the handshake:
//
//     len[4] LE  |  ciphertext[len-16]  |  tag[16]
//
// AAD is the four length bytes.  The nonce is 00000000 | LE64(counter) with a
// separate counter per direction, so a nonce is never reused under a key and
// records cannot be reordered, dropped or replayed without the tag failing.
#pragma once

#include <cstddef>
#include <atomic>
#include <mutex>
#include <span>

#include "crypto.hpp"
#include "util.hpp"

namespace npxf {

inline constexpr size_t kHandshakeMsg1 = 40;
inline constexpr size_t kHandshakeMsg2 = 64;
inline constexpr size_t kHandshakeMsg3 = 32;
inline constexpr int kHandshakeTimeoutMs = 15000;
inline constexpr uint8_t kProtocolVersion = 1;

// Ceiling on a single record's plaintext.  The negotiated 9P msize must fit
// inside this; the server clamps msize accordingly.
inline constexpr size_t kMaxRecordPayload = 8u << 20;

struct SessionKeys {
    crypto::Key send{};
    crypto::Key recv{};
    ~SessionKeys() {
        crypto::secure_zero(send.data(), send.size());
        crypto::secure_zero(recv.data(), recv.size());
    }
};

// Both throw on any failure, including a token mismatch.  `fd` must be a
// connected stream socket; neither takes ownership of it.
void client_handshake(int fd, std::span<const uint8_t> token, SessionKeys &out);
void server_handshake(int fd, std::span<const uint8_t> token, SessionKeys &out);

// Turns an arbitrary-length token into the 32-byte pre-shared key.
crypto::Key derive_psk(std::span<const uint8_t> token);

// One Channel per connection.  send() and recv() are each internally
// serialised, so a reader thread and any number of writer threads may share
// one instance -- which is exactly how the server drives it.
class Channel {
  public:
    Channel(int fd, SessionKeys &keys, size_t max_payload);
    ~Channel();
    Channel(const Channel &) = delete;
    Channel &operator=(const Channel &) = delete;

    void send(const uint8_t *p, size_t n);
    void send(std::span<const uint8_t> s) { send(s.data(), s.size()); }

    // Returns false on a clean EOF at a record boundary.  Any other failure --
    // including a tag mismatch, which means tampering -- throws.
    bool recv(Bytes &out);

    size_t max_payload() const { return max_; }
    int fd() const { return fd_; }

  private:
    friend struct ChannelTestAccess;
    void poison();
    std::atomic<bool> dead_{false};
    int fd_;
    crypto::Key ks_{}, kr_{};
    uint64_t nsend_ = 0, nrecv_ = 0;
    size_t max_;
    std::mutex send_mu_, recv_mu_;
    Bytes sbuf_, rbuf_;
};

}  // namespace npxf
