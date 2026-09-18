#include "channel.hpp"

#include <cstring>

#include "net.hpp"

namespace npxf {
namespace {

const char kMagic[4] = {'N', 'P', 'X', 'F'};
constexpr size_t kRecordHdr = 4;

struct Derived {
    crypto::Key c2s{}, s2c{}, cfm{};
    ~Derived() {
        crypto::secure_zero(c2s.data(), c2s.size());
        crypto::secure_zero(s2c.data(), s2c.size());
        crypto::secure_zero(cfm.data(), cfm.size());
    }
};

void expand_label(const uint8_t prk[32], std::string_view label, const crypto::Hash &h,
                  crypto::Key &out) {
    Bytes info;
    info.reserve(label.size() + h.size());
    info.insert(info.end(), label.begin(), label.end());
    info.insert(info.end(), h.begin(), h.end());
    crypto::hkdf_expand(prk, byte_span(info), out.data(), out.size());
}

// Shared by both sides: given our secret, the peer's ephemeral and the
// transcript hash, produce the three session keys.
void derive(const crypto::Key &psk, const uint8_t sk[32], const uint8_t peer[32],
            const crypto::Hash &h2, Derived &out) {
    uint8_t dh[32];
    if (!crypto::x25519(sk, peer, dh)) fail("handshake: peer sent a small-order public key");

    uint8_t prk[32];
    crypto::hkdf_extract(std::span<const uint8_t>(psk.data(), psk.size()),
                         std::span<const uint8_t>(dh, sizeof dh), prk);
    expand_label(prk, "npxf c2s v1", h2, out.c2s);
    expand_label(prk, "npxf s2c v1", h2, out.s2c);
    expand_label(prk, "npxf cfm v1", h2, out.cfm);

    crypto::secure_zero(dh, sizeof dh);
    crypto::secure_zero(prk, sizeof prk);
}

void confirm_tag(const crypto::Key &cfm, std::string_view who, uint8_t out[32]) {
    crypto::hmac_sha256(std::span<const uint8_t>(cfm.data(), cfm.size()), byte_span(who), out);
}

crypto::Hash transcript_start() {
    return crypto::Sha256::hash(byte_span(std::string_view("npxf-handshake-v1")));
}

crypto::Hash absorb(const crypto::Hash &h, const uint8_t *p, size_t n) {
    crypto::Sha256 s;
    s.update(h.data(), h.size());
    s.update(p, n);
    crypto::Hash out{};
    s.finish(out.data());
    return out;
}

}  // namespace

crypto::Key derive_psk(std::span<const uint8_t> token) {
    if (token.empty()) fail("authentication token is empty");
    crypto::Key psk{};
    crypto::hmac_sha256(byte_span(std::string_view("npxf token v1")), token, psk.data());
    return psk;
}

// ------------------------------------------------------------------- client

void client_handshake(int fd, std::span<const uint8_t> token, SessionKeys &out) {
    crypto::Key psk = derive_psk(token);
    net::set_timeout(fd, kHandshakeTimeoutMs);

    uint8_t ce_sk[32], ce_pk[32];
    crypto::random_bytes(ce_sk, sizeof ce_sk);
    crypto::x25519_base(ce_sk, ce_pk);

    uint8_t msg1[kHandshakeMsg1];
    std::memcpy(msg1, kMagic, 4);
    msg1[4] = kProtocolVersion;
    msg1[5] = msg1[6] = msg1[7] = 0;
    std::memcpy(msg1 + 8, ce_pk, 32);
    net::write_full(fd, msg1, sizeof msg1);

    crypto::Hash h1 = absorb(transcript_start(), msg1, sizeof msg1);

    uint8_t msg2[kHandshakeMsg2];
    if (!net::read_full(fd, msg2, sizeof msg2))
        fail("handshake: server closed the connection (wrong token, or not an npxf server)");

    const uint8_t *se_pk = msg2;
    crypto::Hash h2 = absorb(h1, se_pk, 32);

    Derived d;
    derive(psk, ce_sk, se_pk, h2, d);
    crypto::secure_zero(ce_sk, sizeof ce_sk);

    uint8_t want[32];
    confirm_tag(d.cfm, "server", want);
    if (!crypto::ct_eq(want, msg2 + 32, 32))
        fail("handshake: server authentication failed -- token mismatch, or the connection was "
             "intercepted");

    uint8_t msg3[kHandshakeMsg3];
    confirm_tag(d.cfm, "client", msg3);
    net::write_full(fd, msg3, sizeof msg3);

    out.send = d.c2s;
    out.recv = d.s2c;
    net::set_timeout(fd, 0);
    crypto::secure_zero(psk.data(), psk.size());
}

// ------------------------------------------------------------------- server

void server_handshake(int fd, std::span<const uint8_t> token, SessionKeys &out) {
    crypto::Key psk = derive_psk(token);
    net::set_timeout(fd, kHandshakeTimeoutMs);

    uint8_t msg1[kHandshakeMsg1];
    if (!net::read_full(fd, msg1, sizeof msg1)) fail("handshake: client closed the connection");
    if (std::memcmp(msg1, kMagic, 4) != 0) fail("handshake: bad magic (not an npxf client)");
    if (msg1[4] != kProtocolVersion)
        fail("handshake: unsupported protocol version " + std::to_string(msg1[4]) + " (we speak " +
             std::to_string(kProtocolVersion) + ")");

    const uint8_t *ce_pk = msg1 + 8;
    crypto::Hash h1 = absorb(transcript_start(), msg1, sizeof msg1);

    uint8_t se_sk[32], se_pk[32];
    crypto::random_bytes(se_sk, sizeof se_sk);
    crypto::x25519_base(se_sk, se_pk);
    crypto::Hash h2 = absorb(h1, se_pk, 32);

    Derived d;
    derive(psk, se_sk, ce_pk, h2, d);
    crypto::secure_zero(se_sk, sizeof se_sk);

    uint8_t msg2[kHandshakeMsg2];
    std::memcpy(msg2, se_pk, 32);
    confirm_tag(d.cfm, "server", msg2 + 32);
    net::write_full(fd, msg2, sizeof msg2);

    uint8_t msg3[kHandshakeMsg3], want[32];
    if (!net::read_full(fd, msg3, sizeof msg3))
        fail("handshake: client hung up before confirming (probably a token mismatch)");
    confirm_tag(d.cfm, "client", want);
    if (!crypto::ct_eq(want, msg3, 32)) fail("handshake: client authentication failed (bad token)");

    out.send = d.s2c;
    out.recv = d.c2s;
    net::set_timeout(fd, 0);
    crypto::secure_zero(psk.data(), psk.size());
}

// -------------------------------------------------------------- record layer

Channel::Channel(int fd, SessionKeys &keys, size_t max_payload)
    : fd_(fd), ks_(keys.send), kr_(keys.recv), max_(max_payload) {
    if (max_ > kMaxRecordPayload) max_ = kMaxRecordPayload;
}

namespace {

void make_nonce(uint64_t counter, uint8_t nonce[crypto::kNonceLen]) {
    std::memset(nonce, 0, 4);
    st64(nonce + 4, counter);
}

}  // namespace

void Channel::send(const uint8_t *p, size_t n) {
    if (n > max_) fail("outgoing record of " + std::to_string(n) + " bytes exceeds the channel limit");

    std::lock_guard<std::mutex> lk(send_mu_);
    sbuf_.resize(kRecordHdr + n + crypto::kTagLen);
    st32(sbuf_.data(), uint32_t(n + crypto::kTagLen));

    uint8_t nonce[crypto::kNonceLen];
    make_nonce(nsend_, nonce);
    crypto::aead_seal(ks_.data(), nonce, std::span<const uint8_t>(sbuf_.data(), kRecordHdr), p, n,
                      sbuf_.data() + kRecordHdr, sbuf_.data() + kRecordHdr + n);
    nsend_++;

    net::write_full(fd_, sbuf_.data(), sbuf_.size());
}

bool Channel::recv(Bytes &out) {
    std::lock_guard<std::mutex> lk(recv_mu_);

    uint8_t hdr[kRecordHdr];
    if (!net::read_full(fd_, hdr, sizeof hdr)) return false;

    uint32_t clen = ld32(hdr);
    if (clen < crypto::kTagLen) fail("malformed record: length " + std::to_string(clen));
    size_t plen = clen - crypto::kTagLen;
    if (plen > max_)
        fail("peer sent a " + std::to_string(plen) + " byte record, limit is " + std::to_string(max_));

    rbuf_.resize(clen);
    if (!net::read_full(fd_, rbuf_.data(), clen)) fail("connection closed mid-record");

    uint8_t nonce[crypto::kNonceLen];
    make_nonce(nrecv_, nonce);
    out.resize(plen);
    if (!crypto::aead_open(kr_.data(), nonce, std::span<const uint8_t>(hdr, kRecordHdr), rbuf_.data(),
                           plen, rbuf_.data() + plen, out.data()))
        fail("record authentication failed -- the stream was tampered with or reordered");
    nrecv_++;
    return true;
}

}  // namespace npxf
