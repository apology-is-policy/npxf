// npxf self-test: crypto known-answer vectors, 9P codec round-trips, and a
// live handshake + record exchange over a socketpair.
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "channel.hpp"
#include "crypto.hpp"
#include "net.hpp"
#include "ninep.hpp"
#include "util.hpp"

namespace npxf {
struct ChannelTestAccess {
    static void exhaust(Channel &c, bool send) {
        if (send) c.nsend_ = UINT64_MAX; else c.nrecv_ = UINT64_MAX;
    }
};
}

using namespace npxf;

namespace {

int g_failed = 0;
int g_ran = 0;

void report(const char *name, bool ok, const std::string &detail = {}) {
    g_ran++;
    if (ok) {
        std::printf("  ok    %s\n", name);
    } else {
        g_failed++;
        std::printf("  FAIL  %s%s%s\n", name, detail.empty() ? "" : ": ", detail.c_str());
    }
}

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            detail = "line " + std::to_string(__LINE__) + ": " #cond;        \
            return false;                                                    \
        }                                                                    \
    } while (0)

// ------------------------------------------------------------------- crypto

void test_crypto() {
    std::string err;
    report("crypto vectors (RFC 8439 / 7748 / 5869 / 4231)", crypto::self_test(&err), err);
}

// -------------------------------------------------------------------- codec

bool codec_roundtrip(std::string &detail) {
    using namespace ninep;
    Bytes b;
    begin(b, Tgetattr, 0x1234);
    {
        Enc e(b);
        e.u32(7);
        e.u64(GETATTR_ALL);
        e.str("hello / world");
        e.qid(Qid{QTDIR, 42, 0xdeadbeefcafe});
        e.str("");
    }
    finish(b);

    Header h = parse(byte_span(b));
    CHECK(h.type == Tgetattr);
    CHECK(h.tag == 0x1234);

    Dec d(h.body);
    CHECK(d.u32() == 7);
    CHECK(d.u64() == GETATTR_ALL);
    CHECK(d.str() == "hello / world");
    Qid q = d.qid();
    CHECK(q.type == QTDIR && q.version == 42 && q.path == 0xdeadbeefcafe);
    CHECK(d.str().empty());
    d.end();
    return true;
}

bool codec_rejects_bad_input(std::string &detail) {
    using namespace ninep;

    // Declared size disagreeing with the buffer must be rejected: this is the
    // check that stops a peer overrunning or under-running our parser.
    Bytes b;
    begin(b, Tclunk, 1);
    Enc(b).u32(5);
    finish(b);
    b[0] = 99;
    bool threw = false;
    try {
        parse(byte_span(b));
    } catch (const ProtoError &) {
        threw = true;
    }
    CHECK(threw);

    // Reading past the end throws rather than reading adjacent memory.
    uint8_t tiny[3] = {1, 2, 3};
    Dec d(tiny, sizeof tiny);
    threw = false;
    try {
        d.u64();
    } catch (const ProtoError &) {
        threw = true;
    }
    CHECK(threw);

    // A string whose declared length runs off the end must not be accepted.
    uint8_t s[4] = {0xff, 0xff, 'a', 'b'};
    Dec d2(s, sizeof s);
    threw = false;
    try {
        d2.str();
    } catch (const ProtoError &) {
        threw = true;
    }
    CHECK(threw);

    // Trailing junk is refused by end().
    Bytes c;
    begin(c, Tclunk, 1);
    Enc(c).u32(5);
    Enc(c).u8(0);
    finish(c);
    Dec d3(parse(byte_span(c)).body);
    d3.u32();
    threw = false;
    try {
        d3.end();
    } catch (const ProtoError &) {
        threw = true;
    }
    CHECK(threw);
    return true;
}

void test_codec() {
    std::string detail;
    report("9P codec round-trip", codec_roundtrip(detail), detail);
    detail.clear();
    report("9P codec rejects malformed input", codec_rejects_bad_input(detail), detail);
}

// --------------------------------------------------------------- token file

// The trim rule is interop surface (util.hpp says why), so it gets a test on
// BOTH sides of the wire.  The twin is `trims_the_line_ending_a_file_carries`
// in Thylacine's usr/haul/src/npxf.rs; the two assert the same cases, because
// the failure mode is the two implementations quietly disagreeing.
bool token_file_trim(std::string &detail) {
    auto trimmed = [](std::string_view s) {
        Bytes b(s.begin(), s.end());
        trim_token_file(b);
        return std::string(b.begin(), b.end());
    };
    CHECK(trimmed("swordfish") == "swordfish");
    CHECK(trimmed("swordfish\n") == "swordfish");
    CHECK(trimmed("swordfish\r\n") == "swordfish");
    CHECK(trimmed("swordfish\n\n\n") == "swordfish");
    CHECK(trimmed("swordfish\r\n\r\n") == "swordfish");
    // Only the line ending is noise.  A space someone actually typed is part
    // of the token, and so is anything in the middle.
    CHECK(trimmed("sword fish\n") == "sword fish");
    CHECK(trimmed("swordfish \n") == "swordfish ");
    CHECK(trimmed("\r\n") == "");
    CHECK(trimmed("") == "");
    return true;
}

void test_token_file() {
    std::string detail;
    report("token file trim rule", token_file_trim(detail), detail);
}

// ------------------------------------------------------------------ channel

struct Pair {
    Fd a, b;
    Pair() {
        int sv[2];
        // No SOCK_CLOEXEC on the BSDs; the selftest never execs, so the
        // flag is a hygiene nicety here rather than a property under test.
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) throw_errno("socketpair");
        a.reset(sv[0]);
        b.reset(sv[1]);
    }
};

bool channel_roundtrip(std::string &detail) {
    Pair p;
    Bytes token = Bytes{'s', 'w', 'o', 'r', 'd', 'f', 'i', 's', 'h'};

    SessionKeys skeys;
    std::string serr;
    std::thread srv([&] {
        try {
            server_handshake(p.b.get(), byte_span(token), skeys);
        } catch (const std::exception &e) {
            serr = e.what();
        }
    });

    SessionKeys ckeys;
    std::string cerr;
    try {
        client_handshake(p.a.get(), byte_span(token), ckeys);
    } catch (const std::exception &e) {
        cerr = e.what();
    }
    srv.join();
    CHECK(serr.empty());
    CHECK(cerr.empty());

    // Each side's send key must equal the other's receive key, and the two
    // directions must use different keys.
    CHECK(ckeys.send == skeys.recv);
    CHECK(ckeys.recv == skeys.send);
    CHECK(ckeys.send != ckeys.recv);

    Channel cc(p.a.get(), ckeys, 1 << 20);
    Channel sc(p.b.get(), skeys, 1 << 20);

    // Round-trip a range of sizes, including empty and non-block-aligned.
    for (size_t n : {size_t(0), size_t(1), size_t(63), size_t(64), size_t(65), size_t(4096),
                     size_t(70001)}) {
        Bytes msg(n);
        for (size_t i = 0; i < n; i++) msg[i] = uint8_t(i * 31 + n);
        std::thread w([&] { cc.send(msg); });
        Bytes got;
        bool ok = sc.recv(got);
        w.join();
        CHECK(ok);
        CHECK(got == msg);
    }

    // And the other direction, to confirm the counters are independent.
    Bytes reply = Bytes{'p', 'o', 'n', 'g'};
    std::thread w([&] { sc.send(reply); });
    Bytes got;
    bool ok = cc.recv(got);
    w.join();
    CHECK(ok);
    CHECK(got == reply);
    return true;
}

bool channel_rejects_bad_token(std::string &detail) {
    Pair p;
    SessionKeys skeys, ckeys;
    std::string serr, cerr;
    Bytes t1 = Bytes{'r', 'i', 'g', 'h', 't'};
    Bytes t2 = Bytes{'w', 'r', 'o', 'n', 'g'};

    std::thread srv([&] {
        try {
            server_handshake(p.b.get(), byte_span(t1), skeys);
        } catch (const std::exception &e) {
            serr = e.what();
        }
    });
    try {
        client_handshake(p.a.get(), byte_span(t2), ckeys);
    } catch (const std::exception &e) {
        cerr = e.what();
    }
    srv.join();

    // The client detects it first -- the server's confirmation MAC will not
    // verify -- and the server then fails too rather than serving anything.
    CHECK(!cerr.empty());
    CHECK(!serr.empty());
    return true;
}

bool channel_detects_tampering(std::string &detail) {
    Pair p;
    Bytes token = Bytes{'k', 'e', 'y'};
    SessionKeys skeys, ckeys;
    std::thread srv([&] { server_handshake(p.b.get(), byte_span(token), skeys); });
    client_handshake(p.a.get(), byte_span(token), ckeys);
    srv.join();

    Channel cc(p.a.get(), ckeys, 1 << 20);

    // Hand-build a record with a corrupted tag and confirm the receiver
    // refuses it instead of returning attacker-chosen plaintext.
    Bytes msg(32, 0xAB);
    std::thread w([&] { cc.send(msg); });

    uint8_t hdr[4];
    CHECK(net::read_full(p.b.get(), hdr, 4));
    uint32_t clen = ld32(hdr);
    Bytes body(clen);
    CHECK(net::read_full(p.b.get(), body.data(), clen));
    w.join();

    body[clen - 1] ^= 0x01;  // flip a bit in the authentication tag

    Pair q;
    Channel sc(q.b.get(), skeys, 1 << 20);
    net::write_full(q.a.get(), hdr, 4);
    net::write_full(q.a.get(), body.data(), body.size());

    bool threw = false;
    Bytes out(50, 0xCC);
    try { (void)sc.recv(out); } catch (const std::exception &) { threw = true; }
    CHECK(threw);
    CHECK(out.empty());
    threw = false;
    try { (void)sc.recv(out); } catch (const std::exception &) { threw = true; }
    CHECK(threw); // immediate refusal, not a read waiting for another record
    threw = false;
    try { sc.send(msg); } catch (const std::exception &) { threw = true; }
    CHECK(threw); // authentication failure is terminal in BOTH directions

    return true;
}

bool channel_rejects_replay(std::string &detail) {
    Pair p;
    Bytes token = Bytes{'k', 'e', 'y'};
    SessionKeys skeys, ckeys;
    std::thread srv([&] { server_handshake(p.b.get(), byte_span(token), skeys); });
    client_handshake(p.a.get(), byte_span(token), ckeys);
    srv.join();

    Channel cc(p.a.get(), ckeys, 1 << 20);
    Bytes msg(16, 0x5A);
    std::thread w([&] { cc.send(msg); });
    uint8_t hdr[4];
    CHECK(net::read_full(p.b.get(), hdr, 4));
    uint32_t clen = ld32(hdr);
    Bytes body(clen);
    CHECK(net::read_full(p.b.get(), body.data(), clen));
    w.join();

    // Record 0 decrypts once.  Replaying the identical bytes must fail,
    // because the receiver has moved on to nonce 1.
    Pair q;
    Channel sc(q.b.get(), skeys, 1 << 20);
    for (int i = 0; i < 2; i++) {
        net::write_full(q.a.get(), hdr, 4);
        net::write_full(q.a.get(), body.data(), body.size());
    }
    Bytes out;
    CHECK(sc.recv(out));
    CHECK(out == msg);
    bool threw = false;
    try {
        (void)sc.recv(out);
    } catch (const std::exception &) {
        threw = true;
    }
    CHECK(threw);
    return true;
}

bool channel_enforces_size_limit(std::string &detail) {
    Pair p;
    Bytes token = Bytes{'k'};
    SessionKeys skeys, ckeys;
    std::thread srv([&] { server_handshake(p.b.get(), byte_span(token), skeys); });
    client_handshake(p.a.get(), byte_span(token), ckeys);
    srv.join();

    Channel cc(p.a.get(), ckeys, 1024);
    Bytes big(2048, 0);
    bool threw = false;
    try {
        cc.send(big);
    } catch (const std::exception &) {
        threw = true;
    }
    CHECK(threw);

    // An oversized length field from the peer must be refused before we
    // allocate a buffer for it.
    Channel sc(p.b.get(), skeys, 1024);
    uint8_t hdr[4];
    st32(hdr, 100u << 20);
    net::write_full(p.a.get(), hdr, 4);
    threw = false;
    try {
        Bytes out;
        (void)sc.recv(out);
    } catch (const std::exception &) {
        threw = true;
    }
    CHECK(threw);
    return true;
}

bool channel_counter_exhaustion(std::string &detail) {
    for (bool send : {false, true}) {
        Pair p;
        SessionKeys keys;
        Channel channel(p.a.get(), keys, 1024);
        ChannelTestAccess::exhaust(channel, send);
        bool threw = false;
        Bytes out;
        try {
            if (send) channel.send(out); else (void)channel.recv(out);
        } catch (const std::exception &) { threw = true; }
        CHECK(threw);
        CHECK(out.empty());
    }
    return true;
}

void test_channel() {
    std::string d;
    report("channel handshake + record round-trip", channel_roundtrip(d), d);
    d.clear();
    report("channel rejects a wrong token", channel_rejects_bad_token(d), d);
    d.clear();
    report("channel detects tampering", channel_detects_tampering(d), d);
    d.clear();
    report("channel rejects replayed records", channel_rejects_replay(d), d);
    d.clear();
    report("channel enforces record size limits", channel_enforces_size_limit(d), d);
    d.clear();
    report("channel rejects exhausted counters", channel_counter_exhaustion(d), d);
}

}  // namespace

int main() {
    std::printf("npxf self-test\n");
    try {
        test_crypto();
        test_codec();
        test_token_file();
        test_channel();
    } catch (const std::exception &e) {
        std::printf("  FAIL  unexpected exception: %s\n", e.what());
        g_failed++;
    }
    std::printf("\n%d test(s), %d failure(s)\n", g_ran, g_failed);
    return g_failed ? 1 : 0;
}
