#include "crypto.hpp"

#include <cstring>

#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include "util.hpp"

namespace npxf::crypto {
namespace {

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

// =============================================================== SHA-256

namespace {

const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// SHA-256 is big-endian internally; 9P is little-endian.  Keep them separate.
inline uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void put_be32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

}  // namespace

void Sha256::reset() {
    h_[0] = 0x6a09e667;
    h_[1] = 0xbb67ae85;
    h_[2] = 0x3c6ef372;
    h_[3] = 0xa54ff53a;
    h_[4] = 0x510e527f;
    h_[5] = 0x9b05688c;
    h_[6] = 0x1f83d9ab;
    h_[7] = 0x5be0cd19;
    total_ = 0;
    buflen_ = 0;
}

void Sha256::block(const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = be32(p + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void Sha256::update(const uint8_t *p, size_t n) {
    total_ += n;
    if (buflen_) {
        size_t want = 64 - buflen_;
        if (want > n) want = n;
        std::memcpy(buf_ + buflen_, p, want);
        buflen_ += want;
        p += want;
        n -= want;
        if (buflen_ < 64) return;
        block(buf_);
        buflen_ = 0;
    }
    while (n >= 64) {
        block(p);
        p += 64;
        n -= 64;
    }
    if (n) {
        std::memcpy(buf_, p, n);
        buflen_ = n;
    }
}

void Sha256::finish(uint8_t out[kHashLen]) {
    uint64_t bits = total_ * 8;
    uint8_t pad[72];
    size_t padlen = (buflen_ < 56) ? (56 - buflen_) : (120 - buflen_);
    std::memset(pad, 0, padlen);
    pad[0] = 0x80;
    put_be32(pad + padlen, uint32_t(bits >> 32));
    put_be32(pad + padlen + 4, uint32_t(bits));
    update(pad, padlen + 8);
    for (int i = 0; i < 8; i++) put_be32(out + i * 4, h_[i]);
    secure_zero(h_, sizeof h_);
    secure_zero(buf_, sizeof buf_);
}

Hash Sha256::hash(std::span<const uint8_t> in) {
    Hash out{};
    Sha256 s;
    s.update(in);
    s.finish(out.data());
    return out;
}

// ============================================================ HMAC / HKDF

void hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> msg, uint8_t out[kHashLen]) {
    uint8_t k[64];
    std::memset(k, 0, sizeof k);
    if (key.size() > 64) {
        Sha256 s;
        s.update(key);
        s.finish(k);
    } else {
        std::memcpy(k, key.data(), key.size());
    }

    uint8_t pad[64];
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    uint8_t inner[kHashLen];
    {
        Sha256 s;
        s.update(pad, 64);
        s.update(msg);
        s.finish(inner);
    }
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    {
        Sha256 s;
        s.update(pad, 64);
        s.update(inner, kHashLen);
        s.finish(out);
    }
    secure_zero(k, sizeof k);
    secure_zero(pad, sizeof pad);
    secure_zero(inner, sizeof inner);
}

void hkdf_extract(std::span<const uint8_t> salt, std::span<const uint8_t> ikm, uint8_t prk[kHashLen]) {
    static const uint8_t zeros[kHashLen] = {0};
    if (salt.empty()) salt = {zeros, kHashLen};
    hmac_sha256(salt, ikm, prk);
}

void hkdf_expand(const uint8_t prk[kHashLen], std::span<const uint8_t> info, uint8_t *out, size_t outlen) {
    uint8_t t[kHashLen];
    size_t tlen = 0;
    uint8_t counter = 1;
    size_t done = 0;
    while (done < outlen) {
        // T(n) = HMAC(PRK, T(n-1) | info | n)
        uint8_t k[64];
        std::memset(k, 0, sizeof k);
        std::memcpy(k, prk, kHashLen);
        uint8_t pad[64];
        for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
        uint8_t inner[kHashLen];
        {
            Sha256 s;
            s.update(pad, 64);
            if (tlen) s.update(t, tlen);
            s.update(info);
            s.update(&counter, 1);
            s.finish(inner);
        }
        for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
        {
            Sha256 s;
            s.update(pad, 64);
            s.update(inner, kHashLen);
            s.finish(t);
        }
        tlen = kHashLen;
        size_t take = outlen - done;
        if (take > kHashLen) take = kHashLen;
        std::memcpy(out + done, t, take);
        done += take;
        counter++;
        secure_zero(k, sizeof k);
        secure_zero(pad, sizeof pad);
        secure_zero(inner, sizeof inner);
    }
    secure_zero(t, sizeof t);
}

// ================================================================ ChaCha20

namespace {

void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    std::memcpy(x, in, sizeof x);
#define QR(a, b, c, d)                     \
    x[a] += x[b], x[d] ^= x[a], x[d] = rotl32(x[d], 16); \
    x[c] += x[d], x[b] ^= x[c], x[b] = rotl32(x[b], 12); \
    x[a] += x[b], x[d] ^= x[a], x[d] = rotl32(x[d], 8);  \
    x[c] += x[d], x[b] ^= x[c], x[b] = rotl32(x[b], 7)
    for (int i = 0; i < 10; i++) {
        QR(0, 4, 8, 12);
        QR(1, 5, 9, 13);
        QR(2, 6, 10, 14);
        QR(3, 7, 11, 15);
        QR(0, 5, 10, 15);
        QR(1, 6, 11, 12);
        QR(2, 7, 8, 13);
        QR(3, 4, 9, 14);
    }
#undef QR
    for (int i = 0; i < 16; i++) st32(out + i * 4, x[i] + in[i]);
    secure_zero(x, sizeof x);
}

}  // namespace

void chacha20_xor(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t n) {
    uint32_t st[16];
    st[0] = 0x61707865;  // "expa"
    st[1] = 0x3320646e;  // "nd 3"
    st[2] = 0x79622d32;  // "2-by"
    st[3] = 0x6b206574;  // "te k"
    for (int i = 0; i < 8; i++) st[4 + i] = ld32(key + i * 4);
    st[12] = counter;
    for (int i = 0; i < 3; i++) st[13 + i] = ld32(nonce + i * 4);

    uint8_t ks[64];
    while (n >= 64) {
        chacha20_block(st, ks);
        for (int i = 0; i < 64; i++) out[i] = in[i] ^ ks[i];
        st[12]++;
        in += 64;
        out += 64;
        n -= 64;
    }
    if (n) {
        chacha20_block(st, ks);
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
    }
    secure_zero(ks, sizeof ks);
    secure_zero(st, sizeof st);
}

// ================================================================ Poly1305
// poly1305-donna, 32-bit limb variant: h is held as five 26-bit limbs so all
// products fit in a uint64_t with no 128-bit arithmetic and no reduction
// branches.

namespace {

struct Poly1305Ctx {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
    bool final;

    void init(const uint8_t key[32]) {
        r[0] = (ld32(key + 0)) & 0x3ffffff;
        r[1] = (ld32(key + 3) >> 2) & 0x3ffff03;
        r[2] = (ld32(key + 6) >> 4) & 0x3ffc0ff;
        r[3] = (ld32(key + 9) >> 6) & 0x3f03fff;
        r[4] = (ld32(key + 12) >> 8) & 0x00fffff;
        for (int i = 0; i < 5; i++) h[i] = 0;
        for (int i = 0; i < 4; i++) pad[i] = ld32(key + 16 + i * 4);
        leftover = 0;
        final = false;
    }

    void blocks(const uint8_t *m, size_t bytes) {
        const uint32_t hibit = final ? 0 : (1u << 24);
        const uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
        const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

        while (bytes >= 16) {
            h0 += (ld32(m + 0)) & 0x3ffffff;
            h1 += (ld32(m + 3) >> 2) & 0x3ffffff;
            h2 += (ld32(m + 6) >> 4) & 0x3ffffff;
            h3 += (ld32(m + 9) >> 6) & 0x3ffffff;
            h4 += (ld32(m + 12) >> 8) | hibit;

            uint64_t d0 = uint64_t(h0) * r0 + uint64_t(h1) * s4 + uint64_t(h2) * s3 +
                          uint64_t(h3) * s2 + uint64_t(h4) * s1;
            uint64_t d1 = uint64_t(h0) * r1 + uint64_t(h1) * r0 + uint64_t(h2) * s4 +
                          uint64_t(h3) * s3 + uint64_t(h4) * s2;
            uint64_t d2 = uint64_t(h0) * r2 + uint64_t(h1) * r1 + uint64_t(h2) * r0 +
                          uint64_t(h3) * s4 + uint64_t(h4) * s3;
            uint64_t d3 = uint64_t(h0) * r3 + uint64_t(h1) * r2 + uint64_t(h2) * r1 +
                          uint64_t(h3) * r0 + uint64_t(h4) * s4;
            uint64_t d4 = uint64_t(h0) * r4 + uint64_t(h1) * r3 + uint64_t(h2) * r2 +
                          uint64_t(h3) * r1 + uint64_t(h4) * r0;

            uint32_t c;
            c = uint32_t(d0 >> 26);
            h0 = uint32_t(d0) & 0x3ffffff;
            d1 += c;
            c = uint32_t(d1 >> 26);
            h1 = uint32_t(d1) & 0x3ffffff;
            d2 += c;
            c = uint32_t(d2 >> 26);
            h2 = uint32_t(d2) & 0x3ffffff;
            d3 += c;
            c = uint32_t(d3 >> 26);
            h3 = uint32_t(d3) & 0x3ffffff;
            d4 += c;
            c = uint32_t(d4 >> 26);
            h4 = uint32_t(d4) & 0x3ffffff;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += c;

            m += 16;
            bytes -= 16;
        }
        h[0] = h0;
        h[1] = h1;
        h[2] = h2;
        h[3] = h3;
        h[4] = h4;
    }

    void update(const uint8_t *m, size_t bytes) {
        if (leftover) {
            size_t want = 16 - leftover;
            if (want > bytes) want = bytes;
            std::memcpy(buffer + leftover, m, want);
            bytes -= want;
            m += want;
            leftover += want;
            if (leftover < 16) return;
            blocks(buffer, 16);
            leftover = 0;
        }
        if (bytes >= 16) {
            size_t want = bytes & ~size_t(15);
            blocks(m, want);
            m += want;
            bytes -= want;
        }
        if (bytes) {
            std::memcpy(buffer + leftover, m, bytes);
            leftover += bytes;
        }
    }

    void finish(uint8_t tag[16]) {
        if (leftover) {
            buffer[leftover++] = 1;
            while (leftover < 16) buffer[leftover++] = 0;
            final = true;
            blocks(buffer, 16);
        }

        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        uint32_t c;
        c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        // g = h + 5; if it did not carry out of 2^130 then h < p and we keep h.
        uint32_t g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        uint32_t g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        uint32_t g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        uint32_t g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        uint32_t g4 = h4 + c - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;  // all-ones when h >= p
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Collapse the 26-bit limbs back into four 32-bit words (mod 2^128).
        h0 = (h0) | (h1 << 26);
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        uint64_t f;
        f = uint64_t(h0) + pad[0];
        h0 = uint32_t(f);
        f = uint64_t(h1) + pad[1] + (f >> 32);
        h1 = uint32_t(f);
        f = uint64_t(h2) + pad[2] + (f >> 32);
        h2 = uint32_t(f);
        f = uint64_t(h3) + pad[3] + (f >> 32);
        h3 = uint32_t(f);

        st32(tag + 0, h0);
        st32(tag + 4, h1);
        st32(tag + 8, h2);
        st32(tag + 12, h3);

        secure_zero(this, sizeof(*this));
    }
};

}  // namespace

void poly1305(const uint8_t key[kKeyLen], const uint8_t *msg, size_t n, uint8_t tag[kTagLen]) {
    Poly1305Ctx ctx;
    ctx.init(key);
    ctx.update(msg, n);
    ctx.finish(tag);
}

// =================================================== AEAD_CHACHA20_POLY1305

namespace {

// RFC 8439 sec. 2.8: the MAC input is aad | pad16 | ct | pad16 | le64(|aad|) | le64(|ct|).
void aead_mac(const uint8_t otk[32], std::span<const uint8_t> aad, const uint8_t *ct, size_t ctlen,
              uint8_t tag[16]) {
    static const uint8_t zeros[16] = {0};
    Poly1305Ctx ctx;
    ctx.init(otk);
    ctx.update(aad.data(), aad.size());
    if (aad.size() % 16) ctx.update(zeros, 16 - (aad.size() % 16));
    ctx.update(ct, ctlen);
    if (ctlen % 16) ctx.update(zeros, 16 - (ctlen % 16));
    uint8_t lens[16];
    st64(lens, uint64_t(aad.size()));
    st64(lens + 8, uint64_t(ctlen));
    ctx.update(lens, 16);
    ctx.finish(tag);
}

// The Poly1305 one-time key is the first 32 bytes of ChaCha20 block 0.
void aead_otk(const uint8_t key[32], const uint8_t nonce[12], uint8_t otk[32]) {
    uint8_t zeros[32] = {0};
    chacha20_xor(key, nonce, 0, zeros, otk, 32);
}

}  // namespace

void aead_seal(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], std::span<const uint8_t> aad,
               const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[kTagLen]) {
    uint8_t otk[32];
    aead_otk(key, nonce, otk);
    chacha20_xor(key, nonce, 1, pt, ct, ptlen);
    aead_mac(otk, aad, ct, ptlen, tag);
    secure_zero(otk, sizeof otk);
}

bool aead_open(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], std::span<const uint8_t> aad,
               const uint8_t *ct, size_t ctlen, const uint8_t tag[kTagLen], uint8_t *pt) {
    uint8_t otk[32];
    aead_otk(key, nonce, otk);
    uint8_t want[kTagLen];
    aead_mac(otk, aad, ct, ctlen, want);
    // Verify before decrypting so we never hand back unauthenticated plaintext.
    bool ok = ct_eq(want, tag, kTagLen);
    if (ok) chacha20_xor(key, nonce, 1, ct, pt, ctlen);
    secure_zero(otk, sizeof otk);
    secure_zero(want, sizeof want);
    return ok;
}

// ================================================================== X25519
// TweetNaCl's scalar multiplication, transcribed.  Field elements are sixteen
// signed 16-bit-ish limbs held in int64_t so every product fits without
// overflow; carries are folded with the 2^255-19 reduction 38*hi.

namespace {

using gf = int64_t[16];

const gf kGf121665 = {0xDB41, 1};

void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (int64_t(1) << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

// Conditional swap driven by `b` with no branch on secret data.
void sel25519(gf p, gf q, int b) {
    int64_t c = ~(int64_t(b) - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void pack25519(uint8_t *o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = int((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = uint8_t(t[i] & 0xff);
        o[2 * i + 1] = uint8_t(t[i] >> 8);
    }
}

void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) o[i] = int64_t(n[2 * i]) + (int64_t(n[2 * i + 1]) << 8);
    o[15] &= 0x7fff;
}

void fadd(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}
void fsub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}
void fmul(gf o, const gf a, const gf b) {
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}
void fsq(gf o, const gf a) { fmul(o, a, a); }

// x^(2^255-21) == x^-1 via the standard addition chain.
void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        fsq(c, c);
        if (a != 2 && a != 4) fmul(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

void scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]) {
    uint8_t z[32];
    int64_t x[80];
    gf a, b, c, d, e, f;

    for (int i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;  // clamp, RFC 7748 sec. 5
    z[0] &= 248;

    unpack25519(x, p);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; --i) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, int(r));
        sel25519(c, d, int(r));
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fsq(d, e);
        fsq(f, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fsq(b, a);
        fsub(c, d, f);
        fmul(a, c, kGf121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fsq(b, e);
        sel25519(a, b, int(r));
        sel25519(c, d, int(r));
    }
    for (int i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    fmul(x + 16, x + 16, x + 32);
    pack25519(q, x + 16);

    secure_zero(z, sizeof z);
    secure_zero(x, sizeof x);
}

const uint8_t kBasePoint[32] = {9};

}  // namespace

void x25519_base(const uint8_t sk[32], uint8_t pk[32]) { scalarmult(pk, sk, kBasePoint); }

bool x25519(const uint8_t sk[32], const uint8_t pk[32], uint8_t out[32]) {
    scalarmult(out, sk, pk);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc = uint8_t(acc | out[i]);
    return acc != 0;  // all-zero => peer sent a small-order point
}

// ==================================================================== misc

bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc = uint8_t(acc | (a[i] ^ b[i]));
    return acc == 0;
}

void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
    while (n--) *v++ = 0;
}

namespace {

// getrandom(2) is Linux-only.  Darwin draws from the same kernel pool through
// getentropy(3), which caps a call at 256 bytes and reports all-or-nothing.
// Presenting it in getrandom's shape keeps the caller's retry loop -- and its
// /dev/urandom fallback -- reading identically on both platforms.
ssize_t sys_random(uint8_t *p, size_t n) {
#if defined(__APPLE__)
    size_t chunk = n > 256 ? 256 : n;
    if (::getentropy(p, chunk) != 0) return -1;
    return ssize_t(chunk);
#else
    return ::getrandom(p, n, 0);
#endif
}

}  // namespace

void random_bytes(uint8_t *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = sys_random(p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;  // ENOSYS on ancient kernels; fall through to /dev/urandom
        }
        got += size_t(r);
    }
    if (got == n) return;

    Fd fd(::open("/dev/urandom", O_RDONLY | O_CLOEXEC));
    if (!fd) throw_errno("open /dev/urandom");
    while (got < n) {
        ssize_t r = ::read(fd.get(), p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw_errno("read /dev/urandom");
        }
        if (r == 0) fail("unexpected EOF on /dev/urandom");
        got += size_t(r);
    }
}

}  // namespace npxf::crypto
