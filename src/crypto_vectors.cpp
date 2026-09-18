// Known-answer tests for every primitive in crypto.cpp.  Vectors are copied
// from the defining RFCs; both binaries run these at startup so a bad build
// can never come up serving traffic.
#include <cstring>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "util.hpp"

namespace npxf::crypto {
namespace {

Bytes H(std::string_view s) {
    Bytes b;
    if (!from_hex(s, b)) b.clear();
    return b;
}

Bytes S(std::string_view s) { return Bytes(s.begin(), s.end()); }

bool check(const char *name, std::span<const uint8_t> got, std::span<const uint8_t> want,
           std::string *err) {
    if (got.size() == want.size() && std::memcmp(got.data(), want.data(), got.size()) == 0) return true;
    *err = std::string(name) + ": got " + to_hex(got) + ", want " + to_hex(want);
    return false;
}

#define REQUIRE(name, got, want)                  \
    do {                                          \
        if (!check(name, got, want, err)) return false; \
    } while (0)

bool test_sha256(std::string *err) {
    struct {
        const char *in;
        const char *out;
    } cases[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };
    for (auto &c : cases) {
        Hash h = Sha256::hash(byte_span(std::string_view(c.in)));
        REQUIRE("sha256", h, H(c.out));
    }
    // Exercise the multi-call buffering path: one million 'a' fed in odd chunks.
    Sha256 s;
    std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; i++) s.update(byte_span(chunk));
    uint8_t out[32];
    s.finish(out);
    REQUIRE("sha256-1m", std::span<const uint8_t>(out, 32),
            H("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    return true;
}

bool test_hmac_hkdf(std::string *err) {
    // RFC 4231 test case 1.
    Bytes key(20, 0x0b);
    uint8_t mac[32];
    hmac_sha256(byte_span(key), byte_span(std::string_view("Hi There")), mac);
    REQUIRE("hmac", std::span<const uint8_t>(mac, 32),
            H("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    // RFC 5869 test case 1.
    Bytes ikm(22, 0x0b);
    Bytes salt = H("000102030405060708090a0b0c");
    Bytes info = H("f0f1f2f3f4f5f6f7f8f9");
    uint8_t prk[32];
    hkdf_extract(byte_span(salt), byte_span(ikm), prk);
    REQUIRE("hkdf-extract", std::span<const uint8_t>(prk, 32),
            H("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    uint8_t okm[42];
    hkdf_expand(prk, byte_span(info), okm, sizeof okm);
    REQUIRE("hkdf-expand", std::span<const uint8_t>(okm, 42),
            H("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865"));
    return true;
}

bool test_chacha20(std::string *err) {
    // RFC 8439 sec. 2.4.2.
    Bytes key = H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Bytes nonce = H("000000000000004a00000000");
    Bytes pt = S(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.");
    Bytes ct(pt.size());
    chacha20_xor(key.data(), nonce.data(), 1, pt.data(), ct.data(), pt.size());
    REQUIRE("chacha20",
            byte_span(ct),
            H("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
              "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
              "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
              "5af90bbf74a35be6b40b8eedf2785e42874d"));

    // And decrypting must be the same operation.
    Bytes back(ct.size());
    chacha20_xor(key.data(), nonce.data(), 1, ct.data(), back.data(), ct.size());
    REQUIRE("chacha20-roundtrip", byte_span(back), byte_span(pt));
    return true;
}

bool test_poly1305(std::string *err) {
    // RFC 8439 sec. 2.5.2.
    Bytes key = H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    Bytes msg = S("Cryptographic Forum Research Group");
    uint8_t tag[16];
    poly1305(key.data(), msg.data(), msg.size(), tag);
    REQUIRE("poly1305", std::span<const uint8_t>(tag, 16), H("a8061dc1305136c6c22b8baf0c0127a9"));

    // RFC 8439 sec. A.3 vector 2: r == 0 so the tag is just s.
    Bytes k2 = H("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
    Bytes m2(131, 0);
    std::string text =
        "Any submission to the IETF intended by the Contributor for publication as all or part of "
        "an IETF Internet-Draft or RFC and any statement made within the context of an IETF "
        "activity is considered an \"IETF Contribution\". Such statements include oral statements "
        "in IETF sessions, as well as written and electronic communications made at any time or "
        "place, which are addressed to";
    m2.assign(text.begin(), text.end());
    poly1305(k2.data(), m2.data(), m2.size(), tag);
    REQUIRE("poly1305-r0", std::span<const uint8_t>(tag, 16), H("36e5f6b5c5e06070f0efca96227a863e"));
    return true;
}

bool test_aead(std::string *err) {
    // RFC 8439 sec. 2.8.2.
    Bytes key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    Bytes nonce = H("070000004041424344454647");
    Bytes aad = H("50515253c0c1c2c3c4c5c6c7");
    Bytes pt = S(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.");
    Bytes ct(pt.size());
    uint8_t tag[16];
    aead_seal(key.data(), nonce.data(), byte_span(aad), pt.data(), pt.size(), ct.data(), tag);
    REQUIRE("aead-ct", byte_span(ct),
            H("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116"));
    REQUIRE("aead-tag", std::span<const uint8_t>(tag, 16), H("1ae10b594f09e26a7e902ecbd0600691"));

    Bytes back(ct.size());
    if (!aead_open(key.data(), nonce.data(), byte_span(aad), ct.data(), ct.size(), tag, back.data())) {
        *err = "aead-open: rejected a valid tag";
        return false;
    }
    REQUIRE("aead-open", byte_span(back), byte_span(pt));

    // Every single-bit flip in the ciphertext, aad, tag or nonce must be caught.
    auto must_reject = [&](const char *what, Bytes c, Bytes a, Bytes n, uint8_t t[16]) {
        if (aead_open(key.data(), n.data(), byte_span(a), c.data(), c.size(), t, back.data())) {
            *err = std::string("aead-open: accepted forgery (") + what + ")";
            return false;
        }
        return true;
    };
    {
        Bytes c = ct;
        c[7] ^= 0x01;
        if (!must_reject("ciphertext", c, aad, nonce, tag)) return false;
    }
    {
        Bytes a = aad;
        a[3] ^= 0x80;
        if (!must_reject("aad", ct, a, nonce, tag)) return false;
    }
    {
        Bytes n = nonce;
        n[11] ^= 0x01;
        if (!must_reject("nonce", ct, aad, n, tag)) return false;
    }
    {
        uint8_t t[16];
        std::memcpy(t, tag, 16);
        t[15] ^= 0x01;
        if (!must_reject("tag", ct, aad, nonce, t)) return false;
    }

    // Empty plaintext and empty aad must still authenticate.
    uint8_t t0[16];
    aead_seal(key.data(), nonce.data(), {}, nullptr, 0, nullptr, t0);
    if (!aead_open(key.data(), nonce.data(), {}, nullptr, 0, t0, nullptr)) {
        *err = "aead: empty message failed to round-trip";
        return false;
    }
    return true;
}

bool test_x25519(std::string *err) {
    // RFC 7748 sec. 5.2, first vector.
    Bytes sk = H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    Bytes u = H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    uint8_t out[32];
    if (!x25519(sk.data(), u.data(), out)) {
        *err = "x25519: unexpected all-zero output";
        return false;
    }
    REQUIRE("x25519", std::span<const uint8_t>(out, 32),
            H("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

    // RFC 7748 sec. 6.1, the full Diffie-Hellman exchange.
    Bytes a = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Bytes b = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t A[32], B[32], k1[32], k2[32];
    x25519_base(a.data(), A);
    x25519_base(b.data(), B);
    REQUIRE("x25519-pubA", std::span<const uint8_t>(A, 32),
            H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    REQUIRE("x25519-pubB", std::span<const uint8_t>(B, 32),
            H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    if (!x25519(a.data(), B, k1) || !x25519(b.data(), A, k2)) {
        *err = "x25519: dh produced all-zero output";
        return false;
    }
    REQUIRE("x25519-shared", std::span<const uint8_t>(k1, 32),
            H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    REQUIRE("x25519-shared-sym", std::span<const uint8_t>(k2, 32), std::span<const uint8_t>(k1, 32));

    // Small-order points must be rejected rather than yielding a shared secret.
    const char *lo[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    };
    for (const char *hexpt : lo) {
        Bytes pt = H(hexpt);
        if (x25519(a.data(), pt.data(), out)) {
            *err = std::string("x25519: accepted small-order point ") + hexpt;
            return false;
        }
    }
    return true;
}

bool test_misc(std::string *err) {
    uint8_t x[16] = {0}, y[16] = {0};
    if (!ct_eq(x, y, 16)) {
        *err = "ct_eq: equal buffers compared unequal";
        return false;
    }
    y[15] = 1;
    if (ct_eq(x, y, 16)) {
        *err = "ct_eq: differing buffers compared equal";
        return false;
    }
    // random_bytes must not return a constant block.
    uint8_t r1[32], r2[32];
    random_bytes(r1, sizeof r1);
    random_bytes(r2, sizeof r2);
    if (std::memcmp(r1, r2, 32) == 0) {
        *err = "random_bytes: returned identical blocks";
        return false;
    }
    return true;
}

#undef REQUIRE

}  // namespace

bool self_test(std::string *err) {
    std::string scratch;
    if (!err) err = &scratch;
    return test_sha256(err) && test_hmac_hkdf(err) && test_chacha20(err) && test_poly1305(err) &&
           test_aead(err) && test_x25519(err) && test_misc(err);
}

}  // namespace npxf::crypto
