// OpenSSL owns every cryptographic primitive and the entropy source. This
// adapter preserves NPXF v1's wire bytes; failures throw before use of output.
#include "crypto.hpp"
#include "util.hpp"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <climits>
#include <memory>

namespace npxf::crypto {
namespace {
template<class T, void (*Free)(T *)> using Handle = std::unique_ptr<T, decltype(Free)>;
void check(int rc) { if (rc != 1) fail("OpenSSL cryptographic operation failed"); }
int length(size_t n) { if (n > INT_MAX) fail("cryptographic input too large"); return int(n); }
Handle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> cipher() {
    Handle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> p(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!p) fail("OpenSSL context allocation failed");
    return p;
}
void mac(const char *name, std::span<const uint8_t> key, std::span<const uint8_t> msg,
         uint8_t *out, size_t size, OSSL_PARAM *params = nullptr) {
    Handle<EVP_MAC, EVP_MAC_free> alg(EVP_MAC_fetch(nullptr, name, nullptr), EVP_MAC_free);
    if (!alg) fail("OpenSSL MAC unavailable");
    Handle<EVP_MAC_CTX, EVP_MAC_CTX_free> ctx(EVP_MAC_CTX_new(alg.get()), EVP_MAC_CTX_free);
    if (!ctx) fail("OpenSSL context allocation failed");
    // A non-null empty key means an empty key, not reuse of prior state.
    const uint8_t empty = 0;
    check(EVP_MAC_init(ctx.get(), key.empty() ? &empty : key.data(), key.size(), params));
    if (!msg.empty()) check(EVP_MAC_update(ctx.get(), msg.data(), msg.size()));
    size_t got = 0;
    check(EVP_MAC_final(ctx.get(), out, &got, size));
    if (got != size) fail("OpenSSL MAC size mismatch");
}
void hkdf(char *mode, std::span<const uint8_t> key, std::span<const uint8_t> salt,
          std::span<const uint8_t> info, uint8_t *out, size_t n) {
    Handle<EVP_KDF, EVP_KDF_free> alg(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    if (!alg) fail("OpenSSL HKDF unavailable");
    Handle<EVP_KDF_CTX, EVP_KDF_CTX_free> ctx(EVP_KDF_CTX_new(alg.get()), EVP_KDF_CTX_free);
    if (!ctx) fail("OpenSSL context allocation failed");
    uint8_t empty = 0;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, mode, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.empty() ? &empty : const_cast<uint8_t *>(key.data()), key.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.empty() ? &empty : const_cast<uint8_t *>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.empty() ? &empty : const_cast<uint8_t *>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };
    check(EVP_KDF_derive(ctx.get(), out, n, params));
}
}
Sha256::Sha256() : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) fail("OpenSSL context allocation failed");
    try { reset(); } catch (...) { EVP_MD_CTX_free(ctx_); throw; }
}
Sha256::~Sha256() { EVP_MD_CTX_free(ctx_); }
void Sha256::reset() { check(EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr)); }
void Sha256::update(const uint8_t *p, size_t n) { if (n) check(EVP_DigestUpdate(ctx_, p, n)); }
void Sha256::finish(uint8_t out[32]) {
    unsigned n = 0; check(EVP_DigestFinal_ex(ctx_, out, &n));
    if (n != 32) fail("OpenSSL digest size mismatch");
}
Hash Sha256::hash(std::span<const uint8_t> in) { Sha256 s; s.update(in); Hash h; s.finish(h.data()); return h; }
void hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> msg, uint8_t out[32]) {
    char digest[] = "SHA256";
    OSSL_PARAM p[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end() };
    mac("HMAC", key, msg, out, 32, p);
}
void hkdf_extract(std::span<const uint8_t> salt, std::span<const uint8_t> ikm, uint8_t prk[32]) {
    char mode[] = "EXTRACT_ONLY"; hkdf(mode, ikm, salt, {}, prk, 32);
}
void hkdf_expand(const uint8_t prk[32], std::span<const uint8_t> info, uint8_t *out, size_t n) {
    if (n > 255 * 32) fail("HKDF output too large");
    if (!n) return;
    char mode[] = "EXPAND_ONLY"; hkdf(mode, {prk, 32}, {}, info, out, n);
}
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t n) {
    if ((n + uint64_t(63)) / 64 > uint64_t(UINT32_MAX) + 1 - counter) fail("ChaCha20 counter exhausted");
    auto ctx = cipher(); uint8_t iv[16]; st32(iv, counter); std::memcpy(iv + 4, nonce, 12);
    check(EVP_EncryptInit_ex(ctx.get(), EVP_chacha20(), nullptr, key, iv));
    int got = 0;
    if (n) check(EVP_EncryptUpdate(ctx.get(), out, &got, in, length(n)));
    if (size_t(got) != n) fail("OpenSSL cipher size mismatch");
}
void poly1305(const uint8_t key[32], const uint8_t *msg, size_t n, uint8_t tag[16]) {
    mac("POLY1305", {key, 32}, {msg, n}, tag, 16);
}
void aead_seal(const uint8_t key[32], const uint8_t nonce[12], std::span<const uint8_t> aad,
               const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[16]) {
    auto ctx = cipher(); int got = 0; uint8_t tail[16];
    check(EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key, nonce));
    if (!aad.empty()) check(EVP_EncryptUpdate(ctx.get(), nullptr, &got, aad.data(), length(aad.size())));
    got = 0;
    if (n) check(EVP_EncryptUpdate(ctx.get(), ct, &got, pt, length(n)));
    if (size_t(got) != n) fail("OpenSSL cipher size mismatch");
    check(EVP_EncryptFinal_ex(ctx.get(), tail, &got));
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag));
}
bool aead_open(const uint8_t key[32], const uint8_t nonce[12], std::span<const uint8_t> aad,
               const uint8_t *ct, size_t n, const uint8_t tag[16], uint8_t *pt) {
    auto ctx = cipher(); int got = 0; uint8_t tail[16];
    check(EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key, nonce));
    if (!aad.empty()) check(EVP_DecryptUpdate(ctx.get(), nullptr, &got, aad.data(), length(aad.size())));
    // EVP emits unauthenticated plaintext before Final: wipe it on every failure.
    try {
        got = 0;
        if (n) check(EVP_DecryptUpdate(ctx.get(), pt, &got, ct, length(n)));
        if (size_t(got) != n) fail("OpenSSL cipher size mismatch");
        check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag)));
        if (EVP_DecryptFinal_ex(ctx.get(), tail, &got) != 1) { secure_zero(pt, n); return false; }
    } catch (...) { secure_zero(pt, n); throw; }
    return true;
}
void x25519_base(const uint8_t sk[32], uint8_t pk[32]) {
    Handle<EVP_PKEY, EVP_PKEY_free> key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32), EVP_PKEY_free);
    if (!key) fail("OpenSSL X25519 key creation failed");
    size_t n = 32; check(EVP_PKEY_get_raw_public_key(key.get(), pk, &n));
    if (n != 32) fail("OpenSSL public key size mismatch");
}
bool x25519(const uint8_t sk[32], const uint8_t pk[32], uint8_t out[32]) {
    Handle<EVP_PKEY, EVP_PKEY_free> key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32), EVP_PKEY_free);
    Handle<EVP_PKEY, EVP_PKEY_free> peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pk, 32), EVP_PKEY_free);
    if (!key || !peer) fail("OpenSSL X25519 key creation failed");
    Handle<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx) fail("OpenSSL context allocation failed");
    check(EVP_PKEY_derive_init(ctx.get())); check(EVP_PKEY_derive_set_peer(ctx.get(), peer.get()));
    size_t n = 32;
    if (EVP_PKEY_derive(ctx.get(), out, &n) != 1 || n != 32) { secure_zero(out, 32); return false; }
    uint8_t zero[32]{};
    if (ct_eq(out, zero, 32)) { secure_zero(out, 32); return false; }
    return true;
}
bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n) { return !n || CRYPTO_memcmp(a, b, n) == 0; }
void secure_zero(void *p, size_t n) { if (n) OPENSSL_cleanse(p, n); }
void random_bytes(uint8_t *p, size_t n) { if (n) check(RAND_bytes_ex(nullptr, p, n, 0)); }
} // namespace npxf::crypto
