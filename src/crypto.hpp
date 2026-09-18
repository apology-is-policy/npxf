// OpenSSL 3 provider-backed primitives; NPXF v1 wire format is unchanged.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <openssl/evp.h>

namespace npxf::crypto {

inline constexpr size_t kKeyLen = 32;
inline constexpr size_t kTagLen = 16;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kHashLen = 32;

using Key = std::array<uint8_t, kKeyLen>;
using Hash = std::array<uint8_t, kHashLen>;

// --------------------------------------------------------------------- SHA-256

class Sha256 {
  public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;
    void reset();
    void update(const uint8_t *p, size_t n);
    void update(std::span<const uint8_t> s) { update(s.data(), s.size()); }
    void finish(uint8_t out[kHashLen]);

    static Hash hash(std::span<const uint8_t> in);

  private:
    EVP_MD_CTX *ctx_ = nullptr;
};

void hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> msg, uint8_t out[kHashLen]);

// RFC 5869.  `expand` supports outlen up to 255*32 bytes.
void hkdf_extract(std::span<const uint8_t> salt, std::span<const uint8_t> ikm, uint8_t prk[kHashLen]);
void hkdf_expand(const uint8_t prk[kHashLen], std::span<const uint8_t> info, uint8_t *out, size_t outlen);

// ------------------------------------------------------------ ChaCha20-Poly1305

// XOR `n` bytes of ChaCha20 keystream (starting at the given block counter)
// into `in`, writing to `out`.  `in` and `out` may alias exactly.
void chacha20_xor(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t n);

void poly1305(const uint8_t key[kKeyLen], const uint8_t *msg, size_t n, uint8_t tag[kTagLen]);

// AEAD_CHACHA20_POLY1305.  `ct` must have room for `ptlen` bytes; it may alias
// `pt`.  Nonces must never repeat under a given key -- the record layer uses a
// strictly increasing counter per direction to guarantee that.
void aead_seal(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], std::span<const uint8_t> aad,
               const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[kTagLen]);

// Returns false (without writing plaintext the caller should trust) if the tag
// does not verify.  Callers must treat a false return as fatal for the session.
[[nodiscard]] bool aead_open(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen],
                             std::span<const uint8_t> aad, const uint8_t *ct, size_t ctlen,
                             const uint8_t tag[kTagLen], uint8_t *pt);

// ---------------------------------------------------------------------- X25519

void x25519_base(const uint8_t sk[32], uint8_t pk[32]);

// Returns false if the result is the all-zero point, which means the peer sent
// a small-order public key.  Rejecting it enforces contributory behaviour.
[[nodiscard]] bool x25519(const uint8_t sk[32], const uint8_t pk[32], uint8_t out[32]);

// ----------------------------------------------------------------------- misc

[[nodiscard]] bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n);
void random_bytes(uint8_t *p, size_t n);
void secure_zero(void *p, size_t n);

// Runs every known-answer test.  Returns false and fills `err` on mismatch.
bool self_test(std::string *err);

}  // namespace npxf::crypto
