#include "ninep.hpp"

#include <cstring>

namespace npxf::ninep {

const char *type_name(uint8_t t) {
    switch (t) {
        case Tlerror: return "Tlerror";
        case Rlerror: return "Rlerror";
        case Tstatfs: return "Tstatfs";
        case Rstatfs: return "Rstatfs";
        case Tlopen: return "Tlopen";
        case Rlopen: return "Rlopen";
        case Tlcreate: return "Tlcreate";
        case Rlcreate: return "Rlcreate";
        case Tsymlink: return "Tsymlink";
        case Rsymlink: return "Rsymlink";
        case Tmknod: return "Tmknod";
        case Rmknod: return "Rmknod";
        case Trename: return "Trename";
        case Rrename: return "Rrename";
        case Treadlink: return "Treadlink";
        case Rreadlink: return "Rreadlink";
        case Tgetattr: return "Tgetattr";
        case Rgetattr: return "Rgetattr";
        case Tsetattr: return "Tsetattr";
        case Rsetattr: return "Rsetattr";
        case Txattrwalk: return "Txattrwalk";
        case Rxattrwalk: return "Rxattrwalk";
        case Txattrcreate: return "Txattrcreate";
        case Rxattrcreate: return "Rxattrcreate";
        case Treaddir: return "Treaddir";
        case Rreaddir: return "Rreaddir";
        case Tfsync: return "Tfsync";
        case Rfsync: return "Rfsync";
        case Tlock: return "Tlock";
        case Rlock: return "Rlock";
        case Tgetlock: return "Tgetlock";
        case Rgetlock: return "Rgetlock";
        case Tlink: return "Tlink";
        case Rlink: return "Rlink";
        case Tmkdir: return "Tmkdir";
        case Rmkdir: return "Rmkdir";
        case Trenameat: return "Trenameat";
        case Rrenameat: return "Rrenameat";
        case Tunlinkat: return "Tunlinkat";
        case Runlinkat: return "Runlinkat";
        case Tversion: return "Tversion";
        case Rversion: return "Rversion";
        case Tauth: return "Tauth";
        case Rauth: return "Rauth";
        case Tattach: return "Tattach";
        case Rattach: return "Rattach";
        case Rerror: return "Rerror";
        case Tflush: return "Tflush";
        case Rflush: return "Rflush";
        case Twalk: return "Twalk";
        case Rwalk: return "Rwalk";
        case Tread: return "Tread";
        case Rread: return "Rread";
        case Twrite: return "Twrite";
        case Rwrite: return "Rwrite";
        case Tclunk: return "Tclunk";
        case Rclunk: return "Rclunk";
        case Tremove: return "Tremove";
        case Rremove: return "Rremove";
        default: return "T???";
    }
}

// ----------------------------------------------------------------- encoding

void Enc::u16(uint16_t v) {
    uint8_t t[2];
    st16(t, v);
    raw(t, 2);
}
void Enc::u32(uint32_t v) {
    uint8_t t[4];
    st32(t, v);
    raw(t, 4);
}
void Enc::u64(uint64_t v) {
    uint8_t t[8];
    st64(t, v);
    raw(t, 8);
}

void Enc::str(std::string_view s) {
    if (s.size() > 0xFFFF) throw ProtoError("string too long to encode");
    u16(uint16_t(s.size()));
    raw(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

void Enc::qid(const Qid &q) {
    u8(q.type);
    u32(q.version);
    u64(q.path);
}

uint8_t *Enc::reserve(size_t n) {
    size_t at = b_.size();
    b_.resize(at + n);
    return b_.data() + at;
}

// ----------------------------------------------------------------- decoding

void Dec::need(size_t n) const {
    if (size_t(e_ - p_) < n) throw ProtoError("truncated message");
}

uint8_t Dec::u8() {
    need(1);
    return *p_++;
}
uint16_t Dec::u16() {
    need(2);
    uint16_t v = ld16(p_);
    p_ += 2;
    return v;
}
uint32_t Dec::u32() {
    need(4);
    uint32_t v = ld32(p_);
    p_ += 4;
    return v;
}
uint64_t Dec::u64() {
    need(8);
    uint64_t v = ld64(p_);
    p_ += 8;
    return v;
}

std::string Dec::str() {
    uint16_t n = u16();
    need(n);
    std::string s(reinterpret_cast<const char *>(p_), n);
    p_ += n;
    return s;
}

std::span<const uint8_t> Dec::raw(size_t n) {
    need(n);
    std::span<const uint8_t> s(p_, n);
    p_ += n;
    return s;
}

Qid Dec::qid() {
    Qid q;
    q.type = u8();
    q.version = u32();
    q.path = u64();
    return q;
}

void Dec::end() const {
    if (p_ != e_) throw ProtoError("trailing bytes after message body");
}

// ------------------------------------------------------------------ framing

void begin(Bytes &b, uint8_t type, uint16_t tag) {
    b.clear();
    b.resize(kHeaderLen);
    st32(b.data(), 0);  // patched by finish()
    b[4] = type;
    st16(b.data() + 5, tag);
}

void finish(Bytes &b) {
    if (b.size() < kHeaderLen) throw ProtoError("message shorter than its header");
    if (b.size() > 0xFFFFFFFFu) throw ProtoError("message too large");
    st32(b.data(), uint32_t(b.size()));
}

Header parse(std::span<const uint8_t> msg) {
    if (msg.size() < kHeaderLen) throw ProtoError("runt message");
    uint32_t size = ld32(msg.data());
    if (size != msg.size())
        throw ProtoError("declared size " + std::to_string(size) + " != actual " +
                         std::to_string(msg.size()));
    Header h;
    h.type = msg[4];
    h.tag = ld16(msg.data() + 5);
    h.body = msg.subspan(kHeaderLen);
    return h;
}

void encode_dirent(Enc &e, const Qid &q, uint64_t offset, uint8_t dtype, std::string_view name) {
    e.qid(q);
    e.u64(offset);
    e.u8(dtype);
    e.str(name);
}

}  // namespace npxf::ninep
