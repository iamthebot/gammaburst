#include "crypto_buffer.hpp"
#include <sodium.h>
#include <cstring>

namespace gammaburst::crypto
{
CryptoBuffer::CryptoBuffer (std::size_t size) : len_(size)
{
    buf = static_cast<std::uint8_t *>(sodium_malloc(size));
    if (buf == nullptr) throw std::bad_alloc();
}

CryptoBuffer::~CryptoBuffer ()
{
    std::lock_guard<std::mutex> lock(mut);
    sodium_mprotect_readwrite(buf);
    sodium_free(buf);
}

CryptoBuffer::CryptoBuffer(const CryptoBuffer& s) : len_(s.len()) {
    buf = static_cast<std::uint8_t *>(sodium_malloc(s.len()));
    if (buf == nullptr) throw std::bad_alloc();
    std::memcpy(buf, s.buf, s.len());
}

const std::uint8_t* CryptoBuffer::acquire_ro() const
{
    mut.lock();
    sodium_mprotect_readonly(buf);
    return buf;
}

void CryptoBuffer::release() const
{
    sodium_mprotect_noaccess(buf);
    mut.unlock();
}


void CryptoBuffer::write(void* src, std::size_t len, std::size_t offset)
{
    std::lock_guard<std::mutex> lg(mut);
    sodium_mprotect_readwrite(buf);
    if ((len_ - offset) < len) {
        throw std::runtime_error("not enough space in destination buffer");
    }
    std::memcpy(buf + offset, src, len);
    sodium_mprotect_noaccess(buf);
}

void CryptoBuffer::copy (CryptoBuffer &dest, std::size_t offset) const
{
    std::lock_guard<std::mutex> lg(mut);
    dest.write(buf, len_, offset);
}

void CryptoBuffer::sha256(CryptoBuffer& dest) const
{
    std::lock_guard<std::mutex> lg(mut);
    std::lock_guard<std::mutex> remote_lg(dest.mut);
    if (dest.len() < crypto_hash_sha256_BYTES) {
        throw std::runtime_error("not enough space in destination buffer to hold a SHA256 hash");
    }
    crypto_hash_sha256(dest.buf, buf, len_);
}

} //gammaburst::crypto