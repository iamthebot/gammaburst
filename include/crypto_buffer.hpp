#pragma once

#include <vector>
#include <cstdint>
#include <mutex>

namespace gammaburst::crypto
{

class CryptoBuffer {
    /// @brief Implements a secure buffer we can use to store secrets (keys, plaintext, etc.)
    /// This is safe against being swapped to disk and features canaries, etc. to protect against overflow
    /// Memory is access-restricted by default. Attempting to read or write without locking will cause application failure
    std::uint8_t *buf;  //!< Holds the sensitive memory contents
    const std::size_t len_;
    mutable std::mutex mut;

  public:
    /// @brief CryptoBuffer Constructor
    /// @param size Size of buffer in bytes
    explicit CryptoBuffer (std::size_t size);
    /// @brief Safe destructor
    ~CryptoBuffer ();
    /// @brief Copy constructor
    /// @param source
    CryptoBuffer(const CryptoBuffer& s);
    /// @brief Writes len bytes to the buffer starting at the given offset. Performs bounds checking.
    /// @param src The source pointer
    /// @param len Number of bytes to write
    /// @param offset Number of bytes to offset before writing
    void write(void* src, std::size_t len, std::size_t offset = 0);
    /// @brief Takes full read ownership of the buffer. This allows the caller to read but not write the underlying buffer
    /// @return Pointer to the underlying buffer
    const std::uint8_t* acquire_ro() const;
    /// @brief Releases ownership of the buffer. Until another caller acquires it, the underlying memory is inaccessible
    void release () const;
    /// @brief Returns the length of the buffer in bytes
    /// @return The length of the buffer in bytes
    std::size_t len () const { return len_; };
    /// @brief Securely copies contents to a destination cryptobuffer
    /// @param dest The buffer to copy to
    /// @param offset Number of bytes to offset before writing
    void copy(CryptoBuffer& dest, std::size_t offset = 0) const;
    /// @brief Writes a SHA256 hash to a target CryptoBuffer
    /// @param dest The CryptoBuffer to write to
    void sha256(CryptoBuffer& dest) const;
};
}
