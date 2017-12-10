#pragma once
#include <sodium.h>
#include <cstdint>
#include <vector>
#include "crypto_buffer.hpp"
#include <mutex>

namespace gammaburst::crypto
{

class RatchetingKeyStore
/// @brief Provides a cryptographic ratchet for up n keys chained off a single root key
{
    std::mutex lock; ///< controls concurrent access to the keys
    CryptoBuffer root; ///< stores the root key
    std::vector<CryptoBuffer> root_keys;  ///< holds starting keys for each connection
    std::vector<std::pair<CryptoBuffer, std::uint64_t>> keys;  ///< holds keys and steps
  public:
    /// @brief Constructs a RatchetingKeyStore
    /// @param num_keys How many concurrent keys to support
    explicit RatchetingKeyStore(std::uint16_t num_keys);
    /// @brief Loads the root key into the key store and initializes the subkeys
    /// @param root_key
    void init_root(const CryptoBuffer& root_key);
    /// @brief Computes the key state after <step> steps. This is an n-fold SHA256 composition from the starting key
    /// @param idx The index of the key to use
    /// @param step The step number. Step 0 yields the root key.
    /// @return The key at the given step
    CryptoBuffer at(std::uint16_t idx, std::uint64_t step);

    /// @brief Returns the current key state for a given index. Ratchets the key after returning
    /// @param idx The index of the key to use
    /// @return The current key for a given index and its corresponding step number
    std::pair<CryptoBuffer, std::size_t> current(std::uint16_t idx);
};

}
