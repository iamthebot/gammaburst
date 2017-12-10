#include "key_store.hpp"

namespace gammaburst::crypto
{

RatchetingKeyStore::RatchetingKeyStore (std::uint16_t num_keys) : root(crypto_aead_aes256gcm_KEYBYTES)
{
    for (int i = 0; i < num_keys; ++i)
    {
        keys.emplace_back(std::make_pair(CryptoBuffer(crypto_aead_aes256gcm_KEYBYTES), (std::size_t) 0));
        root_keys.emplace_back(CryptoBuffer(crypto_aead_aes256gcm_KEYBYTES));
    }
}

void RatchetingKeyStore::init_root (const CryptoBuffer &root_key)
{
    std::lock_guard<std::mutex> lg(lock);
    //copy over root key
    root_key.copy(root);

    CryptoBuffer tmp(crypto_aead_aes256gcm_KEYBYTES + sizeof(std::uint16_t));
    std::uint16_t con = 0;

    // set up the connection specific keys
    for (auto& key : keys)
    {
        // connection-specific root key is root key + unsigned 16 bit connection number
        root.copy(tmp);
        tmp.write(&con, sizeof(std::uint16_t), crypto_aead_aes256gcm_KEYBYTES);
        // ratchet the key once to get our starting key for our connection
        // this makes it harder to correlate the connection specific keys
        tmp.sha256(key.first);
        key.first.copy(root_keys[con]);
        ++con;
    }
}

void ratchet (CryptoBuffer &src, CryptoBuffer &tmp)
{
    src.sha256(tmp);
    tmp.copy(src);
}

CryptoBuffer RatchetingKeyStore::at (std::uint16_t idx, std::uint64_t step)
{
    std::lock_guard<std::mutex> lg(lock);
    CryptoBuffer out(root.len());
    if (idx > keys.size()) throw std::runtime_error("invalid idx");
    CryptoBuffer tmp(root.len());
    root_keys[idx].copy(out);
    for (int i = 0; i < step; ++i) ratchet(out, tmp);
    return out;
}

std::pair<CryptoBuffer, std::size_t> RatchetingKeyStore::current (std::uint16_t idx)
{
    std::lock_guard<std::mutex> lg(lock);
    auto out = std::make_pair(CryptoBuffer(root.len()),keys[idx].second);
    keys[idx].first.copy(out.first);
    return out;
}

} //gammaburst::crypto
