#include <regex>

#include "tests.hpp"

typedef const EVP_CIPHER* (*EVP_CIPHERS)(void);

// Указатели на функции хрен const сделаешь (логично, это же не compile time)
static std::unordered_map<Modes, EVP_CIPHERS> ciphers{
    {ECB, EVP_aes_128_ecb},
    {CBC, EVP_aes_128_cbc},
    {CFB, EVP_aes_128_cfb},
    {OFB, EVP_aes_128_ofb},
    {CTR, EVP_aes_128_ctr}
};

Bytes gen_text(size_t length) {
    Bytes res(length);
    RAND_bytes(res.data(), length);
    return res;
}

// Ваааапще небезопасно, но и пофек х2
Bytes from_hexstr_to_bytes(const string& str) {
    auto size{str.size()};
    if (size % 2) throw std::invalid_argument("Bad length of hex string");
    if (!std::regex_match(str, std::regex("^[0-9a-fA-F]*$")))
        throw std::invalid_argument("Forbidden char in the hex string.");
    Bytes out{};
    for (auto i = 0; i < size; i += 2) {
        auto offset{str.begin() + i};
        out.push_back(std::stoul("0x" + string{offset, offset + 2}, nullptr, 16)
        );
    }
    return out;
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
Bytes official_encrypt(
    const Bytes& ptext, Modes mode, const Bytes& key, const Bytes IV
) {
    Bytes ctext{};
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    auto rc = EVP_EncryptInit_ex(
        ctx.get(), ciphers[mode](), NULL, key.data(), IV.data()
    );
    if (rc != 1) throw std::runtime_error("EVP_EncryptInit_ex failed");
    ctext.resize(ptext.size() + BLOCK_SIZE);
    auto out_len1 = (int)ctext.size();

    rc            = EVP_EncryptUpdate(
        ctx.get(), ctext.data(), &out_len1, ptext.data(), (int)ptext.size()
    );
    if (rc != 1) throw std::runtime_error("EVP_EncryptUpdate failed");

    auto out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), ctext.data() + out_len1, &out_len2);
    if (rc != 1) throw std::runtime_error("EVP_EncryptFinal_ex failed");

    ctext.resize(out_len1 + out_len2);
    return ctext;
}