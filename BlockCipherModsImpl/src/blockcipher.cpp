#include "blockcipher.hpp"

#include <algorithm>
#include <iostream>

Bytes key_gen() {
    Bytes key(KEY_SIZE);
    if (RAND_bytes(key.data(), KEY_SIZE) != 1)
        throw std::runtime_error("RAND_Bytes key failed");
    return key;
}

Bytes IV_gen() {
    Bytes iv(KEY_SIZE);
    if (RAND_bytes(iv.data(), KEY_SIZE) != 1)
        throw std::runtime_error("RAND_Bytes IV failed");
    return iv;
}

Bytes XOR_two_vectors_sagnificant(const Bytes& vec1, const Bytes& vec2) {
    auto& smalller{vec1.size() < vec2.size() ? vec1 : vec2};
    auto& bigger{vec1.size() < vec2.size() ? vec2 : vec1};
    Bytes res(smalller.size());
    std::transform(
        smalller.begin(), smalller.end(), bigger.begin(), res.begin(),
        std::bit_xor<>()
    );
    return res;
}

Bytes& increment_byte_vector(Bytes& vector) {
    auto overflowed{vector.size() - 1};
    while (vector[overflowed] == 0xff) {
        if (!overflowed--)
            throw std::runtime_error(
                "Overwlow while the byte vector incrementation"
            );
    }
    ++vector[overflowed];
    return vector;
}

void OwnBlockCipher::PKCS7(Bytes& plainText) {
    // Размер в [1...BLOCK_SIZE]
    auto lastBlockSize{(plainText.size() - 1) % BLOCK_SIZE + 1};
    Bytes lastBlock{plainText.end() - lastBlockSize, plainText.end()};
    Bytes extraPadding{};
    size_t dif{BLOCK_SIZE - lastBlock.size()};
    if (dif) {
        Bytes padding(dif, dif);
        lastBlock.insert(lastBlock.end(), padding.begin(), padding.end());
    } else {
        extraPadding = Bytes(BLOCK_SIZE, BLOCK_SIZE);
    }
    if (extraPadding.empty()) {
        plainText.erase(plainText.end() - lastBlockSize, plainText.end());
        plainText.insert(plainText.end(), lastBlock.begin(), lastBlock.end());
    } else
        plainText.insert(
            plainText.end(), extraPadding.begin(), extraPadding.end()
        );
}

void OwnBlockCipher::is_valid_padding_mode(Paddings& paddingMode) {
    if (paddingMode == DEFAULT_PADDING) {
        auto default_settings{possibleModes.begin()};
        if ((default_settings = std::find_if(
                 possibleModes.begin(), possibleModes.end(),
                 [&](const auto& p) { return p.first == m_mode; }
             )) != possibleModes.end())
            paddingMode = default_settings->second;
    } else {
        std::pair<Modes, Paddings> expected{m_mode, paddingMode};
        if (std::find(possibleModes.begin(), possibleModes.end(), expected) ==
            possibleModes.end())
            throw std::invalid_argument(
                "Unsupporetd padding mode using the current cipher"
            );
    }
};

Bytes& OwnBlockCipher::add_padding(Bytes& plainText, Paddings& pad) {
    is_valid_padding_mode(pad);
    switch (pad) {
        case Paddings::PKCS7:
            PKCS7(plainText);
            break;
        case NON:
            break;
    }
    return plainText;
}

Bytes& OwnBlockCipher::cut_padding(Bytes& plainText, Paddings& pad) {
    switch (pad) {
        case Paddings::PKCS7: {
            byte paddingSize{plainText.back()};
            plainText.erase(plainText.end() - paddingSize, plainText.end());
            break;
        }
        default:
            break;
    }
    return plainText;
}

Bytes& OwnBlockCipher::generate_IV(Bytes& IV, Bytes& ctext) {
    if (IV.empty()) {
        if (m_mode == ECB) {
        } else if (m_mode == CBC) {
            IV = IV_gen();
        } else if (m_mode == OFB) {
            IV = IV_gen();
        } else if (m_mode == CFB) {
            IV = IV_gen();
        } else if (m_mode == CTR) {
            // Ну типа сгенерили
            Bytes nonce(4), innerIV(8), counter(4);
            RAND_bytes(nonce.data(), 4);
            IV.insert(IV.end(), nonce.begin(), nonce.end());
            RAND_bytes(innerIV.data(), 8);
            IV.insert(IV.end(), innerIV.begin(), innerIV.end());
            RAND_bytes(counter.data(), 4);
            IV.insert(IV.end(), counter.begin(), counter.end());
        }
        ctext.insert(ctext.begin(), IV.begin(), IV.end());
    }
    return IV;
}

Bytes OwnBlockCipher::block_cipher_encrypt(const Bytes& data) {
    if (EVP_EncryptInit_ex(
            m_ctx.get(), EVP_aes_128_ecb(), NULL, m_key.data(), NULL
        ) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    Bytes block(BLOCK_SIZE);
    int out_len{0};
    if (EVP_EncryptUpdate(
            m_ctx.get(), block.data(), &out_len, data.data(), BLOCK_SIZE
        ) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    return block;
}

Bytes OwnBlockCipher::block_cipher_decrypt(const Bytes& data) {
    if (EVP_DecryptInit_ex(
            m_ctx.get(), EVP_aes_128_ecb(), NULL, m_key.data(), NULL
        ) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    Bytes block(BLOCK_SIZE);
    int out_len{0};
    if (EVP_DecryptUpdate(
            m_ctx.get(), block.data(), &out_len, data.data(), BLOCK_SIZE
        ) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    return block;
}

Bytes OwnBlockCipher::proccess_block_encrypt(Bytes block, Bytes& feedback) {
    Bytes out{};
    if (m_mode == ECB) {
        out = {block_cipher_encrypt(block)};
    } else if (m_mode == CBC) {
        out = {block_cipher_encrypt(XOR_two_vectors_sagnificant(block, feedback)
        )};
        feedback = out;
    } else if (m_mode == CFB) {
        // Размер шага регистра срвпадает с BLOCK_SIZE, поэтому можно и без ЛРС
        out =
            XOR_two_vectors_sagnificant(block, block_cipher_encrypt(feedback));
        feedback = out;
    } else if (m_mode == OFB) {
        feedback = block_cipher_encrypt(feedback);
        out      = XOR_two_vectors_sagnificant(block, feedback);
    } else if (m_mode == CTR) {
        auto res{
            XOR_two_vectors_sagnificant(block, block_cipher_encrypt(feedback))
        };
        out.insert(out.end(), res.begin(), res.end());
        increment_byte_vector(feedback);
    } else
        throw std::runtime_error("Bad mode while block encrypting");
    return out;
}

Bytes OwnBlockCipher::proccess_block_decrypt(Bytes block, Bytes& feedback) {
    Bytes out{};
    if (m_mode == ECB) {
        out = block_cipher_decrypt(block);
    } else if (m_mode == CBC) {
        out = {
            XOR_two_vectors_sagnificant(feedback, block_cipher_decrypt(block))
        };
        feedback = block;
    } else if (m_mode == CFB) {
        out = {
            XOR_two_vectors_sagnificant(block, block_cipher_encrypt(feedback))
        };
        feedback = block;
    } else if (m_mode == OFB) {
        feedback = block_cipher_encrypt(feedback);
        out      = {XOR_two_vectors_sagnificant(block, feedback)};
    } else if (m_mode == CTR) {
        out = {
            XOR_two_vectors_sagnificant(block, block_cipher_encrypt(feedback))
        };
        increment_byte_vector(feedback);
    } else
        throw std::runtime_error("Bad mode while block decrypting");
    return out;
}

Bytes OwnBlockCipher::encrypt(Bytes plainText, Bytes IV, Paddings pad) {
    add_padding(plainText, pad);
    Bytes cipherText{}, feedback{generate_IV(IV, cipherText)};
    // P = P0 || P1 || ... || Pn
    // C = C0 || C1 || ... || Cn
    while (!plainText.empty()) {
        // Дурачок, куда за цикл выносишь то
        auto begin{plainText.begin()};
        auto end{
            plainText.size() > BLOCK_SIZE ? begin + BLOCK_SIZE : plainText.end()
        };
        Bytes block{begin, end};
        auto res{proccess_block_encrypt(block, feedback)};
        cipherText.insert(cipherText.end(), res.begin(), res.end());
        plainText.erase(begin, end);
    }
    return cipherText;
}

Bytes OwnBlockCipher::decrypt(Bytes cipherText, Bytes IV, Paddings pad) {
    is_valid_padding_mode(pad);
    Bytes plainText{}, feedback{IV};
    while (!cipherText.empty()) {
        auto begin{cipherText.begin()};
        auto end{
            cipherText.size() > BLOCK_SIZE ? begin + BLOCK_SIZE
                                           : cipherText.end()
        };
        Bytes block{begin, end};
        auto res{proccess_block_decrypt(block, feedback)};
        plainText.insert(plainText.end(), res.begin(), res.end());
        cipherText.erase(begin, end);
    }
    cut_padding(plainText, pad);
    return plainText;
}
