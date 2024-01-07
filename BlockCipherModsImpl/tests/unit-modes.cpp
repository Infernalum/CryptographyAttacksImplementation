#include <gtest/gtest.h>

#include "tests.hpp"

void ENCRYPT_WITH_IV(Modes mode, size_t size) {
    Bytes key{key_gen()}, IV{IV_gen()}, plainText{gen_text(size)};
    OwnBlockCipher blockCipher{mode, key};
    auto actual{blockCipher.encrypt(plainText, IV)};
    auto expected{official_encrypt(plainText, mode, key, IV)};
    ASSERT_EQ(expected, actual);
}

void ENCRYPT_WITHOUT_IV(Modes mode, size_t size) {
    Bytes key{key_gen()}, IV{}, plainText{gen_text(size)};
    OwnBlockCipher blockCipher{mode, key};
    auto actual{blockCipher.encrypt(plainText, {})};
    if (mode != ECB) {
        IV = {actual.begin(), actual.begin() + IV_SIZE};
        actual.erase(actual.begin(), actual.begin() + IV_SIZE);
    }
    auto expected{official_encrypt(plainText, mode, key, IV)};
    ASSERT_EQ(expected, actual);
}

void DECRYPT(Modes mode, size_t size) {
    Bytes key{key_gen()}, IV{IV_gen()}, plainText{gen_text(size)};
    auto cipherText{official_encrypt(plainText, mode, key, IV)};
    OwnBlockCipher blockCipher{mode, key};
    auto actual{blockCipher.decrypt(cipherText, IV)};
    ASSERT_EQ(plainText, actual);
}

namespace ECB_test {
TEST(ECB_Encrypt, _1BlOCK_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(ECB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(ECB, BLOCK_SIZE - 2);
}
TEST(ECB_Encrypt, _1BlOCK_MULTIPLE) {
    ENCRYPT_WITH_IV(ECB, BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(ECB, BLOCK_SIZE);
}
TEST(ECB_Encrypt, _More1Block_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(ECB, 2 * BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(ECB, 2 * BLOCK_SIZE - 2);
}
TEST(ECB_Encrypt, _More1Block_MULTIPLE) {
    ENCRYPT_WITH_IV(ECB, 2 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(ECB, 2 * BLOCK_SIZE);
}
TEST(ECB_Encrypt, _2_5_Blocks) {
    ENCRYPT_WITH_IV(ECB, 2.5 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(ECB, 2.5 * BLOCK_SIZE);
}

TEST(ECB_Decrypt, _1BlOCK_NOT_MULTIPLE) { DECRYPT(ECB, BLOCK_SIZE - 2); }
TEST(ECB_Decrypt, _1BlOCK_MULTIPLE) { DECRYPT(ECB, BLOCK_SIZE); }
TEST(ECB_Decrypt, _More1Block_NOT_MULTIPLE) {
    DECRYPT(ECB, 2 * BLOCK_SIZE - 2);
}
TEST(ECB_Decrypt, _More1Block_MULTIPLE) { DECRYPT(ECB, 2 * BLOCK_SIZE); }
TEST(ECB_Decrypt, _2_5_Blocks) { DECRYPT(ECB, 2.5 * BLOCK_SIZE); }

}  // namespace ECB_test

namespace CBC_test {
TEST(CBC_Encrypt, _1_BlOCK_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(CBC, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(CBC, BLOCK_SIZE - 2);
}
TEST(CBC_Encrypt, _1_BlOCK_MULTIPLE) {
    ENCRYPT_WITH_IV(CBC, BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CBC, BLOCK_SIZE);
}
TEST(CBC_Encrypt, _More1Block_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(CBC, 2 * BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(CBC, 2 * BLOCK_SIZE - 2);
}
TEST(CBC_Encrypt, _More1Block_MULTIPLE) {
    ENCRYPT_WITH_IV(CBC, 2 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CBC, 2 * BLOCK_SIZE);
}
TEST(CBC_Encrypt, _2_5_Blocks) {
    ENCRYPT_WITH_IV(CBC, 2.5 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CBC, 2.5 * BLOCK_SIZE);
}

TEST(CBC_Decrypt, _1BlOCK_NOT_MULTIPLE) { DECRYPT(CBC, BLOCK_SIZE - 2); }
TEST(CBC_Decrypt, _1BlOCK_MULTIPLE) { DECRYPT(CBC, BLOCK_SIZE); }
TEST(CBC_Decrypt, _More1Block_NOT_MULTIPLE) {
    DECRYPT(CBC, 2 * BLOCK_SIZE - 2);
}
TEST(CBC_Decrypt, _More1Block_MULTIPLE) { DECRYPT(CBC, 2 * BLOCK_SIZE); }
TEST(CBC_Decrypt, _2_5_Blocks) { DECRYPT(CBC, 2.5 * BLOCK_SIZE); }

}  // namespace CBC_test

namespace CBF_test {
TEST(CFB_Encrypt, _1_BlOCK_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(CFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(CFB, BLOCK_SIZE - 2);
}
TEST(CFB_Encrypt, _1_BlOCK_MULTIPLE) {
    ENCRYPT_WITH_IV(CFB, BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CFB, BLOCK_SIZE);
}
TEST(CFB_Encrypt, _More1Block_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(CFB, 2 * BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(CFB, 2 * BLOCK_SIZE - 2);
}
TEST(CFB_Encrypt, _More1Block_MULTIPLE) {
    ENCRYPT_WITH_IV(CFB, 2 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CFB, 2 * BLOCK_SIZE);
}
TEST(CFB_Encrypt, _2_5_Blocks) {
    ENCRYPT_WITH_IV(CFB, 2.5 * BLOCK_SIZE);
    ENCRYPT_WITHOUT_IV(CFB, 2.5 * BLOCK_SIZE);
}

TEST(CFB_Decrypt, _1BlOCK_NOT_MULTIPLE) { DECRYPT(CFB, BLOCK_SIZE - 2); }
TEST(CFB_Decrypt, _1BlOCK_MULTIPLE) { DECRYPT(CFB, BLOCK_SIZE); }
TEST(CFB_Decrypt, _More1Block_NOT_MULTIPLE) {
    DECRYPT(CFB, 2 * BLOCK_SIZE - 2);
}
TEST(CFB_Decrypt, _More1Block_MULTIPLE) { DECRYPT(CFB, 2 * BLOCK_SIZE); }
TEST(CFB_Decrypt, _2_5_Blocks) { DECRYPT(CFB, 2.5 * BLOCK_SIZE); }
}  // namespace CBF_test

namespace OFB_test {
TEST(OFB_Encrypt, _1_BlOCK_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(OFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(OFB, BLOCK_SIZE - 2);
}
TEST(OFB_Encrypt, _1_BlOCK_MULTIPLE) {
    ENCRYPT_WITH_IV(OFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(OFB, BLOCK_SIZE);
}
TEST(OFB_Encrypt, _More1Block_NOT_MULTIPLE) {
    ENCRYPT_WITH_IV(OFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(OFB, 2 * BLOCK_SIZE - 2);
}
TEST(OFB_Encrypt, _More1Block_MULTIPLE) {
    ENCRYPT_WITH_IV(OFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(OFB, 2 * BLOCK_SIZE);
}
TEST(OFB_Encrypt, _2_5_Blocks) {
    ENCRYPT_WITH_IV(OFB, BLOCK_SIZE - 2);
    ENCRYPT_WITHOUT_IV(OFB, 2.5 * BLOCK_SIZE);
}

TEST(OFB_Decrypt, _1BlOCK_NOT_MULTIPLE) { DECRYPT(OFB, BLOCK_SIZE - 2); }
TEST(OFB_Decrypt, _1BlOCK_MULTIPLE) { DECRYPT(OFB, BLOCK_SIZE); }
TEST(OFB_Decrypt, _More1Block_NOT_MULTIPLE) {
    DECRYPT(OFB, 2 * BLOCK_SIZE - 2);
}
TEST(OFB_Decrypt, _More1Block_MULTIPLE) { DECRYPT(OFB, 2 * BLOCK_SIZE); }
TEST(OFB_Decrypt, _2_5_Blocks) { DECRYPT(OFB, 2.5 * BLOCK_SIZE); }
}  // namespace OFB_test

namespace CTR_test {
TEST(CTR_Encrypt, _1BlOCK_NOT_MULTIPLE) {
    ENCRYPT_WITHOUT_IV(CTR, BLOCK_SIZE - 2);
}
TEST(CTR_Encrypt, _1BlOCK_MULTIPLE) { ENCRYPT_WITHOUT_IV(CTR, BLOCK_SIZE); }
TEST(CTR_Encrypt, _More1Block_NOT_MULTIPLE) {
    ENCRYPT_WITHOUT_IV(CTR, 2 * BLOCK_SIZE - 2);
}
TEST(CTR_Encrypt, _More1Block_MULTIPLE) {
    ENCRYPT_WITHOUT_IV(CTR, 2 * BLOCK_SIZE);
}
TEST(CTR_Encrypt, _2_5_Blocks) { ENCRYPT_WITHOUT_IV(CTR, 2.5 * BLOCK_SIZE); }

TEST(CTR_Decrypt, _1BlOCK_NOT_MULTIPLE) { DECRYPT(CTR, BLOCK_SIZE - 2); }
TEST(CTR_Decrypt, _1BlOCK_MULTIPLE) { DECRYPT(CTR, BLOCK_SIZE); }
TEST(CTR_Decrypt, _More1Block_NOT_MULTIPLE) {
    DECRYPT(CTR, 2 * BLOCK_SIZE - 2);
}
TEST(CTR_Decrypt, _More1Block_MULTIPLE) { DECRYPT(CTR, 2 * BLOCK_SIZE); }
TEST(CTR_Decrypt, _2_5_Blocks) { DECRYPT(CTR, 2.5 * BLOCK_SIZE); }
}  // namespace CTR_test

void decrypt_texts_with_IV_concat(
    const vector<std::pair<string, string>> pairs, Modes mode
) {
    for (const auto& [key_str, text_str] : pairs) {
        std::cout << "\tCipher text: " << text_str << '\n';
        auto key{from_hexstr_to_bytes(key_str)},
            text{from_hexstr_to_bytes(text_str)};
        Bytes IV{text.begin(), text.begin() + IV_SIZE};
        text.erase(text.begin(), text.begin() + IV_SIZE);
        OwnBlockCipher blockCipher{mode, key};
        auto plainText{blockCipher.decrypt(text, IV)};
        std::cout << "\tPlain Text:  ";
        for (const auto& s : plainText) std::cout << s;
        std::cout << std::endl;
    }
}

int main(int argc, char** argv) {
    std::cout << "CBCs:\n";
    decrypt_texts_with_IV_concat(CBCs, CBC);
    std::cout << "CTRs:\n";
    decrypt_texts_with_IV_concat(CTRs, CTR);
    ::testing::InitGoogleTest(&argc, argv);
    // OPENSSL_cleanse(key.data(), KEY_SIZE);
    // OPENSSL_cleanse(IV.data(), BLOCK_SIZE);

    return RUN_ALL_TESTS();
}
