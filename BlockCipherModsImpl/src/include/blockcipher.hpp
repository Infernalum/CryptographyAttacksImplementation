#include <openssl/evp.h>
#include <openssl/rand.h>

#include <bitset>
#include <exception>
#include <iomanip>
#include <memory>
#include <unordered_map>
#include <vector>

typedef uint8_t byte;
using EVP_CIPHER_CTX_free_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using ustring                        = std::basic_string<byte>;
using Bytes                          = std::vector<byte>;

static const unsigned int KEY_SIZE   = 16;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int IV_SIZE    = 16;

enum Modes { ECB = 0, CBC, CFB, OFB, CTR };
enum Paddings { DEFAULT_PADDING = 0, NON, PKCS7 };

static const std::vector<std::pair<Modes, Paddings>> possibleModes{
    {ECB, PKCS7},
    {CBC, PKCS7},
    {CFB,   NON},
    {OFB,   NON},
    {CTR,   NON}
};

Bytes key_gen();
Bytes IV_gen();
// Ксорятся только наиболее значимые биты
Bytes XOR_two_vectors_sagnificant(const Bytes& vec1, const Bytes& vec2);
Bytes& increment_byte_vector(Bytes& vector);

class OwnBlockCipher {
   public:
    inline OwnBlockCipher(Modes mode = ECB, Bytes key = {0x0}) :
        m_mode{mode},
        m_key{key},
        m_ctx{EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free} {
        // Режим паддинга убирается из контекста при инициализации
        EVP_CIPHER_CTX_set_padding(m_ctx.get(), 0);
    };

    inline OwnBlockCipher& mode(Modes _mode) {
        m_mode = _mode;
        return *this;
    };
    inline Modes mode() const { return m_mode; };

    inline OwnBlockCipher& key(const Bytes& _key) {
        m_key = _key;
        return *this;
    };
    inline const Bytes& key() const { return m_key; }

    Bytes encrypt(Bytes data, Bytes IV, Paddings pad = DEFAULT_PADDING);
    Bytes decrypt(Bytes data, Bytes IV, Paddings pad = DEFAULT_PADDING);

   private:
    // Шифрование одного блока алгоритмом AES (блок уже попадает с паддингом)
    Bytes block_cipher_encrypt(const Bytes& data);
    Bytes block_cipher_decrypt(const Bytes& data);

    // Реализация одного шага режимов шифрования
    Bytes proccess_block_encrypt(Bytes plainBlock, Bytes& feedback);
    Bytes proccess_block_decrypt(Bytes plainBlock, Bytes& feedback);

    // Генерирует IV или счетчик (если того требует режим) и конкатенирует в
    // начало шифртекста
    Bytes& generate_IV(Bytes& IV, Bytes& cipherText);

    // Для паддинга
    void is_valid_padding_mode(Paddings& paddingMode);
    Bytes& add_padding(Bytes& plainText, Paddings& pad);
    Bytes& cut_padding(Bytes& plainText, Paddings& pad);
    // (Хрень) Дополняет от до кратности размеру блока по PKCS7
    void PKCS7(Bytes& plainText);

    Modes m_mode;
    Bytes m_key;
    EVP_CIPHER_CTX_free_ptr m_ctx;
};
