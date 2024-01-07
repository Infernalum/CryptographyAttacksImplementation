#include <cmath>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <vector>

using json   = nlohmann::json;
using string = std::string;
using byte   = unsigned char;
template <class T>
using vector = std::vector<T>;
template <class T>
using _2DVector = vector<vector<T>>;

template <class T>
void make_all_combinations(
    const _2DVector<T>& allVecs, size_t vecIndex, vector<T> recursiveStack,
    _2DVector<T>& result
) {
    if (vecIndex >= allVecs.size()) {
        result.push_back(recursiveStack);
        return;
    }
    for (const auto& el : allVecs[vecIndex]) {
        auto combination = recursiveStack;
        combination.push_back(el);
        make_all_combinations(allVecs, vecIndex + 1, combination, result);
    }
}

static const std::regex allowed_PT_chars("[\\w\\d \t:()\\.,\\-\\'\\!\\?_@]");

void is_valid_CT(const string& CT, const int& upperB) {
    if (CT.length() % 2) throw std::length_error("Bad lenght of the CT.");
    if (!std::regex_match(CT, std::regex("^[0-9a-fA-F]*$")))
        throw std::invalid_argument("Forbidden char in the CT.");
    if (CT.length() / 2 < upperB)
        throw std::out_of_range("Not enough lenght of the CT.");
};

void is_valid_params(
    int argc, char** argv, int& lowerB, int& upperB, vector<string>& CTs
) {
    if (argc < 3) throw std::logic_error("invalid argument count.");
    lowerB = stoi(string(argv[1])), upperB = stoi(string(argv[2]));
    if ((lowerB < 0) || (upperB < 0) || (upperB - lowerB < 0))
        throw std::invalid_argument("Bad borders.");
    // Не забыть добавить execute_dir в cmakelists
    std::ifstream CTStream("../CTs.json");
    const auto jf{json::parse(CTStream)};
    const auto& cipherTexts = jf[0]["cipherTexts"];
    for (const auto& text : cipherTexts.items()) CTs.push_back(text.value());
    for (const auto& CT : CTs) is_valid_CT(CT, upperB);
}

auto htoi(const string& hex) {
    if (!std::regex_match(hex, std::regex("^[0-9a-fA-F]*$")))
        throw std::invalid_argument("Forbidden char in a hex string.");
    byte result(0), degree(0);
    for (auto it = hex.rbegin(); it != hex.rend(); ++it) {
        byte ch(*it);
        if (ch >= '0' && ch <= '9')
            ch -= '0';
        else if (ch >= 'a' && ch <= 'f')
            ch += (10 - 'a');
        else if (ch >= 'A' && ch <= 'F')
            ch += (10 - 'A');
        result += (ch * pow(16, degree++));
    }
    return result;
}

auto convert_CTs_2_dec(
    const int& lowerB, const int& upperB, const vector<string>& hexCTs
) {
    _2DVector<byte> decCTs;
    for (const auto& ciphertext : hexCTs) {
        vector<byte> binCT;
        for (size_t i = lowerB * 2; i < upperB * 2; i += 2) {
            string byte(ciphertext.substr(i, 2));
            binCT.push_back(htoi(byte));
        }
        decCTs.push_back(binCT);
    }
    return decCTs;
}

auto get_key_bytes(const _2DVector<byte>& CTs, int& lowerB, const int& upperB) {
    _2DVector<byte> result;
    for (size_t i = 0; i < upperB - lowerB; ++i) {
        vector<byte> possibleBytes;
        for (size_t key = 0; key < 256; ++key) {
            bool fl(true);
            for (const auto& CT : CTs) {
                char ch(CT[i] ^ key);
                if (!std::regex_match(string{ch}, allowed_PT_chars)) {
                    fl = false;
                    break;
                }
            }
            if (fl) possibleBytes.push_back(key);
        }
        result.push_back(possibleBytes);
    }
    return result;
};

auto decrypt_by_key(const _2DVector<byte>& decCTs, const vector<byte>& key) {
    vector<string> PT;
    auto keysize = key.size(), CTsize = decCTs.size();

    for (size_t CT_ind = 0; CT_ind < CTsize; ++CT_ind) {
        auto& cipherText(decCTs[CT_ind]);
        string decryptedText{};
        for (size_t i = 0; i < keysize; ++i) {
            auto decryptedByte(cipherText[i] ^ key[i]);
            // if ((decryptedByte > 'a' && decryptedByte < 'z') ||
            //     (decryptedByte > 'A' && decryptedByte < 'Z'))
            //     decryptedText += decryptedByte;
            // else
            //     decryptedText += '_';
            decryptedText += decryptedByte;
        }
        PT.push_back(decryptedText);
    }

    return PT;
}

void write_2_json(
    const _2DVector<string>& PTs, const _2DVector<byte> allPossibleCombinations
) {
    std::ofstream Out("../res.json");
    json res, variants;
    auto total_count = allPossibleCombinations.size();
    for (auto i = 0; i < total_count; ++i) {
        const auto& key(allPossibleCombinations[i]);
        const auto& texts(PTs[i]);
        string key_str{}, texts_str{};
        for (const auto& byte : key) (key_str += std::to_string(byte)) += ' ';
        key_str.pop_back();
        for (const auto& text : texts) (texts_str += text) += ' ';
        texts_str.pop_back();
        json oneVariant;
        oneVariant += json::object_t::value_type("Key", key_str);
        oneVariant += json::object_t::value_type("OpenText", texts_str);
        variants += oneVariant;
    }
    res += json::object_t::value_type("DecryptedTexts", variants);
    res >> Out;
}

void set_key_bytes(
    const size_t& lowerB, const size_t& upperB, _2DVector<byte>& possibleBytes
) {
    static const vector<byte> fixed{
        174, 129, 249, 220, 148, 212, 230, 66,  131, 173, 111, 220, 182, 236,
        156, 59,  83,  246, 62,  125, 65,  200, 245, 69,  203, 121, 195, 133,
        217, 182, 235, 158, 216, 133, 175, 195, 205, 151, 45,  202, 163, 81,
        114, 189, 160, 234, 142, 50,  139, 33,  161, 101, 6,   163, 122, 17,
        7,   78,  49,  29,  237, 140, 233, 87,  224, 164, 110, 142, 130, 18,
        118, 178, 24,  205, 48,  85,  56,  198, 13,  130, 189, 142, 186
    };

    for (size_t i = lowerB; i < upperB; ++i)
        if (fixed[i] != 0) possibleBytes[i - lowerB] = {fixed[i]};
}

int main(int argc, char** argv) {
    // Валидация параметров и шифртекстов из json'a
    int lowerB{-1}, upperB{-1};
    vector<string> hexCTs{};
    is_valid_params(argc, argv, lowerB, upperB, hexCTs);

    // Переводим шифртексты из hex в ascii
    auto decCTs           = convert_CTs_2_dec(lowerB, upperB, hexCTs);

    // Вычисляем возможные варианты для каждого байта ключа на основании
    // полученных байтов открытых текстов
    auto possibleKeyBytes = get_key_bytes(decCTs, lowerB, upperB);

    // Для установки каких-то конкретных битов для проверки
    set_key_bytes(lowerB, upperB, possibleKeyBytes);

    // Получаем все возможные комбинации байт ключа
    _2DVector<byte> allPossibleCombinations{};
    make_all_combinations(possibleKeyBytes, 0, {}, allPossibleCombinations);

    // Получаем расшифровки
    _2DVector<string> PTs{};
    for (const auto& key : allPossibleCombinations) {
        auto PT = decrypt_by_key(decCTs, key);
        PTs.push_back(PT);
    }

    // Выводим результат
    write_2_json(PTs, allPossibleCombinations);

    std::cout << "Total variants: " << allPossibleCombinations.size()
              << std::endl;
    return 0;
}
