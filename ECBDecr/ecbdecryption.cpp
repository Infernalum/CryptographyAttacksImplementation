#include <cpr/cpr.h>

#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

#include "base64.hpp"

using namespace std::this_thread;
using namespace std::chrono;

using string = std::string;
template <class T>
using vector = std::vector<T>;

enum Modes { ECB = 0, CBC };
std::map<Modes, string> ModesStr{
    {ECB, "ECB"},
    {CBC, "CBC"}
};

static const unsigned char initialChar{'a'};
static const size_t BLOCK_SIZE{16};

static const string host{"http://localhost:8080"}, iserId{"Infernalum"};
static const size_t totalChallenges{5}, bogusTextSize{3 * BLOCK_SIZE};
static size_t challengeId{1};

static string basicURL{host + "/api/EcbDecryption/" + iserId + '/'};

auto is_controller_active() {
    auto r = cpr::Get(cpr::Url{host + "/api/EcbDecryption"});
    return r.text == "operating";
}

auto post(const string& plainText) {
    cpr::Response r;
    do {
        r = {
            cpr::Post(
                cpr::Url{basicURL + std::to_string(challengeId) + "/noentropy"},
                cpr::Body{  nlohmann::json(base64::to_base64(plainText)).dump()},
                cpr::Header{                 {"Content-Type", "application/json"}}
            )
        };
    } while (r.status_code == 0);
    return base64::from_base64(r.text);
}

// Проверка только на то, что используется ECB
auto search_edential_blocks(const string& ctext) {
    // Перебираем для верности все что можно, а то хрен знает, сколько там в
    // начале добавилось, можно было и больше размера блока
    auto size{ctext.size() - 2 * BLOCK_SIZE};
    for (size_t i = 0; i < size; ++i) {
        string block{ctext.begin() + i, ctext.begin() + i + BLOCK_SIZE};
        auto edential{ctext.find(block, i + BLOCK_SIZE)};
        if (edential != string::npos) return edential;
    }
    return string::npos;
}

auto verify() {
    auto r{cpr::Get(cpr::Url{basicURL + std::to_string(challengeId) + "/verify"}
    )};
    return r.text;
}

// Выравниваем длину так, чтобы граница нашего ОТ и target_data совпала
// с границей блока (Миша, все х*~ня, давай по-новой)
auto aligning_bogus_text(string& bogusText) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        // bogusText.erase(bogusText.end() - BLOCK_SIZE, bogusText.end());
        // auto real{base64::from_base64(verify())};
        // bogusText += {real.begin(), real.begin() + BLOCK_SIZE};
        auto ctext{post(bogusText)};
        auto pos{search_edential_blocks(ctext)};
        string cblock{ctext.begin() + pos, ctext.begin() + pos + BLOCK_SIZE};
        vector<size_t> positions;
        pos = ctext.find(cblock, 0);
        while (pos != string::npos) {
            positions.push_back(pos);
            pos = ctext.find(cblock, pos + 1);
        }
        if (positions.size() == 3) {
            return positions[2] + BLOCK_SIZE;
        }
        bogusText += initialChar;
    }
    return string::npos;
}

// pos -
auto bruteforce_block(
    string ptext, string& registr, const size_t targetDataPos, const size_t& pos
) {
    string targetDataBlock{};
    // Дополняем шифруемый текст блоком, по которому будем сравнивать
    string bogusText{ptext + string(BLOCK_SIZE, initialChar)};
    for (size_t i = 1; i <= BLOCK_SIZE; ++i) {
        bogusText.pop_back();
        auto ctext{post(bogusText)};
        // Блок ШТ, соответствующего bogus:16-i || target_data:i
        string expected{ctext.begin() + pos, ctext.begin() + pos + BLOCK_SIZE};
        // Сдвигаем регистр влево
        registr.erase(registr.begin());
        // Подбираем i-тый с конца символ
        bool fl{false};
        for (size_t symbol = 0; symbol < 256; ++symbol) {
            // sleep_for(nanoseconds(1000000));
            auto ctext2{post(ptext + registr + char(symbol))};
            string actual{
                ctext2.begin() + targetDataPos,
                ctext2.begin() + targetDataPos + BLOCK_SIZE
            };
            if (expected == actual) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << unsigned(symbol);
                registr.push_back(symbol);
                targetDataBlock.push_back(symbol);
                fl = true;
                break;
            }
        }
        if (!fl) {
            throw std::runtime_error("Invalide bruteforce");
        }
    }
    return targetDataBlock;
}

auto decrypt_target_data(string& bogusText, size_t targetDataPos, size_t pos) {
    size_t targetDataBlocks{(post(bogusText).size() - pos) / BLOCK_SIZE};
    string targetData{};

    // Самая важная фиговина
    string registr(BLOCK_SIZE, 'a');
    for (size_t i = 0; i < targetDataBlocks; ++i) {
        std::cout << std::dec << "\tBlock #" << i << ":\t";
        targetData += bruteforce_block(bogusText, registr, targetDataPos, pos);
        pos += BLOCK_SIZE;
        std::cout << '\n';
    };
    return targetData;
}

auto ECBDecryption(const string& ptext) {
    string bogusText{ptext};
    // targetDataPos - индекс, с которого начинается блок ШТ, соответствующий
    // target_data; при добавлении к bogusText еще чего-то, он будет указывать
    // на первый блок, содержащий данные из target_data()
    auto targetDataPos{aligning_bogus_text(bogusText)};
    if (targetDataPos == string::npos) {
        throw std::runtime_error("It didn't work out =(");
    }
    return decrypt_target_data(bogusText, targetDataPos, targetDataPos);
}

int main(int argc, char** argv) {
    if (!is_controller_active()) return -1;

    for (challengeId; challengeId <= totalChallenges; ++challengeId) {
        string bogusText(bogusTextSize, initialChar);
        auto ctext{post(bogusText)};
        auto ind{search_edential_blocks(ctext)};
        if (ind == string::npos) continue;
        std::cout << "Decrypted text:\n";
        auto expected{base64::from_base64(verify())};
        // for (const unsigned char& ch : expected) {
        //     std::cout << ch << ' ';
        // }
        auto actual{ECBDecryption(bogusText)};
        // from_base убирает из оригинала сразу нули в конце
        while (actual.back() == 0) actual.pop_back();

        if (expected == actual) {
            std::cout << "Grac!\n";
        }
    }

    return 0;
}