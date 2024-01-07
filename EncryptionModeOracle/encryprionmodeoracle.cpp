#include <cpr/cpr.h>

#include <exception>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

#include "base64.hpp"

using string = std::string;

enum Modes { ECB = 0, CBC };
std::map<Modes, string> ModesStr{
    {ECB, "ECB"},
    {CBC, "CBC"}
};

static const size_t BLOCK_SIZE{16};

static const string host{"http://localhost:8080"}, iserId{"Infernalum"};
static size_t challengeId{1}, totalChallenges{100},
    bogusTextSize{3 * BLOCK_SIZE};

static string basicURL{host + "/api/EncryptionModeOracle/" + iserId + '/'};

int is_controller_active() {
    auto r = cpr::Get(cpr::Url{host + "/api/EncryptionModeOracle"});
    return r.text == "operating";
}

Modes search_edential_blocks(const string& ctext) {
    // Перебираем для верности все что можно, а то фиг знает, сколько там в
    // начале добавилось, можно было и больше размера блока
    auto size{BLOCK_SIZE + 1};
    for (size_t i = 0; i < size; ++i) {
        string block{ctext.begin() + i, ctext.begin() + i + BLOCK_SIZE};
        if (ctext.find(block, i + BLOCK_SIZE) != string::npos) return ECB;
    }
    return CBC;
}

Modes verify() {
    auto r{cpr::Get(cpr::Url{basicURL + std::to_string(challengeId) + "/verify"}
    )};
    return r.text == "ECB" ? ECB : CBC;
}

int main(int argc, char** argv) {
    if (!is_controller_active()) return -1;

    size_t wrongPredictions{0};
    string bogusText(bogusTextSize, 'a');
    for (challengeId; challengeId < totalChallenges; ++challengeId) {
        auto r{
            cpr::Post(
                cpr::Url{basicURL + std::to_string(challengeId) + "/noentropy"},
                cpr::Body{  nlohmann::json(base64::to_base64(bogusText)).dump()},
                cpr::Header{                 {"Content-Type", "application/json"}}
            )
        };
        if (r.text.empty()) {
            // Х*р знает почему с шансом 1:10000 cpr::Post возвращает пустое
            // тело
            std::cout << "Empty Body of the response!\n";
            throw std::runtime_error("What a....fuuuck..");
        }
        auto ctext{base64::from_base64(r.text)};
        auto actual{search_edential_blocks(ctext)};
        auto expected{verify()};
        if (actual == expected) {
            // std::cout << "Oracle is working!\n";
        } else {
            std::cout << "Challenge #" << challengeId << "; Wrong! Expected "
                      << ModesStr[expected] << "; actual " << ModesStr[actual]
                      << std::endl;
            ++wrongPredictions;
        }
    }
    std::cout << "Total challenges:  " << totalChallenges << std::endl;
    std::cout << "Wrong predictions: " << wrongPredictions << std::endl;
    return 0;
}