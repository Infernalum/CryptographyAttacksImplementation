#include <cpr/cpr.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "base64.hpp"

using string = std::string;

static const string host{"http://localhost:8080"}, iserId{"Infernalum"};
static const size_t challengeId{2}, counterPad{16};
static const string basicURL{
    host + "/api/StreamIntegrity/" + iserId + '/' + std::to_string(challengeId)
};
static const string plainText{"Here is some data to encrypt for you"};
static const string encryptedText{"Token: 8ce08ad2d48d7d356db43"};

int is_controller_active() {
    auto r = cpr::Get(cpr::Url{host + "/api/StreamIntegrity"});
    return r.text == "operating";
}

string get_encrypted_msg() {
    auto r = cpr::Get(cpr::Url{basicURL + "/noentropy"});
    return r.text;
}

string encrypt_by_key(const string& key, const string& encrypted) {
    auto& smaller{key.size() < encrypted.size() ? key : encrypted};
    auto& bigger{key.size() < encrypted.size() ? encrypted : key};
    string res(smaller.size(), ' ');
    std::transform(
        smaller.begin(), smaller.end(), bigger.begin(), res.begin(),
        std::bit_xor<>()
    );
    return res;
}
int main(int argc, char** argv) {
    if (!is_controller_active()) return -1;

    auto base64{base64::from_base64(get_encrypted_msg())};
    auto counter{base64.substr(0, 16)};
    auto encryptedMsg{base64.substr(16)};
    auto key{encrypt_by_key(plainText, encryptedMsg)};

    auto postR = cpr::Post(
        cpr::Url{
            basicURL
    },
        cpr::Body{
            nlohmann::json(
                base64::to_base64(counter + encrypt_by_key(key, encryptedText))
            )
                .dump()
        },
        cpr::Header{{"Content-Type", "application/json"}}
    );

    std::cout << postR.text << std::endl;
    return 0;
}