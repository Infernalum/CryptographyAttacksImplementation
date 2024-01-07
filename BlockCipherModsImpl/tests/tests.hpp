#include "blockcipher.hpp"

template <class T>
using vector = std::vector<T>;
using string = std::string;

// Небезопасно, ну и пофек
#define str_to_ustr(str) reinterpret_cast<const byte*>(str)

static const vector<std::pair<string, string>> CBCs{
    {"140b41b22a29beb4061bda66b6747e14",
     "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e"
     "4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"},
    {"140b41b22a29beb4061bda66b6747e14",
     "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e7"
     "13ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"},
};

static const vector<std::pair<string, string>> CTRs{
    {"36f18357be4dbd77f050515c73fcf9f2",
     "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388"
     "d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51"
     "eeca32eabedd9afa9329"      },
    {"36f18357be4dbd77f050515c73fcf9f2",
     "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e"
     "311bde9d4e01726d3184c34451"}
};

Bytes from_hexstr_to_bytes(const string& str);

Bytes gen_text(size_t length);

Bytes official_encrypt(
    const Bytes& ptext, Modes mode, const Bytes& key, const Bytes IV = {}
);
