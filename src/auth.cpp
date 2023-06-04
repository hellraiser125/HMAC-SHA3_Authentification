#include "Header.h"

std::string Key() {


    std::random_device rd;
    std::mt19937 gen(rd() + (unsigned)time(nullptr));

    // Генеруємо 32 байти випадкових даних
    std::uniform_int_distribution<int> distrib(0, 255);
    std::string Key;

    for (int i = 0; i < 32; ++i) {
        int randomNumber = distrib(gen);
        Key += std::to_string(randomNumber);
    }


    return Key;
}

///////////////////////////////////////////////////////////////
std::string generateR(std::string side) {

    std::random_device rd;
    std::mt19937 gen(rd() + (unsigned)time(nullptr));

    // Генеруємо 32 байти випадкових даних
    std::uniform_int_distribution<int> distrib(0, 9);

    for (int i = 0; i < 10; ++i) {
        int randomNumber = distrib(gen);
        side += std::to_string(randomNumber);
    }

    return side;
}

std::string generateID(std::string side) {

    // Використовуємо випадковий генератор для генерації випадкових чисел
    std::random_device rd;
    std::mt19937 gen(rd());

    // Генеруємо випадкове число
    std::uniform_int_distribution<int> distrib(1000, 9999);
    int random_num = distrib(gen);

    // Конвертуємо число в рядок
    std::stringstream ss;
    ss << random_num;
    side = ss.str();

    // Повертаємо унікальний ID
    return side;

}
//////////////////////////////////////////////////

//rA || rB з IB
std::string Concatenation(std::initializer_list<std::string> strings) {

    std::string data;
    for (const std::string& str : strings) {
        data += str;
    }
    return data;
}



//hA1 = результат гешування rA || rB || IB
// HMAC-SHA3_256 function
std::string HMAC_SHA3_256(const std::string& key, const std::string& message) {
    const unsigned int block_size = 136;
    const unsigned int digest_size = 32;

    uint8_t key_pad[block_size];
    std::memset(key_pad, 0x00, block_size);

    if (key.size() > block_size) {
        SHA3_256Sponge(reinterpret_cast<const uint8_t*>(key.c_str()), key.size(), key_pad);
    }
    else {
        std::memcpy(key_pad, key.c_str(), key.size());
    }

    for (unsigned int i = 0; i < block_size; i++) {
        key_pad[i] ^= 0x36;
    }

    uint8_t* inner_input = new uint8_t[block_size + message.size()];
    std::memcpy(inner_input, key_pad, block_size);
    std::memcpy(inner_input + block_size, message.c_str(), message.size());

    uint8_t inner_digest[digest_size];
    SHA3_256Sponge(inner_input, block_size + message.size(), inner_digest);

    for (unsigned int i = 0; i < block_size; i++) {
        key_pad[i] ^= 0x36 ^ 0x5C;
    }

    uint8_t outer_input[block_size + digest_size];
    std::memcpy(outer_input, key_pad, block_size);
    std::memcpy(outer_input + block_size, inner_digest, digest_size);

    uint8_t outer_digest[digest_size];
    SHA3_256Sponge(outer_input, block_size + digest_size, outer_digest);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_size; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(outer_digest[i]);
    }
    delete[] inner_input;

    return oss.str();
}