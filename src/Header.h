#pragma once
#include "libs.h"



//sha3 headers
template<typename T>
T RotateRight(T value, unsigned int count);
void SHA3_256Sponge(const uint8_t* message, size_t message_size, uint8_t* digest);


//authentification 
std::string Key();
std::string generateR(std::string side);
std::string generateID(std::string side);
std::string Concatenation(std::initializer_list<std::string> strings);

//hmac header
std::string HMAC_SHA3_256(const std::string& message, const std::string& key);

