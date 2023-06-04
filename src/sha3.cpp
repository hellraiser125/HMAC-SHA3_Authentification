#include "Header.h"
// SHA-3 256-bit constants
const uint64_t SHA3_CONSTANTS[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// SHA-3 256-bit rotation offsets
const unsigned int SHA3_ROTATION_OFFSETS[24] = {
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56
};

// Right rotate function
template<typename T>
T RotateRight(T value, unsigned int count) {
    return (value >> count) | (value << (sizeof(T) * 8 - count));
}

// SHA-3 256-bit sponge function
void SHA3_256Sponge(const uint8_t* message, size_t message_size, uint8_t* digest) {
    const unsigned int block_size = 136;
    const unsigned int digest_size = 32;

    // Initialize state
    uint64_t state[25] = { 0 };

    // Absorb phase
    for (size_t i = 0; i < message_size; ++i) {
        state[i % block_size / 8] ^= static_cast<uint64_t>(message[i]) << ((i % 8) * 8);
        if ((i + 1) % block_size == 0) {
            // Permutation step
            for (unsigned int j = 0; j < 24; ++j) {
                // Theta step
                uint64_t c[5] = { 0 };
                for (unsigned int x = 0; x < 5; ++x) {
                    for (unsigned int y = 0; y < 5; ++y) {
                        c[x] ^= state[x + 5 * y];
                    }
                }
                for (unsigned int x = 0; x < 5; ++x) {
                    uint64_t d = RotateRight(c[(x + 1) % 5], 1) ^ c[(x + 4) % 5];
                    for (unsigned int y = 0; y < 5; ++y) {
                        state[x + 5 * y] ^= d;
                    }
                }

                // Rho and Pi steps
                uint64_t last = state[1];
                for (unsigned int x = 0; x < 5; ++x) {
                    for (unsigned int y = 0; y < 5; ++y) {
                        uint64_t temp = state[x + 5 * y];
                        state[x + 5 * y] = RotateRight(last, SHA3_ROTATION_OFFSETS[x + 5 * y]);
                        last = temp;
                    }
                }

                // Chi step
                for (unsigned int y = 0; y < 5; ++y) {
                    uint64_t d[5] = { 0 };
                    for (unsigned int x = 0; x < 5; ++x) {
                        d[x] = state[x + 5 * y];
                    }
                    for (unsigned int x = 0; x < 5; ++x) {
                        state[x + 5 * y] = d[x] ^ ((~d[(x + 1) % 5]) & d[(x + 2) % 5]);
                    }
                }

                // Iota step
                state[0] ^= (static_cast<uint64_t>(SHA3_CONSTANTS[j]) << ((1 << j) - 1));
            }
        }
    }

    // Squeeze phase
    std::memcpy(digest, state, digest_size);
}