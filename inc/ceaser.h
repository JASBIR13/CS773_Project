#ifndef CEASER_H
#define CEASER_H

#include <cstdint>
#include <vector>
#include <random>
#include <array>
#include <algorithm>

class CACHE;

constexpr int ADDRESS_BITS = 40;
constexpr int HALF_BITS = ADDRESS_BITS / 2;
constexpr int NUM_ROUNDS = 4;
constexpr int SBOX_OUTPUT_BITS = 20;
constexpr int SBOX_INPUT_BITS = 40;

class LLBC
{
public:
    struct FeistelKey
    {
        uint32_t round_keys[NUM_ROUNDS]; // Lower 20 bits used
    };

    FeistelKey keys;

    LLBC() { generate_keys(); }

    void generate_keys()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, (1U << 20) - 1);
        for (int i = 0; i < NUM_ROUNDS; ++i)
            keys.round_keys[i] = dist(gen);
    }

    uint64_t feistel_encrypt(uint64_t input) const
    {
        uint32_t L = (input >> HALF_BITS) & ((1ULL << HALF_BITS) - 1);
        uint32_t R = input & ((1ULL << HALF_BITS) - 1);
        for (int i = 0; i < NUM_ROUNDS; ++i)
        {
            uint32_t temp = L;
            L = R;
            R = temp ^ round_function(R, keys.round_keys[i]);
        }
        return ((uint64_t)L << HALF_BITS) | R;
    }

    uint64_t feistel_decrypt(uint64_t input) const
    {
        uint32_t L = (input >> HALF_BITS) & ((1ULL << HALF_BITS) - 1);
        uint32_t R = input & ((1ULL << HALF_BITS) - 1);
        for (int i = NUM_ROUNDS - 1; i >= 0; --i)
        {
            uint32_t temp = R;
            R = L;
            L = temp ^ round_function(R, keys.round_keys[i]);
        }
        return ((uint64_t)L << HALF_BITS) | R;
    }

    // Use mid-bits for set indexing to leverage avalanche effect
    uint32_t get_set_index(uint64_t encrypted_tag, uint32_t num_sets) const
    {
        uint32_t set_bits = log2(num_sets);
        // Extract middle bits for better entropy distribution
        return (encrypted_tag >> (ADDRESS_BITS / 2 - set_bits / 2)) & (num_sets - 1);
    }

private:
    struct SBox
    {
        std::array<uint64_t, SBOX_OUTPUT_BITS> masks;

        SBox()
        {
            thread_local std::mt19937_64 gen(std::random_device{}());
            std::uniform_int_distribution<int> dist(0, SBOX_INPUT_BITS - 1);
            for (auto &mask : masks)
            {
                mask = 0;
                for (int j = 0; j < 20; ++j)
                {
                    mask |= (1ULL << dist(gen));
                }
            }
        }
    };

    struct PBox
    {
        std::array<int, SBOX_OUTPUT_BITS> permutation;

        PBox()
        {
            thread_local std::mt19937 gen(std::random_device{}());
            for (int i = 0; i < SBOX_OUTPUT_BITS; ++i)
                permutation[i] = i;
            std::shuffle(permutation.begin(), permutation.end(), gen);
        }
    };


    SBox sbox{};
    PBox pbox{};

    

    uint32_t round_function(uint32_t r, uint32_t key) const
    {
        uint64_t input = (static_cast<uint64_t>(r) << 20) | key;
        uint32_t sbox_out = 0;

        // Apply S-Box
        for (int i = 0; i < SBOX_OUTPUT_BITS; ++i)
        {
            uint64_t mask = sbox.masks[i];
            sbox_out |= (__builtin_popcountll(input & mask) % 2) << i;
        }

        // Apply P-Box
        uint32_t pbox_out = 0;
        for (int i = 0; i < SBOX_OUTPUT_BITS; ++i)
        {
            pbox_out |= ((sbox_out >> pbox.permutation[i]) & 1) << i;
        }

        return pbox_out;
    }
};


class CEASERController
{
public:
    LLBC currKey;
    LLBC nextKey;

    uint32_t SPtr = 0;
    uint8_t active_epoch = 0;
    uint64_t last_rekey_cycle = 0;
    uint64_t rekey_interval = 1000;

    std::vector<uint8_t> set_epoch;

    CEASERController(uint32_t num_set) : set_epoch(num_set, active_epoch) {}

    void rekey_one_set(CACHE *cache, uint64_t current_cycle);

    const LLBC &get_key_for_set(uint32_t set) const
    {
        return (set_epoch[set] == active_epoch) ? currKey : nextKey;
    }

    uint8_t get_epoch_for_set(uint32_t set) const { return set_epoch[set]; }
};

#endif