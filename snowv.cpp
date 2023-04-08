#include <stdio.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>

#define vpset16(value) _mm256_set1_epi16(value)
typedef uint8_t u8;
typedef uint64_t u64;
const __m256i _snowv_mul = _mm256_blend_epi32(vpset16(0x990f), vpset16(0xc963), 0xf0);
const __m256i _snowv_inv = _mm256_blend_epi32(vpset16(-0xcc87), vpset16(-0xe4b1), 0xf0);
const __m128i _snowv_aead = _mm_lddqu_si128((__m128i *)"AlexEkd JingThom");
const __m128i _snowv_sigma = _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0);
const __m128i _snowv_zero = _mm_setzero_si128();

struct SnowV256
{
    __m256i hi, lo;     // LFSR
    __m128i R1, R2, R3; // FSM

    inline __m128i keystream(void) {
        // Extract the tags T1 and T2
        __m128i T1 = _mm256_extracti128_si256(hi, 1);
        __m128i T2 = _mm256_castsi256_si128(lo);
        // LFSR Update
        __m256i mulx = _mm256_xor_si256(_mm256_slli_epi16(lo, 1), _mm256_and_si256(_snowv_mul, _mm256_srai_epi16(lo, 15)));

        __m256i invx = _mm256_xor_si256(_mm256_srli_epi16(hi, 1), _mm256_sign_epi16(_snowv_inv, _mm256_slli_epi16(hi, 15)));
        __m256i hi_old = hi;
        hi = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_blend_epi32(
                    _mm256_alignr_epi8(hi, lo, 1 * 2),
                    _mm256_alignr_epi8(hi, lo, 3 * 2), 0xf0),
                _mm256_permute4x64_epi64(lo, 0x4e)),
            _mm256_xor_si256(invx, mulx));
        lo = hi_old;
        // Keystream word
        __m128i z = _mm_xor_si128(R2, _mm_add_epi32(R1, T1));
        // FSM Update
        __m128i R3new = _mm_aesenc_si128(R2, _snowv_zero);
        __m128i R2new = _mm_aesenc_si128(R1, _snowv_zero);
        R1 = _mm_shuffle_epi8(_mm_add_epi32(R2, _mm_xor_si128(R3, T2)), _snowv_sigma);
        R3 = R3new;
        R2 = R2new;
        return z;
    }

    template <int aead_mode = 0>
    inline void keyiv_setup(const unsigned char *key, const unsigned char *iv) {
        R1 = R2 = R3 = _mm_setzero_si128();
        hi = _mm256_lddqu_si256((const __m256i *)key);
        lo = _mm256_zextsi128_si256(_mm_lddqu_si128((__m128i *)iv));
        if (aead_mode)
            lo = _mm256_insertf128_si256(lo, _snowv_aead, 1);
        for (int i = 0; i < 15; ++i)
            hi = _mm256_xor_si256(hi, _mm256_zextsi128_si256(keystream()));
        R1 = _mm_xor_si128(R1, _mm_lddqu_si128((__m128i *)(key + 0)));
        hi = _mm256_xor_si256(hi, _mm256_zextsi128_si256(keystream()));
        R1 = _mm_xor_si128(R1, _mm_lddqu_si128((__m128i *)(key + 16)));
    }
};

// Main para probar el cifrado snow-v y mostrar por pantalla su velocidad de cifrado en Gbps


int main(void)
{
    SnowV256 snowv;
    uint64_t key[4] = {0x0001020304050607, 0x08090a0b0c0d0e0f, 0x1011121314151617, 0x18191a1b1c1d1e1f};
    uint64_t iv[2] = {0x2021222324252627, 0x28292a2b2c2d2e2f};
    snowv.keyiv_setup<1>((u8 *)key, (u8 *)iv);
    uint64_t message[2] = {0x3031323334353637, 0x38393a3b3c3d3e3f};
    uint64_t ciphertext[2];
    uint64_t tag[2];
    uint64_t start = __rdtsc();
    for (int i = 0; i < 10000000; i++)
    {
        ciphertext[0] = _mm_cvtsi128_si64(snowv.keystream()) ^ message[0];
        ciphertext[1] = _mm_cvtsi128_si64(_mm_srli_si128(snowv.keystream(), 8)) ^ message[1];
        tag[0] = _mm_cvtsi128_si64(snowv.keystream());
        tag[1] = _mm_cvtsi128_si64(_mm_srli_si128(snowv.keystream(), 8));
    }
    uint64_t end = __rdtsc();
    printf("Ciphertext: %016llx %016llx\n", ciphertext[0], ciphertext[1]);
    printf("Tag: %016llx %016llx\n", tag[0], tag[1]);
    printf("Ciclos: %d\n", end - start);
    printf("Gbps: %f\n", (double)10000000 * 2 * 128 / (end - start));
    return 0;
}
