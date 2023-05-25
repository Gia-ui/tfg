#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define MESSAGE_SIZE 16384 // 16 KB
#define GIGABIT 1000000000 // 1 Gbps
#define NUM_MESSAGES 100000

#define vpset16(value) _mm256_set1_epi16(value)
typedef uint8_t u8;
typedef uint64_t u64;
const __m256i _snowv_mul =
    _mm256_blend_epi32(vpset16(0x990f), vpset16(0xc963), 0xf0);
const __m256i _snowv_inv =
    _mm256_blend_epi32(vpset16(-0xcc87), vpset16(-0xe4b1), 0xf0);
const __m128i _snowv_aead = _mm_lddqu_si128((__m128i *)"AlexEkd JingThom");
const __m128i _snowv_sigma =
    _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0);
const __m128i _snowv_zero = _mm_setzero_si128();

struct SnowV256 {
    __m256i hi, lo;     // LFSR
    __m128i R1, R2, R3; // FSM

    inline __m128i keystream(void) {
        // Extract the tags T1 and T2
        __m128i T1 = _mm256_extracti128_si256(hi, 1);
        __m128i T2 = _mm256_castsi256_si128(lo);
        // LFSR Update
        __m256i mulx = _mm256_xor_si256(
            _mm256_slli_epi16(lo, 1),
            _mm256_and_si256(_snowv_mul, _mm256_srai_epi16(lo, 15)));

        __m256i invx = _mm256_xor_si256(
            _mm256_srli_epi16(hi, 1),
            _mm256_sign_epi16(_snowv_inv, _mm256_slli_epi16(hi, 15)));
        __m256i hi_old = hi;
        hi = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_blend_epi32(_mm256_alignr_epi8(hi, lo, 1 * 2),
                                   _mm256_alignr_epi8(hi, lo, 3 * 2), 0xf0),
                _mm256_permute4x64_epi64(lo, 0x4e)),
            _mm256_xor_si256(invx, mulx));
        lo = hi_old;
        // Keystream word
        __m128i z = _mm_xor_si128(R2, _mm_add_epi32(R1, T1));
        // FSM Update
        __m128i R3new = _mm_aesenc_si128(R2, _snowv_zero);
        __m128i R2new = _mm_aesenc_si128(R1, _snowv_zero);
        R1 = _mm_shuffle_epi8(_mm_add_epi32(R2, _mm_xor_si128(R3, T2)),
                              _snowv_sigma);
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

long long timespec_diff(struct timespec start, struct timespec end) {
    struct timespec diff;
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        diff.tv_sec = end.tv_sec - start.tv_sec - 1;
        diff.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        diff.tv_sec = end.tv_sec - start.tv_sec;
        diff.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return diff.tv_sec * 1000000000LL + diff.tv_nsec;
}

int main() {
    struct SnowV256 cipher;
    unsigned char key[32] = {0}, iv[16] = {0};

    cipher.keyiv_setup(key, iv);

    // Generar mensaje de prueba
    unsigned char message[MESSAGE_SIZE];
    for (int i = 0; i < MESSAGE_SIZE; ++i) {
        message[i] = rand() & 0xFF;
    }

    // Realizar múltiples pruebas y medir el tiempo de cifrado
    const int numTests = 1000000;
    long long totalTime = 0;
    struct timespec start, end;
    for (int i = 0; i < numTests; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        // Cifrar el mensaje
        unsigned char ciphertext[MESSAGE_SIZE];
        for (int j = 0; j < MESSAGE_SIZE; j += 16) {
            __m128i keystream = cipher.keystream();
            __m128i plaintext = _mm_lddqu_si128((__m128i *)(message + j));
            __m128i encrypted = _mm_xor_si128(plaintext, keystream);
            _mm_storeu_si128((__m128i *)(ciphertext + j), encrypted);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long elapsed = timespec_diff(start, end);

        // Calcula la velocidad de cifrado en Gbps
        double speed = (double)(MESSAGE_SIZE * 8) / (elapsed / 1000000.0) / 1e9;

        // Acumula el tiempo total
        totalTime += elapsed;
    }

    double averageTime = totalTime / (double)numTests;

    // Calcula la velocidad de cifrado promedio en Gbps
    double averageSpeed =
        (double)(MESSAGE_SIZE * 8) / (averageTime / 1000000000.0) / 1e9;

    // Imprime la velocidad de cifrado promedio
    printf("Velocidad de cifrado promedio = %.2f Gbps\n", averageSpeed);

    return 0;
}
