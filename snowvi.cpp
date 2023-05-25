#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <x86intrin.h>

typedef unsigned char u8;
#define SIZE 16384         // 16 KB
#define KEY_SIZE 32        // 256 bits
#define IV_SIZE 16         // 128 bits
#define GIGABIT 1000000000 // 1 Gbps

#define XOR(a, b) _mm_xor_si128(a, b)
#define AND(a, b) _mm_and_si128(a, b)
#define ADD(a, b) _mm_add_epi32(a, b)
#define SET(v) _mm_set1_epi16((short)v)
#define SLL(a) _mm_slli_epi16(a, 1)
#define SRA(a) _mm_srai_epi16(a, 15)
#define TAP7(Hi, Lo) _mm_alignr_epi8(Hi, Lo, 7 * 2)
#define SIGMA(a)                                                               \
    _mm_shuffle_epi8(                                                          \
        a, _mm_set_epi64x(0x0f0b07030e0a0602ULL, 0x0d0905010c080400ULL));
#define AESR(a, k) _mm_aesenc_si128(a, k)
#define ZERO() _mm_setzero_si128()
#define LOAD(src) _mm_loadu_si128((const __m128i *)(src))
#define STORE(dst, x) _mm_storeu_si128((__m128i *)(dst), x)

#define SnowVi_XMM_ROUND(mode, offset)                                         \
    T1 = B1, T2 = A1;                                                          \
    A1 = XOR(XOR(XOR(TAP7(A1, A0), B0), AND(SRA(A0), SET(0x4a6d))), SLL(A0));  \
    B1 = XOR(XOR(B1, AND(SRA(B0), SET(0xcc87))), XOR(A0, SLL(B0)));            \
    A0 = T2;                                                                   \
    B0 = T1;                                                                   \
    if (mode == 0)                                                             \
        A1 = XOR(A1, XOR(ADD(T1, R1), R2));                                    \
    else                                                                       \
        STORE(out + offset, XOR(ADD(T1, R1), XOR(LOAD(in + offset), R2)));     \
    T2 = ADD(R2, R3);                                                          \
    R3 = AESR(R2, A1);                                                         \
    R2 = AESR(R1, ZERO());                                                     \
    R1 = SIGMA(T2);
// Note : here the length must be 16 - bytes aligned
inline void SnowVi_encdec(int length, u8 *out, u8 *in, u8 *key, u8 *iv) {
    __m128i A0, A1, B0, B1, R1, R2, R3, T1, T2;
    // key /IV loading
    B0 = R1 = R2 = ZERO();
    A0 = LOAD(iv);
    R3 = A1 = LOAD(key);
    B1 = LOAD(key + 16);
    // Initialisation
    for (int i = -14; i < 2; ++i) {
        SnowVi_XMM_ROUND(0, 0);
        if (i < 0)
            continue;
        R1 = XOR(R1, LOAD(key + i * 16));
    }
    // Bulk encryption
    for (int i = 0; i <= length - 16; i += 16) {
        SnowVi_XMM_ROUND(1, i);
    }
}
// ... some test program

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
    unsigned char key[KEY_SIZE] = {0};
    unsigned char iv[IV_SIZE] = {0};
    unsigned char message[SIZE];
    unsigned char ciphertext[SIZE];

    // Generar mensaje de prueba
    for (int i = 0; i < SIZE; ++i) {
        message[i] = rand() & 0xFF;
    }

    // Inicializar el temporizador
    // clock_t start = clock();

    // Realizar múltiples pruebas y medir el tiempo de cifrado
    const int numTests = 1000000;
    long long totalTime = 0;
    struct timespec start, end;
    for (int i = 0; i < numTests; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        SnowVi_encdec(SIZE, ciphertext, message, key, iv);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long elapsed = timespec_diff(start, end);

        // Calcula la velocidad de cifrado en Gbps
        double speed = (double)(SIZE * 8) / (elapsed / 1000000.0) / 1e9;

        // Acumula el tiempo total
        totalTime += elapsed;
    }

    // Calcular la velocidad de cifrado en Gbps
    // clock_t end = clock();
    // Calcula el tiempo promedio por prueba
    double averageTime = totalTime / (double)numTests;

    // Calcula la velocidad de cifrado promedio en Gbps
    double averageSpeed =
        (double)(SIZE * 8) / (averageTime / 1000000000.0) / 1e9;

    // Imprime la velocidad de cifrado promedio
    printf("Velocidad de cifrado promedio = %.2f Gbps\n", averageSpeed);

    return 0;
}