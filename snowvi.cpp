#include <stdio.h>
#include <x86intrin.h>

#define XOR(a, b) _mm_xor_si128(a, b)
#define AND(a, b) _mm_and_si128(a, b)
#define ADD(a, b) _mm_add_epi32(a, b)
#define SET(v) _mm_set1_epi16((short)v)
#define SLL(a) _mm_slli_epi16(a, 1)
#define SRA(a) _mm_srai_epi16(a, 15)
#define TAP7(Hi, Lo) _mm_alignr_epi8(Hi, Lo, 7 * 2)
#define SIGMA(a)                       \
    _mm_shuffle_epi8(a, _mm_set_epi64x( \
                            0x0f0b07030e0a0602ULL, 0x0d0905010c080400ULL));
#define AESR(a, k) _mm_aesenc_si128(a, k)
#define ZERO() _mm_setzero_si128()
#define LOAD(src) \
    _mm_loadu_si128((const __m128i *)(src))
#define STORE(dst, x) \
    _mm_storeu_si128((__m128i *)(dst), x)
struct SnowVi
{
    __m128i A0, A1, B0, B1; // LFSR
    __m128i R1, R2, R3;     // FSM
    inline __m128i keystream(void)
    { // Taps
        __m128i T1 = B1, T2 = A1;
        // LFSR -A/B
        A1 = XOR(XOR(XOR(TAP7(A1, A0), B0), SLL(A0)), AND(SET(0x4a6d), SRA(A0)));
        B1 = XOR(XOR(SLL(B0), A0), XOR(B1, AND(SET(0xcc87), SRA(B0))));
        A0 = T2;
        B0 = T1;
        // Keystream word
        __m128i z = XOR(R2, ADD(R1, T1));
        // FSM Update
        T2 = ADD(XOR(T2, R3), R2);
        R3 = AESR(R2, ZERO());
        R2 = AESR(R1, ZERO());
        R1 = SIGMA(T2);
        return z;
    }
    template <int aead_mode = 0>
    inline void keyiv_setup(
        const unsigned char *key, const unsigned char *iv)
    {
        B0 = R1 = R2 = R3 = ZERO();
        A0 = LOAD(iv);
        A1 = LOAD(key);
        B1 = LOAD(key + 16);
        if (aead_mode)
            B0 = LOAD(" AlexEkd JingThom ");
        for (int i = 0; i < 15; ++i)
            A1 = XOR(A1, keystream());
        R1 = XOR(R1, LOAD(key));
        A1 = XOR(A1, keystream());
        R1 = XOR(R1, LOAD(key + 16));
    }
};
// ... some test program

int main()
{
    SnowVi s;
    unsigned char key[32] = {0}, iv[16] = {0};
    s.keyiv_setup(key, iv);
    for (int t = 0; t < 4; t++)
    {
        unsigned char ks[16];
        STORE(ks, s.keystream());
        for (int i = 0; i < 16; i++)
            printf("%02x ", (unsigned int)ks[i]);
        printf("\n");
    }
    return 0;
}