----- HEADERS ----- */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h> 
#include "aes.h"


typedef uint8_t byte;
typedef uint32_t word;
/* ----- VARIABLES ----- */
int P = 173; // prime number
int a = 23;
int b = 11;
// TODO: change to random
int alpha[2]; // point on the curve
// TODO: change to input
int na , nb ; // private keys
int *SK;            // shared public key; x1 = SK[0], y1 = SK[1]
word state[8];
byte data[63];
word l;
uint64_t bl;
word hash[32];
// word Ka[32], Kb[32];
void selectPoint();
int *elMult(int, int[]);
int *elAdd(int[], int[]);
int addInv(int);
int multInv(int);
void init();
void transform();
void add(byte[], uint32_t);
void finish();
/* ----- function declarations ----- */
word _rotr(word x, int n);
word _rotl(word x, int n);
word _sigma0(word x);
word _sigma1(word x);
word _epilogue0(word x);
word _epilogue1(word x);
word _ch(word x, word y, word z);
word _maj(word x, word y, word z);

#define ax 4
#define bx 8
#define cx 14

int MODULAR = 173;    

const unsigned int K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif


typedef uint8_t state_t[4][4];

void padding(unsigned char ma[2], int len, unsigned char block[64]){ 
    // To ensure that the message1 has length multiple of 512 bits:
    // • first, a bit 1 is appended,
    // • next, k bits 0 are appended, with k being the smallest positive integer such that l + 1 + k ≡ 448
    // mod 512, where l is the length in bits of the initial message,
    // • finally, the length l < 2
    // 64 of the initial message is represented with exactly 64 bits, and these bits
    // are added at the end of the message.
    // The message shall always be padded, even if the initial length is already a multiple of 512.

    int j = 0;
    for (int i = 0; i < len; i++){
        if (ma[i] == ' ')
            continue;

        unsigned char arr[2] = {ma[i], ma[i + 1]};
        i++;

        unsigned char ans = strtol(arr, NULL, 16);
        block[j] = ans;
        j++;
    }
    long long int ltemp = j * 8;

    block[j] = 0x80;
    j++;
    for (; j < 64; j++){
        block[j] = 0;
    }
    for (int i = 0; i < 8; i++){
        j = 64 - i;
        unsigned char val = ltemp >> (8 * i);
        block[j - 1] = val;
    }
}

unsigned int ROTL(unsigned int A, int n){  //circular right shift of n bits of the binary word A.
    return (A>>n)|(A<<(32-n)); // (A >> 24) | (A << 8);
}

unsigned int CH(unsigned int X, unsigned int Y, unsigned int Z){
    return (((X) & (Y)) ^ (~(X) & (Z)));
}

unsigned int MAJ(unsigned X,unsigned Y,unsigned Z){
    return (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)));
}

unsigned int eps0(unsigned int word){
    return (ROTL(word, 2) ^ ROTL(word, 13) ^ ROTL(word, 22));
}

unsigned int eps1(unsigned int word){
    return (ROTL(word, 6) ^ ROTL(word, 11) ^ ROTL(word, 25));
}

unsigned int sigma0(unsigned int word){
    return (ROTL(word, 7) ^ ROTL(word, 18) ^ (word>>3));
}

unsigned int sigma1(unsigned int word){
    return (ROTL(word, 17) ^ ROTL(word, 19) ^ (word>>10));
}

void blockDecomposition(unsigned char block[], unsigned int word[])
{
    // For each block M ∈ {0, 1}^512:
    // 64 words of 32 bits each are constructed as follows:
    // • the first 16 are obtained by splitting M in 32-bit blocks M = W1kW2k · · · kW15kW16
    // • the remaining 48 are obtained with the formula:
    // Wi = σ1(Wi−2) + Wi−7 + σ0(Wi−15) + Wi−16, 17 ≤ i ≤ 64.

    int i, j;

    for (i = 0, j = 0; i < 16; i++, j += 4){
        word[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | (block[j + 3]);
    }

    for (; i < 64; i++){
        word[i] = sigma1(word[i - 2]) + word[i - 7] + sigma0(word[i - 15]) + word[i - 16];
    }
}

void hashing(unsigned int word[], unsigned int output[]){
    unsigned int hash[8];
    const unsigned int H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int temp1,temp2;

    for(int i=0;i<8;i++){
        hash[i]=H[i];
    }

    a=H[0];
    b=H[1];
    c=H[2];
    d=H[3];
    e=H[4];
    f=H[5];
    g=H[6];
    h=H[7];

    for (int i = 0; i < 64; i++){
        temp1=h+eps1(e)+CH(e,f,g)+K[i]+word[i];
        temp2=eps0(a)+MAJ(a,b,c);
        h=g;
        g=f;
        f=e;
        e=d+temp1;
        d=c;
        c=b;
        b=a;
        a=temp1+temp2;
    }

    hash[0]=hash[0]+a;
    hash[1]=hash[1]+b;
    hash[2]=hash[2]+c;
    hash[3]=hash[3]+d;
    hash[4]=hash[4]+e;
    hash[5]=hash[5]+f;
    hash[6]=hash[6]+g;
    hash[7]=hash[7]+h;

    for(int i=0;i<8;i++){
        output[i]=hash[i];
    }
}

// void SHA256(unsigned char ssk[2], unsigned int K[8]){
//     // SHA-256 (secure hash algorithm) is a cryptographic hash function with digest length of 256
//     // A message is processed by blocks of 512 = 16 × 32 bits, each block requiring 64 rounds.
//     unsigned char block[64]; //512 length block
//     unsigned int word[64];
//     padding(ssk, strlen(ssk), block); //converting the message i.e. x1||y1 to 512 bit blocks
//     blockDecomposition(block,word); //converting into 64 words
//     hashing(word,K);//hashing to get 256 bit output
// }
void MAC(unsigned int K[8], unsigned char M[33], unsigned int mac[8] ){
// MACA = SHA-256(KA ⊕ 1||SHA-256((KA ⊕ 2)||MA))
// MACA = SHA256(x||SHA256(y||ma))
}


static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

static const uint8_t RMix[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getSBox(num) (sbox[(num)])

// This function produces ax(cx+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < bx; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = bx; i < ax * (cx + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % bx == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBox(tempa[0]);
        tempa[1] = getSBox(tempa[1]);
        tempa[2] = getSBox(tempa[2]);
        tempa[3] = getSBox(tempa[3]);
      }

      tempa[0] = tempa[0] ^ RMix[i/bx];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % bx == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBox(tempa[0]);
        tempa[1] = getSBox(tempa[1]);
        tempa[2] = getSBox(tempa[2]);
        tempa[3] = getSBox(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - bx) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * ax * 4) + (i * ax) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBox((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

void selectPoint()
{
    // EL: y^2 = (x^3 + ax + b) mod p => y^2 = (x^3 + 23x + 11) mod 173
    int points[2][173] = {};
    int no_of_points = 0;

    // 1.1 find all points on the curve
    for (int x = 0; x < P; x++)
        for (int y = 0; y < P; y++)
        {
            int g = (x * x * x + 23 * x + 11) % P;
            if ((y * y - g) % P == 0)
            {
                // printf("(%d, %d)\n", x, y);
                points[0][no_of_points] = x;
                points[1][no_of_points] = y;

                no_of_points++;
            }
        }

    //1.2 select random point from the list
    //  srand(time(0));
    //  int alphaIndex = rand() % no_of_points;
    //  alpha[0] = points[0][alphaIndex];
    //  alpha[1] = points[1][alphaIndex];

    //  printf("alpha: (%d, %d)\n", alpha[0], alpha[1]);
}

int *elMult(int n, int p[])
{
    int *q = (int *)malloc(2 * sizeof(int));
    q = p;
    for (int i = 1; i < n; i++)
        q = elAdd(p, q);

    return q;
}
// function for adding two points on the curve
int *elAdd(int p[], int q[])
{
    int m;
    int theta[2] = {0, 1};
    int *sk = (int *)malloc(2 * sizeof(int));

    // case 1
    if ((p[0] != q[0]) && (p[1] != q[1]))
    {
        m = (q[1] + addInv(p[1])) * multInv(q[0] + addInv(p[0])) % P;

        sk[0] = (m * m + addInv(p[0]) + addInv(q[0])) % P;
        sk[1] = (p[1] + m * (sk[0] + addInv(p[0]))) % P;
        sk[1] = addInv(sk[1]);
    }
    // case 3
    else if ((p[0] == q[0]) && (p[1] == q[1]))
    {
        m = (3 * p[0] * p[0] + a) * multInv(2 * p[1]) % P;

        sk[0] = (m * m + addInv(2 * p[0])) % P;
        sk[1] = (p[1] + m * (sk[0] + addInv(p[0]))) % P;
        sk[1] = addInv(sk[1]);
    }
    // case 2
    else if ((p[0] == q[0]) && (p[1] == -1 * q[1]))
    {
        sk[0] = theta[0];
        sk[1] = theta[1];
    }
    // printf("\nSK: (%d, %d)\n", sk[0], sk[1]);
    return sk;
}

// function for finding additive inverse modulo P
int addInv(int x)
{
    return (P - x);
}

// function for finding multiplicative inverse modulo P using extended euclidean algorithm
int multInv(int a)
{
    for (int i = 1; i < P; i++)
        if (((a % P) * (i % P)) % P == 1)
            return i;
}
// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be cx rounds.
  // The first cx-1 rounds are identical.
  // These cx rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == cx) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(cx, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(cx, state, RoundKey);

  // There will be cx rounds.
  // The first cx-1 rounds are identical.
  // These cx rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (cx - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif // #if defined(CTR) && (CTR == 1)


int AES_BOB(uint8_t Key[], uint8_t message[], uint8_t decrypted_text[]) {
    struct AES_ctx ctx;
    uint8_t in[16], in1[16]; 
    for(int i = 0; i < 16; i++) 
        in[i] = message[i], in1[i] = message[i + 16];
    AES_init_ctx(&ctx, Key);
    AES_ECB_decrypt(&ctx, in);
    AES_init_ctx(&ctx, Key);
    AES_ECB_decrypt(&ctx, in1);

    for(int i = 0; i < 16; i++) 
        decrypted_text[i] = in[i], decrypted_text[i + 16] = in1[i];
    return 0;
}

int AES_ALICE(uint8_t Key[], uint8_t message[], uint8_t ciphertext[]) {
    uint8_t in[16], in1[16]; 
    for(int i = 0; i < 16; i++) 
        in[i] = message[i], in1[i] = message[i + 16];
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, Key);
    AES_ECB_encrypt(&ctx, in);
    AES_init_ctx(&ctx, Key);
    AES_ECB_encrypt(&ctx, in1);

    for(int i = 0; i < 16; i++) 
        ciphertext[i] = in[i], ciphertext[i + 16] = in1[i];

}

#define uchar unsigned char
#define uint unsigned int

#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
	uchar data[64];
	uint datalen;
	uint bitlen[2];
	uint state[8];
} SHA256_CTX;

uint k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX *ctx, uchar data[])
{
	uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX *ctx, uchar data[], uint len)
{
	for (uint i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			SHA256Transform(ctx, ctx->data);
			DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
			ctx->datalen = 0;
		}
	}
}

void SHA256Final(SHA256_CTX *ctx, uchar hash[])
{
	uint i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		SHA256Transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	SHA256Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

char* SHA256(unsigned char* data, uint8_t Result[]) {
	int strLen = strlen((char*)data);
	SHA256_CTX ctx;
	unsigned char hash[32];
	char* hashStr = (char*)malloc(65);
	strcpy(hashStr, "");

	SHA256Init(&ctx);
	SHA256Update(&ctx, (uchar*)data, strLen);
	SHA256Final(&ctx, hash);

	char s[3];
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);
        Result[i] = hash[i];
		strcat(hashStr, s);
	}

	return hashStr;
}

int SecondSHA(uint8_t Key[], uint8_t Message[], uint8_t Result[]) {

    unsigned char K1[32], M[32], M1[32];
    for(int i = 0; i < 32; i++) 
        K1[i] = (Key[i] ^ 0x02) % 0xff;
    printf("\n");
    for(int i = 0; i < 32; i++)     
        M[i] = (Message[i] | K1[i]) % 0xff;    

    unsigned char K2[32];
    for(int i = 0; i < 32; i++) 
        K2[i] = (Key[i] ^ 0x01) % 0xff;

    SHA256(M, Result);
    // printf("\nMessage Secret \n\n");
    for(int i = 0; i < 32; i++) 
        M1[i] = (M[i] | K2[i]) % 0xff;
    SHA256(M1, Result);
    printf("\n");
    return 1;
}

int FirstSHA(uint8_t K[], uint8_t a, uint8_t b) {
    printf("%d %d\n", a, b);
    unsigned char Key[2] = {a, b};
    char* sha256 = SHA256(Key, K);
    return 1;
}

int compute(int a, int m, int n)
{
    int r;
    int y = 1;
 
    while (m > 0)
    {
        r = m % 2;
 
        // fast exponention
        if (r == 1) {
            y = (y*a) % n;
        }
        a = a*a % n;
        m = m / 2;
    }
 
    return y;
}
 
// C program to demonstrate the Diffie-Hellman algorithm
int Step2(int32_t x, int32_t y, int32_t a, int32_t b)
{
//    Deffie Hellman
    int gx = x, gy = y, Ax, Bx, Ay, By; 
    Ax = compute(gx, a, MODULAR), Ay = compute(gy, a, MODULAR);
    Bx = compute(gx, b, MODULAR), By = compute(gy, b, MODULAR);
    int keyAx = compute(Bx, a, MODULAR), keyAy = compute(By, a, MODULAR);
    int keyBx = compute(Ax, b, MODULAR), keyBy = compute(Ay, b, MODULAR); 
 
    printf("Alice's secret key is (%d, %d)\axob's secret key is (%d, %d)", keyAx, keyAy, keyBx, keyBy);
    
    uint8_t key_Alice[32], key_Bob[32];
    FirstSHA(key_Alice, (uint8_t) keyAx, (uint8_t)keyAy);
    FirstSHA(key_Bob, (uint8_t) keyBx, (uint8_t)keyBy);

    printf("\bxey_Alice -->\n");
    for(int i = 0; i < 32; i++)
        printf("%02x ", key_Alice[i]);
    printf("\bxey_Bob -->\n");
    for (int i = 0; i < 32; i++)
        printf("%02x ", key_Bob[i]);
    printf("\n");
    uint8_t CipherText[32] , MessageBob[32], MAC_alice[32], MAC_bob[32], MessageAlice[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xa6, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xa6, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    printf("Plain Text of  Alice(Ma):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MessageAlice[i]);
    printf("\n");

    AES_ALICE(key_Alice, MessageAlice, CipherText);

    printf("Encrypted Text We get fromAlice:\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", CipherText[i]);
    printf("\n");

    AES_BOB(key_Bob, CipherText, MessageBob);

    printf("Decrypted Text we get by Bob(Mb):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MessageBob[i]);
    printf("\n");

    SecondSHA(key_Alice, MessageAlice, MAC_alice);

    printf("MAC of Alice:\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MAC_alice[i]);
    printf("\n");


    SecondSHA(key_Bob, MessageBob, MAC_bob);
    printf("MAC of  Bob:\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MAC_bob[i]);
    printf("\n");
    return 0;
}


int Step1()
{
    int32_t x, y, a = 23, b = 11, MODULAR = 173;
    int flag = false;
    for (int32_t i = 0; i < 173; i++)
    {
        int32_t tempy = (i * i) % MODULAR;

        for (int32_t j = 0; j < 173; j++)
        {
            int32_t tempx = ((j * j * j) % MODULAR + (a * j) % MODULAR + b) % MODULAR;
            if (tempx == tempy)
            {
                x = j;
                y = i;
                flag++;
                break;
            }
        }
        if (flag == 2)
            break;
    }

    printf("x: %d y: %d", x, y);

    uint32_t alice_private, bob_private;
    printf("\nEnter the private key of Alice [1,150]: ");
    scanf("%d", &alice_private);
    printf("\nEnter the private key of Bob  [1,150]: ");
    scanf("%d", &bob_private);
    Step2(x, y, alice_private, bob_private);
}
// Deffie Hellman
int main() {
    Step1();
    return 0;
}
202051044_Lab4.c
Displaying 202051044_Lab4.c.
LAB Assignment IV
Dibyendu Roy
•
Apr 20, 2023 (Edited Apr 26, 2023)
30 points
Due Apr 27, 2023, 11:59 PM
Write name and roll no on the top of your code. File name roll no.c

Drive file
Unknown File
1 class comment

ANKUR KUMAR SHUKLAMay 4, 2023
Sir i had submitted lab assignment, but in way of deleting some file of drive to match with current limit , by mistake it got deleted. You can confirm it from l
