/*
Name- Ayushi Shukla
ID-202051044
LAB Assignment -3*/

#include <stdio.h>
#include <stdint.h>
typedef unsigned char uc;
typedef uint8_t byte;


// AES-128 S-Box
unsigned int subbytes[16][16] = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                                 {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                                 {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                                 {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                                 {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                                 {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                                 {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                                 {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                                 {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                                 {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                                 {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                                 {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                                 {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                                 {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                                 {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                                 {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

//Function to look the value in S-Box of AES (Sub-Byte Values)
/*
Steps: Take last four bits then take first four bit and look for the correponding value in S-Box Defined*/
uc Sub_bytes(uc temp)
{
    int t1, t2;
    t1 = temp & 15;
    t2 = (temp >> 4);
    return (subbytes[t2][t1]);
}

// Inverse subbytes function of AES-128 Will be used in Decryption 
uc Inverse_Sub_bytes(uc temp)
{
    int i, j;
    uc x;
    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 16; j++)
        {
            if (subbytes[i][j] == temp)
            {
                x = i;
                x = (x << 4) | j;
                break;
            }
        }
    }

    return x;
}


/*the Galois Field GF(2^8) is commonly used in AES for
 its byte-level enccryptption operation. 
*/

const uc polynomial_function = 0b100011011;//corresponds to the polynomial x^8+x^4 + x^3 + 1. 
//it is used to perform multiplication in GF(2^8) in the galois_field_multiplication function.
//here 0x001b can be said that it is used for bit saving!
uc galois_field_multiplication(uc a, uc b)
{
    uc ans = 0;
    for (; b; b >>= 1)
    {
        if (b & 1)
            ans ^= a;
        //here we are using polynomial_function to check  overflow during the multiplication operation
        if (a & 0x80)
            a = (a << 1) ^ polynomial_function;
        else
            a <<= 1;
    }
    return ans;
}

/*
A/Q;
function Subbyte′
: {0, 1}
8 → {0, 1}
8 as per the following rule,
Subbyte′(x) = Sub(2 ∗ x + 1)
.*/
uc new_Subbytes(uc s)
{
    uc t;
    // feild multiplication by 2
    t = galois_field_multiplication(s, 2);
    // addition is XOR in feild 2
    t = t ^ 1;
    return Sub_bytes(t);//This is the new Sub-Bytes according to the requirement of question
}

/*
A/Q;
function Subbyte′
: {0, 1}
8 → {0, 1}
8 as per the following rule,
Subbyte′(x) = Sub(2 ∗ x + 1)
Using this to find the Inverse of New Sub-Byte function which will be used in Decryption
.*/
uc new_Inverse_Subbytes(uc senc)
{
    byte sdec = Inverse_Sub_bytes(senc);
    byte t;
    t = sdec ^ 1;
    t = galois_field_multiplication(t, 141);
    return t;
}

//Now using New_Subbyte function, we will have the function which we will use to look Subbyte in S-box
void subbyte(uc in[4][4], uc out[4][4])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[i][j] = new_Subbytes(in[i][j]);
        }
    }
}

//Now using Inver_ New_Subbyte function, we will have the function which we will use to look Subbyte in S-box for deccryptption!
void invsubbyte(uc in[4][4], uc out[4][4])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[i][j] = new_Inverse_Subbytes(in[i][j]);
        }
    }
}

/*
Now Performing Left and right shift operations!*/

// doing left shift for AES Encryption!
uc shift_left(uc temp[4][4], int num, int RowWise)
{
    for (int i = 0; i < num; i++)
    {
        uc t1 = temp[RowWise][0];
        temp[RowWise][0] = temp[RowWise][1];
        temp[RowWise][1] = temp[RowWise][2];
        temp[RowWise][2] = temp[RowWise][3];
        temp[RowWise][3] = t1;
    }
}

// doing right shift for AES Encryption!
uc shift_right(uc temp[4][4], int num, int RowWise)
{
    for (int i = 0; i < num; i++)
    {
        uc t1 = temp[RowWise][3];
        temp[RowWise][3] = temp[RowWise][2];
        temp[RowWise][2] = temp[RowWise][1];
        temp[RowWise][1] = temp[RowWise][0];
        temp[RowWise][0] = t1;
    }
}

/*
Performing Shift Row !*/
uc shiftrow(uc x[4][4])
{
    // shifting each row based on the row number
    shift_left(x, 1, 1);
    shift_left(x, 2, 2);
    shift_left(x, 3, 3);
    shift_left(x, 4, 4);
}

// Performing Inverse Shift Row for deccryptption
uc inv_shiftrow(uc x[4][4])
{
    // shifting each row based on the row number
    shift_right(x, 1, 1);
    shift_right(x, 2, 2);
    shift_right(x, 3, 3);
    shift_right(x, 4, 4);
}


/*
mix column we use state Matrix and multiply it with Mix column Matrix
Mix column Matrix is given in the question sheet*/
void MixCol(uc input[4][4], uc output[4][4])
{

    for (int x = 0; x < 4; ++x)
    {
        (output[0])[x] = galois_field_multiplication(1, (input[0])[x]) ^ galois_field_multiplication(4, (input[1])[x]) ^ galois_field_multiplication(4, (input[2])[x]) ^ galois_field_multiplication(5, (input[3])[x]);
        (output[1])[x] = galois_field_multiplication(5, (input[0])[x]) ^ galois_field_multiplication(1, (input[1])[x]) ^ galois_field_multiplication(4, (input[2])[x]) ^ galois_field_multiplication(4, (input[3])[x]);
        (output[2])[x] = galois_field_multiplication(4, (input[0])[x]) ^ galois_field_multiplication(5, (input[1])[x]) ^ galois_field_multiplication(1, (input[2])[x]) ^ galois_field_multiplication(4, (input[3])[x]);
        (output[3])[x] = galois_field_multiplication(4, (input[0])[x]) ^ galois_field_multiplication(4, (input[1])[x]) ^ galois_field_multiplication(5, (input[2])[x]) ^ galois_field_multiplication(1, (input[3])[x]);
    }
}

/*
Performing Inverse mix column we use state Matrix and multiply it with Mix column Matrix
Mix column Matrix is given in the question sheet
This is used in deccryptption process*/
void Inverse_MixCol(uc input[4][4], uc output[4][4])
{
    int x = 0;

    for (x = 0; x < 4; ++x)
    {
        (output[0])[x] = galois_field_multiplication(165, (input[0])[x]) ^ galois_field_multiplication(7, (input[1])[x]) ^ galois_field_multiplication(26, (input[2])[x]) ^ galois_field_multiplication(115, (input[3])[x]);
        (output[1])[x] = galois_field_multiplication(115, (input[0])[x]) ^ galois_field_multiplication(165, (input[1])[x]) ^ galois_field_multiplication(7, (input[2])[x]) ^ galois_field_multiplication(26, (input[3])[x]);
        (output[2])[x] = galois_field_multiplication(26, (input[0])[x]) ^ galois_field_multiplication(115, (input[1])[x]) ^ galois_field_multiplication(165, (input[2])[x]) ^ galois_field_multiplication(7, (input[3])[x]);
        (output[3])[x] = galois_field_multiplication(7, (input[0])[x]) ^ galois_field_multiplication(26, (input[1])[x]) ^ galois_field_multiplication(115, (input[2])[x]) ^ galois_field_multiplication(165, (input[3])[x]);
    }
}




uint32_t Rotation_of_word(uint32_t word)
{
    uc temp[4];
    temp[0] = (word >> 8) & 0xfF;
    temp[1] = (word >> 16) & 0xfF;
    temp[2] = (word >> 24) & 0xfF;
    temp[3] = word & 0xfF;
    uint32_t rotword = temp[3] << 24 | temp[2] << 16 | temp[1] << 8 | temp[0];
    return rotword;
}

// finding sub bytes of each word
uint32_t Subbyte_Of_Word(uint32_t word)
{
    uc temp[4];
    temp[0] = word & 0xfF;
    temp[1] = (word >> 8) & 0xfF;
    temp[2] = (word >> 16) & 0xfF;
    temp[3] = (word >> 24) & 0xfF;
    for (int i = 0; i < 4; i++)
    {
        temp[i] = Sub_bytes(temp[i]);
    }
    // concatanating back into a 32 bit
    uint32_t subword = temp[3] << 24 | temp[2] << 16 | temp[1] << 8 | temp[0];
    return subword;
}

// key expansion function 
void key_Expansion_Function(uc key[16], uint32_t w[44])
{
    uint32_t Constant[16];
    Constant[1] = 0x01000000;
    Constant[2] = 0x02000000;
    Constant[3] = 0x04000000;
    Constant[4] = 0x08000000;
    Constant[5] = 0x10000000;
    Constant[6] = 0x20000000;
    Constant[7] = 0x40000000;
    Constant[8] = 0x80000000;
    Constant[9] = 0x1B000000;
    Constant[10] = 0x36000000;
    for (int i = 0; i < 4; i++)
        w[i] = (key[4 * i] << 24 | key[4 * i + 1] << 16 | key[4 * i + 2] << 8 | key[4 * i + 3]);
    uint32_t temp = 0;
    // remaing 40 words other than the first 4Constant
    for (int i = 4; i < 44; i++)
    {
        temp = w[i - 1];
        if (i % 4 == 0)
            temp = Subbyte_Of_Word(Rotation_of_word(temp)) ^ Constant[i / 4];
        w[i] = w[i - 4] ^ temp;
    }
}

// XOR function to XOR two 128 bit texts.
void XOR (uc a[4][4], uc b[4][4], uc c[4][4]) {
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            c[i][j] = a[i][j] ^ b[i][j];
        }
    }
}

    // RoundKey Function for 10 rounds 
    void Round_Key_Function(uint32_t word[], uc key[4][4], int round)
{
    // Now we will join 4 number each of 32 bits hence craeting a 128 bit number 
    for (int i = 0; i < 4; i++)
    {
        key[i][3] = word[4 * round + i] & 0xFF;
        key[i][2] = (word[4 * round + i] >> 8) & 0xFF;
        key[i][1] = (word[4 * round + i] >> 16) & 0xFF;
        key[i][0] = (word[4 * round + i] >> 24) & 0xFF;
    }
}

// Performing AES Encryption
void AES_Encryption(byte input[4][4], uc Enc[4][4], uc key[16])
{
    /*
    Performing same procedure for 9 rounds:
    which include subbyte 
    shiftrow
    mixcoloumn
    Round 10 will be different*/
    // generating words by key expansion function
    uint32_t words[44];
    key_Expansion_Function(key, words);
    // generating round key and doing XOR
    uc roundkey0[4][4];
    Round_Key_Function(words, roundkey0, 0);
    uc round1[4][4];
    XOR(roundkey0, input, round1);
    // round 1 begins
    uc SubByte_1[4][4];
    subbyte(round1, SubByte_1);
    shiftrow(SubByte_1);
    uc MixCol_r1[4][4];
    MixCol(SubByte_1, MixCol_r1);
    uc roundkey1[4][4];
    Round_Key_Function(words, roundkey1, 1);
    uc round2[4][4];
    XOR(roundkey1, MixCol_r1, round2);

    // round 2  Begins
   
    uc SubByte_2[4][4];
    subbyte(round2, SubByte_2);
    shiftrow(SubByte_2);
    uc MixCol_r2[4][4];
    MixCol(SubByte_2, MixCol_r2);
    uc roundkey2[4][4];
    Round_Key_Function(words, roundkey2, 2);
    uc round3[4][4];
    XOR(roundkey2, MixCol_r2, round3);
  

   // round 3  Begins
    uc SubByte_3[4][4];
    subbyte(round3, SubByte_3);
    shiftrow(SubByte_3);
    uc MixCol_r3[4][4];
    MixCol(SubByte_3, MixCol_r3);
    // generating round key and doing XOR
    uc roundkey3[4][4];
    Round_Key_Function(words, roundkey3, 3);
    uc round4[4][4];
    XOR(roundkey3, MixCol_r3, round4);

    // round 4 begins
    uc SubByte_4[4][4];
    subbyte(round4, SubByte_4);
    shiftrow(SubByte_4);
    uc MixCol_r4[4][4];
    MixCol(SubByte_4, MixCol_r4);
    uc roundkey4[4][4];
    Round_Key_Function(words, roundkey4, 4);
    uc round5[4][4];
    XOR(MixCol_r4, roundkey4, round5);

    // round 5 begins
    uc SubByte_5[4][4];
    subbyte(round5, SubByte_5);
    shiftrow(SubByte_5);
    uc MixCol_r5[4][4];
    MixCol(SubByte_5, MixCol_r5);
    uc roundkey5[4][4];
    Round_Key_Function(words, roundkey5, 5);
    uc round6[4][4];
    XOR(MixCol_r5, roundkey5, round6);

    // round 6 begins
    uc SubByte_6[4][4];
    subbyte(round6, SubByte_6);
    shiftrow(SubByte_6);
    uc MixCol_r6[4][4];
    MixCol(SubByte_6, MixCol_r6);
    uc roundkey6[4][4];
    Round_Key_Function(words, roundkey6, 6);
    uc round7[4][4];
    XOR(MixCol_r6, roundkey6, round7);
    // round 7 begins
    uc SubByte_7[4][4];
    subbyte(round7, SubByte_7);
    shiftrow(SubByte_7);
    uc MixCol_r7[4][4];
    MixCol(SubByte_7, MixCol_r7);
   
    uc roundkey7[4][4];
    Round_Key_Function(words, roundkey7, 7);
    uc round8[4][4];
    XOR(MixCol_r7, roundkey7, round8);

    // round 8 begins
    uc SubByte_8[4][4];
    subbyte(round8, SubByte_8);
    shiftrow(SubByte_8);
    uc MixCol_r8[4][4];
    MixCol(SubByte_8, MixCol_r8);
    uc roundkey8[4][4];
    Round_Key_Function(words, roundkey8, 8);
    uc round9[4][4];
    XOR(MixCol_r8, roundkey8, round9);
    // round 9 begins
    uc SubByte_9[4][4];
    subbyte(round9, SubByte_9);
    shiftrow(SubByte_9);
    uc MixCol_r9[4][4];
    MixCol(SubByte_9, MixCol_r9);
    uc roundkey9[4][4];
    Round_Key_Function(words, roundkey9, 9);
    uc round10[4][4];
    XOR(MixCol_r9, roundkey9, round10);
   /*
   Round-10 
   In this We dont perform MixCol*/
    uc SubByte_10[4][4];
    subbyte(round10, SubByte_10);
    shiftrow(SubByte_10);
    uc roundkey10[4][4];
    Round_Key_Function(words, roundkey10, 10);
    XOR(SubByte_10, roundkey10, Enc);
}

//Performing Decryption 

void deccryptpt(uc enccrypt[4][4], uc deccrypt[4][4], uc key[16])
{
    // generating words by key expansion function
    uint32_t words[44];
    key_Expansion_Function(key, words);
    uc roundkey10[4][4];
    Round_Key_Function(words, roundkey10, 10);
    uc round11[4][4];
    XOR(enccrypt, roundkey10, round11);
    // round 10 
    inv_shiftrow(round11);
    uc iSubByte_10[4][4];
    invsubbyte(round11, iSubByte_10);
  
    uc roundkey9[4][4];
    Round_Key_Function(words, roundkey9, 9);
    uc round10[4][4];
    XOR(iSubByte_10, roundkey9, round10);
    // round 9
    uc iMixCol_r9[4][4];
    Inverse_MixCol(round10, iMixCol_r9);
    inv_shiftrow(iMixCol_r9);
    uc iSubByte_9[4][4];
    invsubbyte(iMixCol_r9, iSubByte_9);

    uc roundkey8[4][4];
    Round_Key_Function(words, roundkey8, 8);
    uc round9[4][4];
    XOR(iSubByte_9, roundkey8, round9);
    // round 8 
    uc iMixCol_r8[4][4];
    Inverse_MixCol(round9, iMixCol_r8);
    inv_shiftrow(iMixCol_r8);
    uc iSubByte_8[4][4];
    invsubbyte(iMixCol_r8, iSubByte_8);
 
    uc roundkey7[4][4];
    Round_Key_Function(words, roundkey7, 7);
    uc round8[4][4];
    XOR(iSubByte_8, roundkey7, round8);
    // round 7 
    uc iMixCol_r7[4][4];
    Inverse_MixCol(round8, iMixCol_r7);
    inv_shiftrow(iMixCol_r7);
    uc iSubByte_7[4][4];
    invsubbyte(iMixCol_r7, iSubByte_7);
  
    uc roundkey6[4][4];
    Round_Key_Function(words, roundkey6, 6);
    uc round7[4][4];
    XOR(iSubByte_7, roundkey6, round7);
    // round 6 
    uc iMixCol_r6[4][4];
    Inverse_MixCol(round7, iMixCol_r6);
    inv_shiftrow(iMixCol_r6);
    uc iSubByte_6[4][4];
    invsubbyte(iMixCol_r6, iSubByte_6);
    
    uc roundkey5[4][4];
    Round_Key_Function(words, roundkey5, 5);
    uc round6[4][4];
    XOR(iSubByte_6, roundkey5, round6);
    // round 5 
    uc iMixCol_r5[4][4];
    Inverse_MixCol(round6, iMixCol_r5);
    inv_shiftrow(iMixCol_r5);
    uc iSubByte_5[4][4];
    invsubbyte(iMixCol_r5, iSubByte_5);
 
    uc roundkey4[4][4];
    Round_Key_Function(words, roundkey4, 4);
    uc round5[4][4];
    XOR(iSubByte_5, roundkey4, round5);
    // round 4 
    uc iMixCol_r4[4][4];
    Inverse_MixCol(round5, iMixCol_r4);
    inv_shiftrow(iMixCol_r4);
    uc iSubByte_4[4][4];
    invsubbyte(iMixCol_r4, iSubByte_4);
  
    uc roundkey3[4][4];
    Round_Key_Function(words, roundkey3, 3);
    uc round4[4][4];
    XOR(iSubByte_4, roundkey3, round4);
    // round 3
    uc iMixCol_r3[4][4];
    Inverse_MixCol(round4, iMixCol_r3);
    inv_shiftrow(iMixCol_r3);
    uc iSubByte_3[4][4];
    invsubbyte(iMixCol_r3, iSubByte_3);

    uc roundkey2[4][4];
    Round_Key_Function(words, roundkey2, 2);
    uc round3[4][4];
    XOR(iSubByte_3, roundkey2, round3);
    // round 2
    uc iMixCol_r2[4][4];
    Inverse_MixCol(round3, iMixCol_r2);
    inv_shiftrow(iMixCol_r2);
    uc iSubByte_2[4][4];
    invsubbyte(iMixCol_r2, iSubByte_2);
   
    uc roundkey1[4][4];
    Round_Key_Function(words, roundkey1, 1);
    uc round2[4][4];
    XOR(iSubByte_2, roundkey1, round2);
    // round 1 
    uc iMixCol_r1[4][4];
    Inverse_MixCol(round2, iMixCol_r1);
    inv_shiftrow(iMixCol_r1);
    uc iSubByte_1[4][4];
    invsubbyte(iMixCol_r1, iSubByte_1);

    uc roundkey0[4][4];
    Round_Key_Function(words, roundkey0, 0);
    uc round0[4][4];
    XOR(iSubByte_1, roundkey0, deccrypt);
}

int main()
{
    // taking input of the  text
    byte input[4][4];
    printf("Enter plaintext of 128 bits. Input will be 16 hexadecimal e.g., a1 12 ...ca 45 ec :\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            scanf("%hhx", &input[i][j]);
        }
    }

    // taking input of secret key
    printf("Enter the key of 128 bits: Input will be 16 hexadecimal e.g., b1 32 ...ef 3a cb :\n");
    uc key[16];
    for (int i = 0; i < 16; i++)
    {
        scanf("%hhx", &key[i]);
    }
    uc encryption[4][4];
    AES_Encryption(input, encryption, key);

    // enccryptted text
    printf("\n\nThe Encryption of the following Input will be  :\n\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", encryption[i][j]);
        }
        printf("\n");
    }
    uc decryption[4][4];
    // deccryptpting the cipher text
    deccryptpt(encryption, decryption, key);
    printf("\n\n The Decryption of the following  will be :\n\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", decryption[i][j]);
        }
        printf("\n");
    }
    // validating
    printf("\n\nHence we got back our input Plaintext : \n\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", input[i][j]);
        }
        printf("\n");
    }
}
