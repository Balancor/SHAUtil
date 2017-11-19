//
// Created by guoguo on 2017/11/18.
//

#include <cstdio>
#include <iostream>
#include <cmath>
#include <cstring>
#include "SHAUtil.h"

#define INT_BITS 32
#define LEFTROTATE(n, d)  (((n << d) | (n >> (INT_BITS - d))) & 0xFFFFFFFF)
#define RIGHTROTATE(n, d) (((n >> d) | (n << (INT_BITS - d))) & 0xFFFFFFFF)

#define LITTLESIGMA0(value) \
    ((RIGHTROTATE(value, 7) ^ RIGHTROTATE(value, 18) ^ (value >> 3)) & 0xFFFFFFFF)

#define LITTLESIGMA1(value) \
    ((RIGHTROTATE(value, 17) ^ RIGHTROTATE(value, 19) ^ (value >> 10)) & 0xFFFFFFFF)

#define BIGSIGMA0(value) \
    ((RIGHTROTATE(value, 2) ^ RIGHTROTATE(value, 13) ^ RIGHTROTATE(value, 22)) & 0xFFFFFFFF)

#define BIGSIGMA1(value) \
    ((RIGHTROTATE(value, 6) ^ RIGHTROTATE(value, 11) ^ RIGHTROTATE(value, 25)) & 0xFFFFFFFF)

#define CH(x, y, z) (((x&y)|((~x)&z))&0xFFFFFFFF)

#define MAJ(a, b, c) (((a&b)|(a&c)|(b&c)) & 0xFFFFFFFF)



uint32_t H0 = 0x6a09e667;
uint32_t H1 = 0xbb67ae85;
uint32_t H2 = 0x3c6ef372;
uint32_t H3 = 0xa54ff53a;
uint32_t H4 = 0x510e527f;
uint32_t H5 = 0x9b05688c;
uint32_t H6 = 0x1f83d9ab;
uint32_t H7 = 0x5be0cd19;

static const uint32_t KEY[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void SHAUtil::dumpMessage(const char *message, int32_t messageLength) {
    for (int i = 0; i < messageLength; ++i) {
        if( (i + 1) % 16 == 0){
            printf("%02x\n", (message[i] & 0xFF));
        } else {
            printf("%02x ", (message[i] & 0xFF));
        }
    }
    printf("\n");
}


int32_t SHAUtil::sha256(const char *message, int64_t messageLength, char *encryptMessage) {
    uint64_t  messageLengthAtBit = messageLength * 8;

    int64_t times = (int64_t)floor(messageLengthAtBit / 512);
    int32_t reserved = messageLengthAtBit % 512;

    int32_t addedLengthAtBit = 0;
    if(reserved >= 448){
        addedLengthAtBit = (times + 1) * 512 + 448 - messageLengthAtBit;
    } else {
        addedLengthAtBit = times * 512 + 448 - messageLengthAtBit;
    }

    int64_t preMessageLengthAtBit = messageLengthAtBit + addedLengthAtBit + 64;
    char* preMessaged = (char*)malloc(preMessageLengthAtBit / 8);
    if(preMessaged == NULL){
        return 1;
    }

    memset(preMessaged, 0, preMessageLengthAtBit / 8);
    memcpy(preMessaged, message, messageLength);
    preMessaged[messageLength] = 0x80;

    uint64_t preMessageLengthAtByte = preMessageLengthAtBit / 8;
    preMessaged[preMessageLengthAtByte - 8] = ((messageLengthAtBit >> 56) & 0xFF);
    preMessaged[preMessageLengthAtByte - 7] = ((messageLengthAtBit >> 48) & 0xFF);
    preMessaged[preMessageLengthAtByte - 6] = ((messageLengthAtBit >> 40) & 0xFF);
    preMessaged[preMessageLengthAtByte - 5] = ((messageLengthAtBit >> 32) & 0xFF);
    preMessaged[preMessageLengthAtByte - 4] = ((messageLengthAtBit >> 24) & 0xFF);
    preMessaged[preMessageLengthAtByte - 3] = ((messageLengthAtBit >> 16) & 0xFF);
    preMessaged[preMessageLengthAtByte - 2] = ((messageLengthAtBit >> 8) & 0xFF);
    preMessaged[preMessageLengthAtByte - 1] = ((messageLengthAtBit >> 0) & 0xFF);



    sprintf(encryptMessage, "%08x%08x%08x%08x%08x%08x%08x%08x",
           H0, H1, H2, H3, H4, H5, H6, H7);
    free(preMessaged);
}