//
// Created by guoguo on 2017/11/19.
//
#include <cstdio>
#include <iostream>
#include <cmath>
#include <cstring>
#include "SHATask.h"

using namespace std;

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

SHATask::SHATask(char* &message, uint32_t messageLen) {
    printf(">>>>>%s\n", __func__);
    mPostdMessage = message;
    mMessageLengthAtBit = messageLen;
}

int32_t SHATask::run(){
    printf(">>>>>%s\n", __func__);
    mState = RUNNING;
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t *M = (uint32_t*)mPostdMessage;
    uint32_t words[64] = {0};

    int32_t chunkMAX = mMessageLengthAtBit / 512; // 512 bit as a chunk
    for (int64_t chunkIndex = 0; chunkIndex < chunkMAX; chunkIndex++) {
        for(int i = 0; i < 16; i++){
            words[i] = __htonl(M[chunkIndex * 16 + i]);
        }

        for (int i = 16; i < 64; i++) {
            words[i] = words[i - 16]
                       + LITTLESIGMA0(words[i - 15])
                       + words[i - 7]
                       + LITTLESIGMA1(words[i - 2]);
        }

        A = this->H[0];
        B = this->H[1];
        C = this->H[2];
        D = this->H[3];
        E = this->H[4];
        F = this->H[5];
        G = this->H[6];
        H = this->H[7];
        for (int i = 0; i < 64; i++) {
            uint32_t temp1 = H + BIGSIGMA1(E)
                             + CH(E, F, G)
                             + KEY[i] + words[i];
            uint32_t temp2 = BIGSIGMA0(A) + MAJ(A, B, C);
            H = G; G = F; F = E; E = D + temp1;
            D = C; C = B; B = A; A = temp1 + temp2;
        }
        this->H[0] += A;
        this->H[1] += B;
        this->H[2] += C;
        this->H[3] += D;
        this->H[4] += E;
        this->H[5] += F;
        this->H[6] += G;
        this->H[7] += H;
    }
    mState = COMPLETE;
    return 0;
}
uint32_t* SHATask::getTaskResult(){
    if(mState == COMPLETE){
        return this->H;
    }
}

SHATask::~SHATask() {

}