#include <iostream>
#include <cstring>
#include "SHAUtil.h"
#include "ThreadPool.h"
#include "SHATask.h"


using namespace std;


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <cmath>

// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

// 3.2
uint32_t rotr(uint32_t x, size_t n) {
    return (x >> n) | (x << (32-n));
}

uint32_t shr(uint32_t x, size_t n) {
    return x >> n;
}

// 4.1.2
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}
uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

// swap byte endian
uint32_t swapE32(uint32_t val) {
    uint32_t x = val;
    x = (x & 0xffff0000) >> 16 | (x & 0x0000ffff) << 16;
    x = (x & 0xff00ff00) >>  8 | (x & 0x00ff00ff) <<  8;
    return x;
}

uint64_t swapE64(uint64_t val) {
    uint64_t x = val;
    x = (x & 0xffffffff00000000) >> 32 | (x & 0x00000000ffffffff) << 32;
    x = (x & 0xffff0000ffff0000) >> 16 | (x & 0x0000ffff0000ffff) << 16;
    x = (x & 0xff00ff00ff00ff00) >>  8 | (x & 0x00ff00ff00ff00ff) <<  8;
    return x;
}

// print hex numbers
void hex(void* buffer, size_t len) {
    for(size_t i = 0; i < len; i++) {
        printf("%02x", ((char*)buffer)[i] & 0xff);
        if(i % 4 == 3)
            printf("");
    }
}

void hexOutput(void* buffer, size_t len) {
    hex(buffer, len);
    printf("\n");
}
void dumpMessage(const char *message, int32_t messageLength) {
    for (int i = 0; i < messageLength; ++i) {
        if( (i + 1) % 16 == 0){
            printf("%02x\n", (message[i] & 0xFF));
        } else {
            printf("%02x ", (message[i] & 0xFF));
        }
    }
    printf("\n");
}

int sha256(const char* msg) {
//    if(argc < 2) {
//        printf("Usage: sha256 <string>\n");
//        return 0;
//    }

    // 4.2.2
    uint32_t K[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // 5.3.2
    uint32_t H[] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t len = strlen(msg);

    // 5.1.1
    uint64_t l = len * sizeof(char) * 8;
    size_t k = (448 - l - 1) % 512;

    if(k < 0) k += 512;
    assert((l+1+k) % 512 == 448);

    size_t msgSize = l + 1 + k + 64;

    char* msgPad = (char*)calloc((msgSize / 8), sizeof(char));
    memcpy(msgPad, msg, len);
    msgPad[len] = 0x80;
    l = swapE64(l);
    memcpy(msgPad+(msgSize/8)-8, &l, 8);

//    dumpMessage(msgPad, msgSize / 8);

    // 5.2.1
    size_t N = msgSize / 512;

    // 6.2
    uint32_t v[8];
    uint32_t W[64];
    uint32_t* M = (uint32_t*)msgPad;
    uint32_t T1, T2;

    for(size_t i = 0; i < N * 16; i++) {
        M[i] = swapE32(M[i]);
    }

    // 6.2.2
    for(size_t i = 0; i < N; i++) {
        // 1
        for(size_t t = 0; t < 16; t++) {
            W[t] = M[i*16 + t];
        }
        for(size_t t = 16; t < 64; t++) {
            W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
        }

        // 2
        for(size_t t = 0; t < 8; t++) {
            v[t] = H[t];
        }

        // 3
        for(size_t t = 0; t < 64; t++) {
            T1 = v[7] + ep1(v[4]) + Ch(v[4], v[5], v[6]) + K[t] + W[t];
            T2 = ep0(v[0]) + Maj(v[0], v[1], v[2]);

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] + T1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = T1 + T2;

        }

        for(size_t t = 0; t < 8; t++) {
            H[t] += v[t];
        }
    }

    for(size_t i = 0; i < 8; i++) {
        H[i] = swapE32(H[i]);
        hex(&H[i], 4);
    }
    printf("\n");

    free(msgPad);
    return 0;
}

ThreadPool* mThreadPool;
uint32_t mutiThreadHashResult[8] = {0};
static int32_t mRunningTaskNum = 0;
void onTaskCompleted(Task* task){
    SHATask* shaTask = (SHATask*)task;
    if(shaTask == NULL)
        return;
    printf(">>>>%s[%d]\n",__func__, __LINE__);
    uint32_t* result = shaTask->getTaskResult();
    if (result == NULL)return;
    for (int i = 0; i < 8; i++) {
        mutiThreadHashResult[i] += result[i];
    }
    mRunningTaskNum --;

}


void preprocessedMessage(const char *message, int64_t messageLength){
    if(mThreadPool == NULL) return;
    printf(">>>>>%s\n", __func__);
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
        return;
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

    uint64_t taskMessageSizeAtBit = 4 * 1024 * 8;
    uint64_t taskNumber = (uint64_t)(preMessageLengthAtBit / taskMessageSizeAtBit + 1);
    mRunningTaskNum = taskNumber;
    printf(">>>>>%s taskNumber: %d\n", __func__, taskNumber);
    for (int i = 0; i < taskNumber - 1; i++) {
        printf(">>>>>%s[%d]: \n", __func__, __LINE__);
        char* taskMessage = preMessaged + i * taskMessageSizeAtBit;
        SHATask* shaTask = new SHATask(taskMessage, taskMessageSizeAtBit);
        shaTask->setCompletedCallback(onTaskCompleted);
        mThreadPool->addTaskToPool(shaTask);
    }

    uint64_t latestMessageOffset = (taskMessageSizeAtBit * (taskNumber - 1));
    uint32_t latestMessageSizeAtBit = preMessageLengthAtBit - latestMessageOffset;
    char* latestMessage = preMessaged + latestMessageOffset;
    SHATask* latestTask = new SHATask(latestMessage, latestMessageSizeAtBit);
    latestTask->setCompletedCallback(onTaskCompleted);

    mThreadPool->addTaskToPool(latestTask);
    printf("<<<<<<<<<<<<<<<<%s\n", __func__);
}

int main() {
    struct timeval start, end;
    mThreadPool = new ThreadPool(4);
    const char* message ="dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
    "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
    "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
            "dffadafaeDAETaerhyirohGSWRYT427875jsr2q256yykie6479lstqF.lyp[8690q345tqadfV;yiargafartqagfQAGRAFDHKWWDFAadd"
    ;


    int64_t messageLength = strlen(message);
    char* encryptMessage = (char*)malloc(64);
    if(encryptMessage == NULL){
        cout<<"Internal Error"<<endl;
        return 1;
    }

    printf("messageLength: %d bytes\n", messageLength);
    preprocessedMessage(message, messageLength);
    mThreadPool->start();
    printf("mRunningTaskNum: %d \n", mRunningTaskNum);
    while (mThreadPool->mPoolShutdown)
//    while (mRunningTaskNum > 0)
        printf("mRunningTaskNum: %d, Result:\n%08x%08x%08x%08x%08x%08x%08x%08x\n",
               mRunningTaskNum,
               mutiThreadHashResult[0],mutiThreadHashResult[1],
               mutiThreadHashResult[2],mutiThreadHashResult[3],
               mutiThreadHashResult[4],mutiThreadHashResult[5],
               mutiThreadHashResult[6],mutiThreadHashResult[7]);

/*
    SHAUtil* shaUtil = new SHAUtil();
    gettimeofday( &start, NULL );
    shaUtil->sha256(message, messageLength, encryptMessage);
    gettimeofday( &end, NULL );

    printf("%s\n", encryptMessage);
    printf("time  : %d us\n", (end.tv_sec * 1000000 + end.tv_usec)- (start.tv_sec * 1000000 + start.tv_usec) );
    free(encryptMessage);

    gettimeofday( &start, NULL );
    sha256(message);
    gettimeofday( &end, NULL );
    printf("time  : %d us\n", (end.tv_sec * 1000000 + end.tv_usec)- (start.tv_sec * 1000000 + start.tv_usec) );
*/
    delete(mThreadPool);
    return 0;
}
