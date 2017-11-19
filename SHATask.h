//
// Created by guoguo on 2017/11/19.
//

#ifndef SHAUTIL_SHATASK_H
#define SHAUTIL_SHATASK_H

#include "Task.h"

class SHATask : public Task {
public:
    SHATask(char* &, uint32_t messageLen);

    int32_t run();
    uint32_t *getTaskResult();
private:
    uint32_t H[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
    };
    char* mPostdMessage;
    uint32_t mMessageLengthAtBit;
    ~SHATask();
};


#endif //SHAUTIL_SHATASK_H
