//
// Created by guoguo on 2017/11/18.
//

#ifndef SHAUTIL_SHAUTIL_H
#define SHAUTIL_SHAUTIL_H


#include <cstdint>

class SHAUtil {
public:
    int32_t sha1(const char* message, int64_t messageLength,
                char* encryptMessage);

    int32_t sha256(const char* message, int64_t messageLength,
                 char* encryptMessage);

    void dumpMessage(const char* message, int32_t messageLength);

};


#endif //SHAUTIL_SHAUTIL_H
