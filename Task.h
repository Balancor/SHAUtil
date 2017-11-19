//
// Created by guoguo on 2017/11/18.
//

#ifndef SHAUTIL_TASK_H
#define SHAUTIL_TASK_H


#include <stdint-gcc.h>
enum TaskState{
    RUNNING,
    COMPLETE
};

class Task {
public:
    void setCompletedCallback(void(*callbackFunc)(Task*)){
        this->onTaskCompleted = callbackFunc;
    }
    virtual int32_t run() = 0;
    void (*onTaskCompleted)(Task*);
    uint32_t mArgumentsCount;
    void* mArguments;
    TaskState mState = RUNNING;
    Task* next;


};


#endif //SHAUTIL_TASK_H
