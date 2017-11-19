//
// Created by guoguo on 2017/11/18.
//

#ifndef SHAUTIL_THREADPOOL_H
#define SHAUTIL_THREADPOOL_H


#include <sys/types.h>
#include "Task.h"

class ThreadPool {
public:
    ThreadPool(int threadNum){
        poolInit(threadNum);
    }
    void poolInit(int maxThreadNum);
    int addTaskToPool(Task* task);


    void start();
    pthread_mutex_t mLock;
    pthread_cond_t  mCondition;

    Task* mWorkQueue;

    int mPoolShutdown;

    pthread_t* mThreads;
    int mMaxThreadNum;
    int mWorkNum;

    ~ThreadPool();

};


#endif //SHAUTIL_THREADPOOL_H
