//
// Created by guoguo on 2017/11/18.
//

#include <cstdlib>
#include <pthread.h>
#include <cstdio>
#include "ThreadPool.h"

void *threadRoutine(void* pool){
    if(pool == NULL) return NULL;
    ThreadPool* threadPool = (ThreadPool*)pool;
    printf(">>>>>%s\n", __func__);
    while (1) {
        pthread_mutex_lock(&(threadPool->mLock));
        while (threadPool->mWorkNum == 0 && !threadPool->mPoolShutdown){
            pthread_cond_wait(&(threadPool->mCondition), &(threadPool->mLock));
        }

        if(threadPool->mPoolShutdown){
            pthread_mutex_unlock(&(threadPool->mLock));
            pthread_exit(NULL);
        }

        printf(">>>>>%s  mWorkNum: %d\n", __func__,threadPool->mWorkNum);
        if(threadPool->mWorkNum == 0 || threadPool->mWorkQueue == NULL) return NULL;

        threadPool->mWorkNum--;
        Task* task = threadPool->mWorkQueue;
        threadPool->mWorkQueue = task->next;
        pthread_mutex_unlock(&(threadPool->mLock));

        task->run();
        if(task->onTaskCompleted){
            task->onTaskCompleted(task);
        }

        free(task);
        task = NULL;
    }
    pthread_exit(NULL);
}


void ThreadPool::poolInit(int maxThreadNum){
    pthread_mutex_init(&(mLock), NULL);
    pthread_cond_init(&(mCondition), NULL);

    mWorkQueue = NULL;
    mMaxThreadNum = maxThreadNum;
    mWorkNum = 0;
    mPoolShutdown = 0;

}
int ThreadPool::addTaskToPool(Task* task){
    if(task == NULL) return 1;

    printf(">>>>>%s\n", __func__);
    pthread_mutex_lock(&mLock);

    Task* member = mWorkQueue;
    if(member != NULL){
        while (member->next != NULL)
            member = member->next;
        member->next = task;
    } else {
        mWorkQueue = task;
    }
    mWorkNum++;
    pthread_mutex_unlock(&mLock);

    pthread_cond_signal(&mCondition);
    return 0;
}

void ThreadPool::start() {
    if(mWorkNum == 0) delete this;
    mThreads = (pthread_t*)malloc(mMaxThreadNum * sizeof(pthread_t));
    for (int i = 0; i < mMaxThreadNum; i++) {
        pthread_create(&(mThreads[i]), NULL, threadRoutine, this);
    }
}

ThreadPool::~ThreadPool(){
    if(mPoolShutdown) return ;
    printf(">>>>>%s\n", __func__);
    mPoolShutdown = 1;

    pthread_cond_broadcast(&mCondition);

    for (int i = 0; i < mMaxThreadNum; i++) {
        pthread_join(mThreads[i], NULL);
    }
    free(mThreads);

    Task* head = NULL;
    while (mWorkQueue != NULL){
        head = mWorkQueue;
        mWorkQueue = mWorkQueue->next;
        free(head);
    }

    pthread_mutex_destroy(&mLock);
    pthread_cond_destroy(&mCondition);
}