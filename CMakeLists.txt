cmake_minimum_required(VERSION 3.8)
project(SHAUtil)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp SHAUtil.cpp SHAUtil.h ThreadPool.cpp ThreadPool.h Task.cpp Task.h SHATask.cpp SHATask.h)
add_executable(SHAUtil ${SOURCE_FILES})