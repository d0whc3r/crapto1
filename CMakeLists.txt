cmake_minimum_required(VERSION 3.6)
project(crapto1)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
    crapto1.c
    crapto1.h
    crypto1.c
    test.c)

add_executable(crapto1 ${SOURCE_FILES})