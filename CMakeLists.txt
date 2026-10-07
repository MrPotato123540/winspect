cmake_minimum_required(VERSION 3.21)
 
project(winspect C)
 
add_executable(winspect
    src/main.c
    src/list.c
)

target_include_directories(winspect PRIVATE inc)
 
# C11 makes anonymous unions standard, which winnt.h structs rely on
target_compile_features(winspect PRIVATE c_std_11)
 
# Faster builds, fewer macro collisions, we include extra headers explicitly
target_compile_definitions(winspect PRIVATE WIN32_LEAN_AND_MEAN)
 
if(MSVC)
	target_compile_options(winspect PRIVATE /W4)
	target_compile_definitions(winspect PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
	target_compile_options(winspect PRIVATE -Wall -Wextra -Wpedantic)
endif()
 