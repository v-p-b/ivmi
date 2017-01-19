cmake_minimum_required(VERSION 2.8)
project(ivmi)
include(ExternalProject)

ExternalProject_Add(drakvuf
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/drakvuf
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --disable-plugin-cpuidmon --disable-plugin-debugmon --disable-plugin-ssdtmon --disable-plugin-objmon --disable-plugin-filedelete --disable-plugin-filetracer --disable-plugin-poolmon --disable-plugin-syscalls --disable-plugin-exmon
    STEP_TARGETS build
    INSTALL_COMMAND true
    BUILD_COMMAND ${MAKE})

ExternalProject_Add_Step(drakvuf autogen
    COMMAND ./autogen.sh
    WORKING_DIRECTORY <SOURCE_DIR> 
)
add_subdirectory("src")

