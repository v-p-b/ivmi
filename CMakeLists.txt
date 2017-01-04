cmake_minimum_required(VERSION 2.8)
project(vebug)
include(ExternalProject)

ExternalProject_Add(drakvuf
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/drakvuf
    STEP_TARGETS build
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
    BUILD_COMMAND ${MAKE})

ExternalProject_Add_Step(drakvuf autogen
    COMMAND ./autogen.sh
    WORKING_DIRECTORY <SOURCE_DIR> 
)
add_subdirectory("src")

