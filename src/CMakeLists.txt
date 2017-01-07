add_executable(ivmi ivmi.cpp)
include_directories("../drakvuf/src")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb -std=c++11")

ExternalProject_Get_Property(drakvuf binary_dir)
add_dependencies(ivmi drakvuf)

file(GLOB drakvuf_objects "${binary_dir}/src/libdrakvuf/*.o")
target_link_libraries(ivmi ${drakvuf_objects})

file(GLOB xenhelper_objects "${binary_dir}/src/xen_helper/*.o")
target_link_libraries(ivmi ${xenhelper_objects})

find_library(JSONC_LIBRARY "json-c" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${JSONC_LIBRARY})

find_library(GLIB_LIBRARY "glib-2.0" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${GLIB_LIBRARY})

find_library(XENTOOLLOG_LIBRARY "xentoollog" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${XENTOOLLOG_LIBRARY})

find_library(XENCTRL_LIBRARY "xenctrl" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${XENCTRL_LIBRARY})

find_library(XENLIGHT_LIBRARY "xenlight" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${XENLIGHT_LIBRARY})

find_library(VMI_LIBRARY "vmi" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${VMI_LIBRARY})

find_library(PTHREAD_LIBRARY "pthread" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${PTHREAD_LIBRARY})

find_library(XENSTORE_LIBRARY "xenstore" "/usr/lib" "/usr/local/lib")
target_link_libraries(ivmi ${XENSTORE_LIBRARY})

find_package(PkgConfig)
pkg_check_modules(PC_JSON-C QUIET json-c)

find_path(JSON-C_INCLUDE_DIR json.h
    HINTS ${PC_JSON-C_INCLUDEDIR} ${PC_JSON-C_INCLUDE_DIRS} PATH_SUFFIXES json-c json)

find_library(JSON-C_LIBRARY NAMES json-c libjson-c
    HINTS ${PC_JSON-C_LIBDIR} ${PC_JSON-C_LIBRARY_DIRS})

set(JSON-C_LIBRARIES ${JSON-C_LIBRARY})
set(JSON-C_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(JSON-C DEFAULT_MSG JSON-C_LIBRARY JSON-C_INCLUDE_DIR)

mark_as_advanced(JSON-C_INCLUDE_DIR JSON-C_LIBRARY)
target_link_libraries(ivmi ${JSON-C_LIBRARY})

target_link_libraries(ivmi zmq)
target_link_libraries(ivmi zmqpp)

pkg_check_modules (GLIB2 REQUIRED glib-2.0)

include_directories (${GLIB2_INCLUDE_DIRS})
target_link_libraries (ivmi ${GLIB2_LIBRARIES})
