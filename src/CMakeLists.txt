add_executable(vebug vebug.cpp)
include_directories("../drakvuf/src")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")

ExternalProject_Get_Property(drakvuf binary_dir)
add_dependencies(vebug drakvuf)

file(GLOB drakvuf_objects "${binary_dir}/src/libdrakvuf/*.o")
target_link_libraries(vebug ${drakvuf_objects})

file(GLOB xenhelper_objects "${binary_dir}/src/xen_helper/*.o")
target_link_libraries(vebug ${xenhelper_objects})

find_library(JSONC_LIBRARY "json-c" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${JSONC_LIBRARY})

find_library(GLIB_LIBRARY "glib-2.0" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${GLIB_LIBRARY})

find_library(XENTOOLLOG_LIBRARY "xentoollog" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${XENTOOLLOG_LIBRARY})

find_library(XENCTRL_LIBRARY "xenctrl" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${XENCTRL_LIBRARY})

find_library(XENLIGHT_LIBRARY "xenlight" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${XENLIGHT_LIBRARY})

find_library(VMI_LIBRARY "vmi" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${VMI_LIBRARY})

find_library(PTHREAD_LIBRARY "pthread" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${PTHREAD_LIBRARY})

find_library(XENSTORE_LIBRARY "xenstore" "/usr/lib" "/usr/local/lib")
target_link_libraries(vebug ${XENSTORE_LIBRARY})

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
target_link_libraries(vebug ${JSON-C_LIBRARY})
