cmake_minimum_required(VERSION 3.10)



# Project setup

project(fastweb)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

list(INSERT CMAKE_PREFIX_PATH 0 /opt/homebrew)
include_directories("/usr/local/include")
link_directories("/usr/local/lib")



# Executable definitions

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

find_path     (LIBEVENT_INCLUDE_DIR NAMES event.h)
find_library  (LIBEVENT_LIBRARY     NAMES event)
find_library  (LIBEVENT_CORE        NAMES event_core)
find_library  (LIBEVENT_THREAD      NAMES event_pthreads)
find_library  (LIBEVENT_SSL         NAMES event_openssl)
set (LIBEVENT_INCLUDE_DIRS ${LIBEVENT_INCLUDE_DIR})
set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARY}
        ${LIBEVENT_CORE}
        ${LIBEVENT_THREAD}
        ${LIBEVENT_SSL})

add_executable(
    fastweb
    src/FileResourceManager.cc
    src/Main.cc
    src/MemoryResourceManager.cc
    src/MIMEType.cc
    src/ResourceManagerBase.cc
)
target_include_directories(fastweb PUBLIC ${LIBEVENT_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})
target_link_libraries(fastweb phosg ${LIBEVENT_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARY} pthread)



# Installation configuration

install(TARGETS fastweb DESTINATION bin)
