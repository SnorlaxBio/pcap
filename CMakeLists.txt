cmake_minimum_required(VERSION 3.22)
project(SnorlaxPCAP C)
include(ExternalProject)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DSNORLAX_DEBUG")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DSNORLAX_DEBUG")

include_directories(src include)

message(${CMAKE_CURRENT_SOURCE_DIR})

ExternalProject_Add(snorlax-std
    PREFIX          "${PROJECT_SOURCE_DIR}/lib/snorlax/std"
    TMP_DIR         "${PROJECT_SOURCE_DIR}/lib/snorlax/std/tmp"
    STAMP_DIR       "${PROJECT_SOURCE_DIR}/lib/snorlax/std/stamp"
    DOWNLOAD_DIR    "${PROJECT_SOURCE_DIR}/lib/snorlax/std/src"
    SOURCE_DIR      "${PROJECT_SOURCE_DIR}/lib/snorlax/std/src"
    BINARY_DIR      "${PROJECT_SOURCE_DIR}/lib/snorlax/std/build"
    INSTALL_DIR     "${PROJECT_SOURCE_DIR}/lib/snorlax/std/install"
    LOG_DIR         "${PROJECT_SOURCE_DIR}/lib/snorlax/std/log"
    GIT_REPOSITORY  git@github.com:SnorlaxBio/std.git
    GIT_TAG         main
    GIT_REMOTE_NAME origin
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug
                                       -S "${PROJECT_SOURCE_DIR}/lib/snorlax/std/src"
                                       -B "${PROJECT_SOURCE_DIR}/lib/snorlax/std/build"
                                       --install-prefix ${PROJECT_SOURCE_DIR}
    BUILD_COMMAND     ${CMAKE_COMMAND} --build "${PROJECT_SOURCE_DIR}/lib/snorlax/std/build"
                                       --target all)

ExternalProject_Add(snorlax-protocol
    PREFIX          "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol"
    TMP_DIR         "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/tmp"
    STAMP_DIR       "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/stamp"
    DOWNLOAD_DIR    "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/src"
    SOURCE_DIR      "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/src"
    BINARY_DIR      "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/build"
    INSTALL_DIR     "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/install"
    LOG_DIR         "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/log"
    GIT_REPOSITORY  git@github.com:SnorlaxBio/protocol.git
    GIT_TAG         main
    GIT_REMOTE_NAME origin
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug
                                       -S "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/src"
                                       -B "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/build"
                                       --install-prefix ${PROJECT_SOURCE_DIR}
    BUILD_COMMAND     ${CMAKE_COMMAND} --build "${PROJECT_SOURCE_DIR}/lib/snorlax/protocol/build"
                                       --target all)

link_directories(${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/build)

set(SNORLAX_PCAP_SOURCE     src/snorlax/pcap.c
                            src/snorlax/pcap/packet.c
                            src/snorlax/pcap/packet/capture.c)

set(SNORLAX_PCAP_HEADER     src/snorlax/pcap.h
                            src/snorlax/pcap/packet.h
                            src/snorlax/pcap/packet/capture.h)

add_library(snorlax-pcap ${SNORLAX_PCAP_SOURCE}
                         ${SNORLAX_PCAP_HEADER})

target_compile_options(snorlax-pcap PUBLIC "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")

add_executable(snorlax-pcap-check src/snorlax/pcap/main.c)
target_link_libraries(snorlax-pcap-check snorlax-pcap libsnorlax-protocol.a libsnorlax-std.a -lpcap)
