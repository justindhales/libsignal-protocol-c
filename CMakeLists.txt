cmake_minimum_required(VERSION 2.8.4)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
project(signal-protocol-c)

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW)
endif()

set(SIGNAL_PROTOCOL_C_VERSION_MAJOR 2)
set(SIGNAL_PROTOCOL_C_VERSION_MINOR 3)
set(SIGNAL_PROTOCOL_C_VERSION_PATCH 3)
set(SIGNAL_PROTOCOL_C_VERSION
    ${SIGNAL_PROTOCOL_C_VERSION_MAJOR}.${SIGNAL_PROTOCOL_C_VERSION_MINOR}.${SIGNAL_PROTOCOL_C_VERSION_PATCH}
)

set(LIB_SUFFIX
    ""
    CACHE STRING "Define suffix of directory name (32/64)")
set(BIN_INSTALL_DIR
    "${CMAKE_INSTALL_PREFIX}/bin"
    CACHE STRING "The directory the binaries are installed in")
set(LIB_INSTALL_DIR
    "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}"
    CACHE STRING "The directory the libraries are installed in")
set(INCLUDE_INSTALL_DIR
    "${CMAKE_INSTALL_PREFIX}/include"
    CACHE PATH "The directory the headers are installed in")
set(INSTALL_PKGCONFIG_DIR
    "${LIB_INSTALL_DIR}/pkgconfig"
    CACHE PATH "Installation directory for pkgconfig (.pc) files")

include(CheckSymbolExists)
include(CheckCCompilerFlag)
include(TestBigEndian)

check_symbol_exists(memset_s "string.h" HAVE_MEMSET_S)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  check_symbol_exists(SecureZeroMemory "Windows.h;WinBase.h"
                      HAVE_SECUREZEROMEMORY)
endif(CMAKE_SYSTEM_NAME MATCHES "Windows")

if(BUILD_TESTING)
  enable_testing()
endif(BUILD_TESTING)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -fmessage-length=0 -Wall -Wmissing-field-initializers -Wno-missing-braces -Wparentheses"
  )
endif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

if(CMAKE_COMPILER_IS_GNUCC)
  check_c_compiler_flag("-Wsign-conversion" GCC_WARN_SIGN_CONVERSION)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-compare")
  if(GCC_WARN_SIGN_CONVERSION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-conversion")
  endif(GCC_WARN_SIGN_CONVERSION)
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -Wswitch -Wunused-variable -Wunused-value -Wshadow -Wint-conversion -Wpointer-sign -Wprotocol -Wshorten-64-to-32"
  )
endif(CMAKE_C_COMPILER_ID MATCHES "Clang")

if(HAVE_MEMSET_S)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_MEMSET_S=1")
endif(HAVE_MEMSET_S)

test_big_endian(WORDS_BIGENDIAN)
if(WORDS_BIGENDIAN)
  add_definitions(-DWORDS_BIGENDIAN)
endif(WORDS_BIGENDIAN)

if(COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  set(LINK_FLAGS "${LINK_FLAGS} -fprofile-arcs -ftest-coverage")

  add_custom_command(
    OUTPUT run_coverage
    COMMAND ctest
    COMMAND lcov -q --capture --directory src --output-file coverage.info.total
    COMMAND lcov -q --remove coverage.info.total 'vpool.*' 'ut*.h' '*.pb-c.*'
            'protobuf-c/*' 'curve25519/*' --output-file coverage.info
    COMMAND genhtml -q coverage.info --output-directory coverage
    COMMENT Collecting and creating coverage information)
  add_custom_target(coverage DEPENDS run_coverage)
endif(COVERAGE)

add_subdirectory(src)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif(BUILD_TESTING)
