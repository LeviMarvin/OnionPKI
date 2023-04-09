cmake_minimum_required(VERSION 3.24)
project(OnionPKI VERSION 0.1.0 LANGUAGES C)


# Dependencies
# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_C_STANDARD 11)
include_directories(${PROJECT_SOURCE_DIR}/include)

set(SOURCE_FILES include/onionpki/storage.h include/onionpki/websrv/win/socket.h src/onionpki/websrv/win/socket.c include/onionpki/websrv.h include/onionpki/websrv/server.h src/sqlite/sqlite3.c include/sqlite/sqlite3.h src/onionpki/x509/cert_v3.c include/onionpki/x509/cert_v3.h include/onionpki/cert.h include/onionpki/stderr.h src/onionpki/onion.c src/onionpki/x509/ext.c include/onionpki/x509/ext.h include/onionpki/key.h src/onionpki/key/rsa.c include/onionpki/key/rsa.h src/onionpki/x509/crl_v2.c include/onionpki/x509/crl_v2.h include/onionpki/crl.h include/onionpki/stdonion.h src/onionpki/stdonion.c include/onionpki/x509/x509.h src/onionpki/x509/x509.c src/onionpki/ocsp/ocsp.c include/onionpki/ocsp/ocsp.h include/onionpki/ocsp.h src/onionpki/websrv/websrv.c src/onionpki/websrv/server.c src/onionpki/storage/dao.c include/onionpki/storage/dao.h)

# File information for Windows
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(VERSIONINFO_RC "${CMAKE_BINARY_DIR}/verinfo.rc")
    configure_file("${CMAKE_SOURCE_DIR}/src/onionpki/verinfo.rc.in" "${VERSIONINFO_RC}")
    set(SOURCE_FILES ${SOURCE_FILES} ${VERSIONINFO_RC})
endif()

add_executable(OnionPKI ${SOURCE_FILES})
target_link_libraries(OnionPKI OpenSSL::SSL OpenSSL::Crypto)
