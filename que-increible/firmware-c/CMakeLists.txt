# Firmware de los TPV de tienda de Que Increible Compañia SL (empresa ficticia de demo).
cmake_minimum_required(VERSION 3.20)
project(firmware_tpv C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
find_package(OpenSSL 3 REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(liboqs REQUIRED)
find_package(Botan 3 REQUIRED)
add_executable(tpv src/terminal/pin.c src/terminal/tls_central.c src/terminal/firma_tickets.c
               src/terminal/actualizacion.c src/interfaz/Telemetria.cpp src/interfaz/Fidelizacion.cpp)
target_include_directories(tpv PRIVATE include)
target_link_libraries(tpv OpenSSL::Crypto OpenSSL::SSL MbedTLS::mbedcrypto OQS::oqs Botan::Botan)
