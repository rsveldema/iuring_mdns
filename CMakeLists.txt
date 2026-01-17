cmake_minimum_required(VERSION 3.18)

project(iuring_mdns CXX)

set(MDNS_SOURCES
    src/mdns/MDNS_Service.cpp
    src/mdns/MDNS_Ravenna_HTTP_Handler.cpp
    src/mdns/MDNS_Ravenna_RTSP_Handler.cpp
    src/mdns/MDNS_NMOS_HTTP_Handler.cpp
)

add_subdirectory(iuring)

add_library(iuring_mdns ${MDNS_SOURCES})

target_compile_features(iuring_mdns PUBLIC cxx_std_23)
target_include_directories(iuring_mdns PUBLIC 
    include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    iuring/iuring/include
)
target_link_libraries(iuring_mdns PUBLIC iuring_httpserver)
