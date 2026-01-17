cmake_minimum_required(VERSION 3.18)

project(io_uring_mdns CXX)

include(CTest)

add_subdirectory(iuring)
add_subdirectory(urtsched)

enable_testing()

# Include directories
set(PUBLIC_INCLUDE_DIRECTORIES include/)
set(PRIVATE_INCLUDE_DIRECTORIES src/)

# Source files
file(GLOB_RECURSE SOURCE_FILES "src/*.cpp" "src/*.hpp")
file(GLOB_RECURSE INCLUDE_FILES "include/*.hpp")

add_library(iuring_mdns)

target_compile_features(iuring_mdns PUBLIC cxx_std_23)
target_link_libraries(iuring_mdns iuring slogger urtsched)
target_include_directories(iuring_mdns PUBLIC ${PUBLIC_INCLUDE_DIRECTORIES})
target_include_directories(iuring_mdns PRIVATE ${PRIVATE_INCLUDE_DIRECTORIES})

target_sources(iuring_mdns
    PUBLIC FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
    FILES ${INCLUDE_FILES}
    PRIVATE ${SOURCE_FILES}
)

install(TARGETS iuring_mdns FILE_SET HEADERS)

# Set target properties for public headers
set_target_properties(iuring_mdns PROPERTIES PUBLIC_HEADER "${INCLUDE_FILES}")

find_package(GTest)

if(GTest_FOUND)
add_subdirectory(tests)
endif()