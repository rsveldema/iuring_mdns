
find_package(GTest REQUIRED)

add_executable(iuring_mdns_unittests tests.cpp test_mdns_service.cpp)
target_include_directories(iuring_mdns_unittests PUBLIC ${GTEST_INCLUDE_DIRS})
target_link_libraries(iuring_mdns_unittests iuring_mdns  -lgtest -lgmock -lgtest_main )


add_test(NAME googletest
         COMMAND iuring_mdns_unittests)