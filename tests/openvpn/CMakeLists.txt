cmake_minimum_required(VERSION 3.16)
project(openvpn_config_tests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Concurrent)
find_package(Boost REQUIRED)
find_package(yaml-cpp REQUIRED)
add_executable(openvpn_config_tests checks.cpp
    ../../src/gharqad/configs/proxy/OpenVPNConfig.cpp)
target_include_directories(openvpn_config_tests PRIVATE ../../src)
target_link_libraries(openvpn_config_tests PRIVATE Qt6::Core)
# Compile against real application headers, without replacing the model or
# editor with fixtures. Unrelated application services are not linked here.
add_library(openvpn_profile_compile OBJECT
    ../../src/gharqad/configs/proxy/OpenVPNBean.cpp
    ../../src/gharqad/ui/profile/edit_openvpn.cpp
    ../../src/gharqad/dataStore/ProxyEntity.cpp)
target_include_directories(openvpn_profile_compile PRIVATE ../../src ${Boost_INCLUDE_DIRS})
target_link_libraries(openvpn_profile_compile PRIVATE Qt6::Widgets Qt6::Network Qt6::Concurrent)
if(TARGET yaml-cpp::yaml-cpp)
    target_link_libraries(openvpn_profile_compile PRIVATE yaml-cpp::yaml-cpp)
else()
    target_link_libraries(openvpn_profile_compile PRIVATE yaml-cpp)
endif()
enable_testing()
add_test(NAME openvpn_config COMMAND openvpn_config_tests)
