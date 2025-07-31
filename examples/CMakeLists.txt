# Simple example that demonstrates inkpacket protection

add_executable(example_basic basic.cpp)
target_link_libraries(example_basic PRIVATE inkpacket)

add_executable(example_crypto crypto_demo.cpp)
target_link_libraries(example_crypto PRIVATE inkpacket)

add_executable(example_patcher simple_patcher.cpp)
target_link_libraries(example_patcher PRIVATE inkpacket)

add_executable(example_loader loader_demo.cpp)
target_link_libraries(example_loader PRIVATE inkpacket)

add_executable(example_complete complete_demo.cpp)
target_link_libraries(example_complete PRIVATE inkpacket)

# Protected app demo
add_library(secret_lib SHARED secret_lib.cpp)
set_target_properties(secret_lib PROPERTIES PREFIX "")

add_executable(protected_app protected_app.cpp)
target_link_libraries(protected_app PRIVATE inkpacket ${CMAKE_DL_LIBS})

add_executable(wrong_key_demo wrong_key_demo.cpp)
target_link_libraries(wrong_key_demo PRIVATE inkpacket)