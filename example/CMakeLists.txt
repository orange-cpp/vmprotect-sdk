
project(example LANGUAGES CXX)
add_executable(${PROJECT_NAME} example/main.cpp)

target_link_libraries(${PROJECT_NAME} vmprotect_sdk)
