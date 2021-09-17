# cmake min version
cmake_minimum_required(VERSION 3.11)

# project name
project(nydus-stat)

# configuration
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
	nlohmann_json
	URL https://github.com/nlohmann/json/archive/refs/tags/v3.10.2.tar.gz
)

FetchContent_MakeAvailable(nlohmann_json)

# target binary
add_executable(${PROJECT_NAME} src/nydus-stat.cpp)
target_link_libraries(${PROJECT_NAME} nlohmann_json::nlohmann_json)