cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

project(
    Zvonilka
    VERSION 1.0
    # HOMEPAGE_URL "https://github.com/..."
    LANGUAGES C CXX
)
set(CMAKE_CXX_STANDARD 20)

cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

project(
    Zvonilka
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_SOURCE_DIR}/dependencies)

find_package(imgui REQUIRED)

# +++ NEW:
find_package(OpenSSL REQUIRED) # добавили
find_package(Threads REQUIRED) # на всякий случай

add_executable(${CMAKE_PROJECT_NAME}
    src/main.cpp
)

target_link_libraries(${PROJECT_NAME}
    imgui::imgui
    OpenSSL::Crypto # добавили
    Threads::Threads # добавили
)
# остальное оставляем
add_subdirectory(src)
