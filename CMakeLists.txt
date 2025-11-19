cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

project(
    Zvonilka
    VERSION 0.0
    # HOMEPAGE_URL "https://github.com/..."
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(DEPENDENCIES_DIR ${CMAKE_SOURCE_DIR}/dependencies)

include_directories(${DEPENDENCIES_DIR})

find_package(imgui REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SDL3 REQUIRED)           
find_package(OpenGL REQUIRED)
find_package(miniaudio REQUIRED)   
find_package(Opus REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
    ${DEPENDENCIES_DIR}/imgui_bindings/imgui_impl_sdl3.cpp
    ${DEPENDENCIES_DIR}/imgui_bindings/imgui_impl_opengl3.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    imgui::imgui
    OpenSSL::SSL 
    OpenSSL::Crypto
    SDL3::SDL3
    OpenGL::GL
    miniaudio::miniaudio
    Opus::opus
)

add_subdirectory(src)

if (UNIX AND NOT APPLE)
  find_package(X11 REQUIRED)
  target_link_libraries(${PROJECT_NAME} PRIVATE X11::X11 dl)
endif()
