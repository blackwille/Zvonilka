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

find_package(GLEW REQUIRED)
find_package(imgui REQUIRED)
find_package(libnice REQUIRED)
find_package(miniaudio REQUIRED)
find_package(OpenGL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Opus REQUIRED)
find_package(SDL3 REQUIRED)
find_package(spdlog REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
    ${DEPENDENCIES_DIR}/imgui_bindings/imgui_impl_sdl3.cpp
    ${DEPENDENCIES_DIR}/imgui_bindings/imgui_impl_opengl3.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    GLEW::GLEW
    imgui::imgui
    libnice::libnice
    miniaudio::miniaudio
    OpenGL::GL
    OpenSSL::Crypto
    OpenSSL::SSL
    Opus::opus
    SDL3::SDL3
    spdlog::spdlog
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${DEPENDENCIES_DIR}
)

add_subdirectory(src)

if (UNIX AND NOT APPLE)
  find_package(X11 REQUIRED)
  target_link_libraries(${PROJECT_NAME} PRIVATE X11::X11 dl)
endif()

install(TARGETS ${PROJECT_NAME})
