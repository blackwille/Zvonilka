import os
from typing import final

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, cmake_layout
from conan.tools.files import copy


@final
class ZvonilkaDeps(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps"

    def requirements(self):
        if self.requires is None:
            return
        self.requires("glew/2.2.0")
        self.requires("imgui/1.92.2b-docking")
        self.requires("libffi/3.4.4")
        self.requires("libnice/0.1.21")
        self.requires("miniaudio/0.11.22")
        self.requires("openssl/3.6.0")
        self.requires("opus/1.5.2")
        self.requires("sdl/3.2.20")
        self.requires("spdlog/1.16.0")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        if self.source_folder is None:
            return

        tc = CMakeToolchain(self)
        tc.cache_variables["CMAKE_EXPORT_COMPILE_COMMANDS"] = "ON"
        tc.generate()

        pkg_folder = self.dependencies["imgui"].package_folder
        copy(
            self,
            "*sdl3*",
            os.path.join(pkg_folder, "res", "bindings"),
            os.path.join(self.source_folder, "imgui_bindings"),
        )
        copy(
            self,
            "*opengl3*",
            os.path.join(pkg_folder, "res", "bindings"),
            os.path.join(self.source_folder, "imgui_bindings"),
        )
