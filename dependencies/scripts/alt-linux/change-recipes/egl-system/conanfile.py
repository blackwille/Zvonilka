from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.gnu import PkgConfig
from conan.tools.system import package_manager

required_conan_version = ">=1.50.0"


class SysConfigEGLConan(ConanFile):
    name = "egl"
    version = "system"
    description = "cross-platform virtual conan package for the EGL support"
    topics = ("opengl", "egl")
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://www.khronos.org/egl"
    license = "MIT"
    package_type = "shared-library"
    settings = "os", "arch", "compiler", "build_type"

    def layout(self):
        pass

    def package_id(self):
        self.info.clear()

    def validate(self):
        if self.settings.os not in ["Linux", "FreeBSD"]:
            raise ConanInvalidConfiguration("This recipes supports only Linux and FreeBSD")

    def system_requirements(self):
        # IN ALT LINUX ONLY YUM WORKING FOR CHECKING!!! MUST BE SPECIFIED <<tools.system.package_manager:tool = yum>> IN global.conf!!!
        yum = package_manager.Yum(self)
        yum.install(["libEGL-devel"], update=False, check=True)

    def package_info(self):
        self.cpp_info.includedirs = []
        self.cpp_info.libdirs = []
        pkg_config = PkgConfig(self, "egl")
        pkg_config.fill_cpp_info(self.cpp_info, is_system=True)