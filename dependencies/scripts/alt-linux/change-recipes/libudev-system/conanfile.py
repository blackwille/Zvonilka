from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.system import package_manager
from conan.tools.gnu import PkgConfig

required_conan_version = ">=1.50.0"


class LibUDEVConan(ConanFile):
    name = "libudev"
    version = "system"
    description = "API for enumerating and introspecting local devices"
    topics = ("udev", "devices", "enumerating")
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://www.freedesktop.org/software/systemd/man/udev.html"
    license = "GPL-2.0-or-later", "LGPL-2.1-or-later"
    package_type = "shared-library"
    settings = "os", "arch", "compiler", "build_type"

    def layout(self):
        pass

    def validate(self):
        if self.settings.os != "Linux":
            raise ConanInvalidConfiguration("libudev is only supported on Linux.")

    def package_id(self):
        self.info.clear()

    def system_requirements(self):
        yum = package_manager.Yum(self)
        yum.install(["libsystemd-devel"], update=False, check=True)

    def package_info(self):
        self.cpp_info.includedirs = []
        self.cpp_info.libdirs = []
        pkg_config = PkgConfig(self, "libudev")
        pkg_config.fill_cpp_info(self.cpp_info)
        self.cpp_info.set_property("system_package_version", str(pkg_config.version))

        # todo Remove this workaround for Conan v1
        self.cpp_info.set_property("component_version", str(pkg_config.version))
