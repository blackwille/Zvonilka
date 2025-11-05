#!/bin/bash

conan editable add $(dirname $0)/xorg-system
conan editable add $(dirname $0)/opengl-system
conan editable add $(dirname $0)/egl-system
conan editable add $(dirname $0)/libudev-system