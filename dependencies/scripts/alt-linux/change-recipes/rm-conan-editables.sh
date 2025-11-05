#!/bin/bash

conan editable remove $(dirname $0)/xorg-system
conan editable remove $(dirname $0)/opengl-system
conan editable remove $(dirname $0)/egl-system
conan editable remove $(dirname $0)/libudev-system