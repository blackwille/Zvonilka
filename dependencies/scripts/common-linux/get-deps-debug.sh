#!/bin/sh

DEPENDENCIES_DIR=$(dirname $(dirname $(dirname $(realpath $0))))
conan install ${DEPENDENCIES_DIR} --build=missing --settings=build_type=Debug
