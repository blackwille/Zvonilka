#!/bin/sh

PARENT_DIR=$(dirname $(dirname $(realpath $0)))
DEPENDENCIES_DIR=${PARENT_DIR}
conan install ${DEPENDENCIES_DIR} --build=missing --settings=build_type=Debug
