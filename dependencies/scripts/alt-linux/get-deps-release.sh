#!/bin/sh

CURRENT_DIR=$(dirname $(realpath $0))
DEPENDENCIES_DIR=$(dirname $(dirname $(dirname $(realpath $0))))
${CURRENT_DIR}/change-recipes/add-conan-editables.sh
${DEPENDENCIES_DIR}/scripts/common-linux/get-deps-release.sh
${CURRENT_DIR}/change-recipes/rm-conan-editables.sh
