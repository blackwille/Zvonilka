#!/bin/sh

LINUXDEPLOY_DIR="~/MyApps/AppImage/linuxdeploy-x86_64.AppImage"
ARTIFACTS_DIR=$(dirname $(dirname $(realpath $0)))
export LDAI_OUTPUT="${ARTIFACTS_DIR}/linux/Zvonilka_x86_64.AppImage"
LD_LIBRARY_PATH=${ARTIFACTS_DIR}/linux/usr/lib:$LD_LIBRARY_PATH ${LINUXDEPLOY_DIR} \
    --appdir ${ARTIFACTS_DIR} \
    --output appimage \
    --desktop-file ${ARTIFACTS_DIR}/assets/Zvonilka.desktop \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/16x16/Zvonilka.png \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/32x32/Zvonilka.png \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/64x64/Zvonilka.png \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/128x128/Zvonilka.png \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/256x256/Zvonilka.png \
    --icon-file ${ARTIFACTS_DIR}/assets/icons/scalable/Zvonilka.svg

