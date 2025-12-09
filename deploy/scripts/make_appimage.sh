#!/bin/sh

LINUXDEPLOY_DIR="~/MyApps/AppImage/linuxdeploy-x86_64.AppImage"
DEPLOY_DIR=$(dirname $(dirname $(realpath $0)))
export LDAI_OUTPUT="${DEPLOY_DIR}/linux/Zvonilka_x86_64.AppImage"
LD_LIBRARY_PATH=${DEPLOY_DIR}/linux/usr/lib:$LD_LIBRARY_PATH ${LINUXDEPLOY_DIR} \
    --appdir ${DEPLOY_DIR} \
    --output appimage \
    --desktop-file ${DEPLOY_DIR}/assets/Zvonilka.desktop \
    --icon-file ${DEPLOY_DIR}/assets/icons/16x16/Zvonilka.png \
    --icon-file ${DEPLOY_DIR}/assets/icons/32x32/Zvonilka.png \
    --icon-file ${DEPLOY_DIR}/assets/icons/64x64/Zvonilka.png \
    --icon-file ${DEPLOY_DIR}/assets/icons/128x128/Zvonilka.png \
    --icon-file ${DEPLOY_DIR}/assets/icons/256x256/Zvonilka.png \
    --icon-file ${DEPLOY_DIR}/assets/icons/scalable/Zvonilka.svg
