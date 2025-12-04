#!/bin/sh

DEPENDENCIES_DIR=$(dirname $(dirname $(dirname $(realpath $0))))
INSTALLATION_DIR=${DEPENDENCIES_DIR}/../artifacts/
conan install ${DEPENDENCIES_DIR} --settings=build_type=Release --deployer=full_deploy --deployer-folder=${INSTALLATION_DIR}

FULL_DEPLOY_BASE=${INSTALLATION_DIR}"/full_deploy"
FULL_DEPLOY_ROOT=${FULL_DEPLOY_BASE}"/host"

INSTALL_LIB_DIR=${INSTALLATION_DIR}"/usr/lib"
INSTALL_BIN_DIR=${INSTALLATION_DIR}"/usr/bin"
INSTALL_INCLUDE_DIR=${INSTALLATION_DIR}"/usr/include"


mkdir -p "${INSTALL_LIB_DIR}" "${INSTALL_BIN_DIR}" "${INSTALL_INCLUDE_DIR}"

find "${FULL_DEPLOY_ROOT}" -path "*/Release/x86_64/lib/*.so*" -exec cp -L {} "${INSTALL_LIB_DIR}" \;
echo "Copied shared libraries from Release/lib to ${INSTALL_LIB_DIR}"

find "${FULL_DEPLOY_ROOT}" -path "*/Release/x86_64/bin/*" -type f -exec cp -L {} "${INSTALL_BIN_DIR}" \;
echo "Copied binaries from Release/bin to ${INSTALL_BIN_DIR}"

find "${FULL_DEPLOY_ROOT}" -path "*/Release/x86_64/include/*" -exec cp -L {} "${INSTALL_INCLUDE_DIR}" \;
echo "Copied headers from Release/include to ${INSTALL_INCLUDE_DIR}"

# Clean up the temporary, nested full_deploy folder structure
rm -rf "${FULL_DEPLOY_BASE}"

echo "Conan artifacts structure is now ready for linuxdeploy in the 'artifacts' folder."

