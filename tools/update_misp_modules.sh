#!/usr/bin/env bash

set -e
set -x

# Updates the MISP Modules while respecting the current permissions
# It aims to support the two following installation methods:
# * Everything is runinng on the same machine following the MISP installation guide.
# * The modules are installed using pipenv on a different machine from the one where MISP is running.

if [ -d "/var/www/MISP" ] && [ -d "/usr/local/src/misp-modules" ]
then
    echo "MISP is installed on the same machine, following the recommanded install script. Using MISP virtualenv."
    PATH_TO_MISP="/var/www/MISP"
    PATH_TO_MISP_MODULES="/usr/local/src/misp-modules"

    pushd ${PATH_TO_MISP_MODULES}
    USER=`stat -c "%U" .`
    sudo -H -u ${USER} git pull
    sudo -H -u ${USER} ${PATH_TO_MISP}/venv/bin/pip install -U -r REQUIREMENTS
    sudo -H -u ${USER} ${PATH_TO_MISP}/venv/bin/pip install -U -e .

    popd
else
    if ! [ -x "$(command -v pipenv)" ]; then
        echo 'Error: pipenv not available, unable to automatically update.' >&2
        exit 1
    fi

    echo "Standalone mode, use pipenv from the current directory."
    git pull
    pipenv install
fi


