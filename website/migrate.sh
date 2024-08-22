#!/bin/bash

source env/bin/activate
export FLASKENV=development

function migrate {
    flask db migrate
}

function upgrade {
    flask db upgrade
}

function downgrade {
    flask db downgrade
}


if [ "$1" ]; then
    case $1 in
        -m | --migrate )            migrate;
                                        ;;
		-u | --upgrade )            upgrade;
                                        ;;
		-d | --downgrade )          downgrade;
    esac
    shift
else
	echo "need -m or -u or -d"
fi
