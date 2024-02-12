#!/bin/bash


function launch {
    export FLASKENV="development"
    python3 app.py -m
    python3 app.py
}

function test {
    export FLASKENV="testing"
    pytest
}

function init_db {
	python3 app.py -i
}

function reload_db {
	python3 app.py -r
}


if [ "$1" ]; then
    case $1 in
        -l | --launch )             launch;
                                        ;;
		-i | --init_db )            init_db;
                                        ;;
		-r | --reload_db )          reload_db;
                                        ;;
        -t | --test )               test;
    esac
    shift
else
	launch
fi
