#!/bin/bash
isscripted=`screen -ls | egrep '[0-9]+.misp_mod' | cut -d. -f1`

function killscript {
    if  [ $isscripted ]; then
		screen -X -S misp_mod quit
    fi
}

function launch {
    export FLASKENV="development"
    killscript
    screen -dmS "misp_mod"
    screen -S "misp_mod" -X screen -t "misp_modules_server" bash -c "misp-modules -l 127.0.0.1; read x"
    sleep 2
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
                                        ;;                                
        -ks | --killscript )        killscript;
    esac
    shift
else
	launch
fi
