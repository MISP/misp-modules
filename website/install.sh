#!/bin/bash

sudo apt-get update -y
sudo apt-get install virtualenv -y

virtualenv env
source env/bin/activate

pip install -r requirements.txt

git submodule init && git submodule update

python app.py -i
deactivate
