#!/bin/bash

sudo apt-get update -y
sudo apt-get install virtualenv -y

virtualenv env
source env/bin/activate

pip install -r requirements.txt

python app.py -i
deactivate
