## How to install and start MISP modules in a Python virtualenv?

~~~~bash
sudo apt-get install python3-dev python3-pip libpq5 libjpeg-dev tesseract-ocr imagemagick
sudo -u www-data virtualenv -p python3 /var/www/MISP/venv
cd /usr/local/src/
sudo git clone https://github.com/MISP/misp-modules.git
cd misp-modules
sudo -u www-data /var/www/MISP/venv/bin/pip install -I -r REQUIREMENTS
sudo -u www-data /var/www/MISP/venv/bin/pip install .
sudo apt install ruby-pygments.rb -y
sudo gem install asciidoctor-pdf --pre
sudo sed -i -e '$i \sudo -u www-data /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local
/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s & #to start the modules
~~~~

## How to install and start MISP modules?

~~~~bash
sudo apt-get install python3-dev python3-pip libpq5 libjpeg-dev tesseract-ocr imagemagick
cd /usr/local/src/
sudo git clone https://github.com/MISP/misp-modules.git
cd misp-modules
sudo pip3 install -I -r REQUIREMENTS
sudo pip3 install -I .
sudo apt install ruby-pygments.rb -y
sudo gem install asciidoctor-pdf --pre
sudo sed -i -e '$i \sudo -u www-data /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local
/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s & #to start the modules
~~~~

## How to use an MISP modules Docker container

### Docker run

~~~~bash
# Start Redis
docker run --rm -d --container_name misp-redis redis:alpine
docker run \
    --rm -d --container_name misp-modules \
    -e REDIS_BACKEND=misp-redis \
    -e REDIS_PORT="6379" \
    -e REDIS_PW="" \
    -e REDIS_DATABASE="245" \
    -e MISP_MODULES_DEBUG: "false" \
    dcso/misp-dockerized-redis
~~~~

### Docker-compose

~~~~yml
services:
  misp-modules:
    # https://hub.docker.com/r/dcso/misp-dockerized-misp-modules
    image: dcso/misp-dockerized-misp-modules:3
    environment:
      # Redis
      REDIS_BACKEND: misp-redis
      REDIS_PORT: "6379"
      REDIS_DATABASE: "245"
      # System PROXY (OPTIONAL)
      http_proxy: 
      https_proxy: 
      no_proxy: 0.0.0.0
      # Timezone (OPTIONAL)
      TZ: Europe/Berlin
      # MISP-Modules (OPTIONAL)
      MISP_MODULES_DEBUG: "false"
      # Logging options (OPTIONAL)
      LOG_SYSLOG_ENABLED: "no"
  misp-redis:
    # https://hub.docker.com/_/redis or alternative https://hub.docker.com/r/dcso/misp-dockerized-redis/
    image: redis:alpine
~~~~

## Install misp-module on an offline instance.
First, you need to grab all necessary packages for example like this :

Use pip wheel to create an archive
~~~
mkdir misp-modules-offline
pip3 wheel -r REQUIREMENTS shodan --wheel-dir=./misp-modules-offline
tar -cjvf misp-module-bundeled.tar.bz2 ./misp-modules-offline/*
~~~
On offline machine :
~~~
mkdir misp-modules-bundle
tar xvf misp-module-bundeled.tar.bz2 -C misp-modules-bundle
cd misp-modules-bundle
ls -1|while read line; do sudo pip3 install --force-reinstall --ignore-installed --upgrade --no-index --no-deps ${line};done
~~~
Next you can follow standard install procedure.