## How to install and start MISP modules (in a Python virtualenv)?

~~~~bash
SUDO_WWW="sudo -u www-data"

sudo apt-get install -y \
  git \
  libpq5 \
  libjpeg-dev \
  tesseract-ocr \
  libpoppler-cpp-dev \
  imagemagick virtualenv \
  libopencv-dev \
  zbar-tools \
  libzbar0 \
  libzbar-dev \
  libfuzzy-dev

# BEGIN with virtualenv:   
$SUDO_WWW virtualenv -p python3 /var/www/MISP/venv
# END with virtualenv

cd /usr/local/src/
# Ideally you add your user to the staff group and make /usr/local/src group writeable, below follows an example with user misp
sudo adduser misp staff
sudo chmod 2775 /usr/local/src
sudo chown root:staff /usr/local/src
git clone https://github.com/MISP/misp-modules.git
git clone git://github.com/stricaud/faup.git faup
git clone git://github.com/stricaud/gtcaca.git gtcaca

# Install gtcaca/faup
cd gtcaca
mkdir -p build
cd build
cmake .. && make
sudo make install
cd ../../faup
mkdir -p build
cd build
cmake .. && make
sudo make install
sudo ldconfig

cd ../../misp-modules

# BEGIN with virtualenv: 
$SUDO_WWW  /var/www/MISP/venv/bin/pip install -I -r REQUIREMENTS
$SUDO_WWW  /var/www/MISP/venv/bin/pip install .
# END with virtualenv

# BEGIN without virtualenv: 
sudo pip install -I -r REQUIREMENTS
sudo pip install .
# END without virtualenv

# Start misp-modules as a service
sudo cp etc/systemd/system/misp-modules.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now misp-modules
/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s & #to start the modules
~~~~

## How to install and start MISP modules on RHEL-based distributions ?

As of this writing, the official RHEL repositories only contain Ruby 2.0.0 and Ruby 2.1 or higher is required. As such, this guide installs Ruby 2.2 from the SCL repository.

~~~~bash
SUDO_WWW="sudo -u apache"
sudo yum install \
  rh-ruby22 \
  openjpeg-devel \
  rubygem-rouge \
  rubygem-asciidoctor \
  zbar-devel \
  opencv-devel \
  gcc-c++ \
  pkgconfig \
  poppler-cpp-devel \
  python-devel \
  redhat-rpm-config
cd /usr/local/src/
sudo git clone https://github.com/MISP/misp-modules.git
cd misp-modules
$SUDO_WWW /usr/bin/scl enable rh-python36 "virtualenv -p python3 /var/www/MISP/venv"
$SUDO_WWW /var/www/MISP/venv/bin/pip install -U -I -r REQUIREMENTS
$SUDO_WWW /var/www/MISP/venv/bin/pip install -U .
~~~~

Create the service file /etc/systemd/system/misp-modules.service :

~~~~bash
echo "[Unit]
Description=MISP's modules
After=misp-workers.service

[Service]
Type=simple
User=apache
Group=apache
ExecStart=/usr/bin/scl enable rh-python36 rh-ruby22  '/var/www/MISP/venv/bin/misp-modules –l 127.0.0.1 –s'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/misp-modules.service
~~~~

The After=misp-workers.service must be changed or removed if you have not created a misp-workers service. Then, enable the misp-modules service and start it:

~~~~bash
systemctl daemon-reload
systemctl enable --now misp-modules
~~~~

## How to use an MISP modules Docker container

### Docker build

~~~~bash
docker build -t misp-modules \
    --build-arg BUILD_DATE=$(date -u +"%Y-%m-%d") \
  docker/
~~~~

### Docker run

~~~~bash
# Start Redis
docker run --rm -d --name=misp-redis redis:alpine
# Start MISP-modules
docker run \
    --rm -d --name=misp-modules \
    -e REDIS_BACKEND=misp-redis \
    -e REDIS_PORT="6379" \
    -e REDIS_PW="" \
    -e REDIS_DATABASE="245" \
    -e MISP_MODULES_DEBUG="false" \
    dcso/misp-dockerized-misp-modules
~~~~

### Docker-compose

~~~~yml
services:
  misp-modules:
    # https://hub.docker.com/r/dcso/misp-dockerized-misp-modules
    image: dcso/misp-dockerized-misp-modules:3
    
    # Local image:
    #image: misp-modules
    #build:
    #  context: docker/
    
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
