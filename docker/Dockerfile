FROM python:3.7-buster AS build

ENV DEBIAN_FRONTEND noninteractive
ENV WORKDIR="/usr/local/src/misp_modules"
ENV VENV_DIR="/misp_modules"

# Install Packages for build
RUN set -eu \
        ;mkdir -p ${WORKDIR} ${VENV_DIR} \
        ;apt-get update  \
        ;apt-get install -y \
                git \
                libpq5 \
                libjpeg-dev \
                tesseract-ocr \
                libpoppler-cpp-dev \
                imagemagick \
                virtualenv \
                libopencv-dev \
                zbar-tools \
                libzbar0 \
                libzbar-dev \
                libfuzzy-dev \
        ;apt-get -y autoremove \
        ;apt-get -y clean \
        ;rm -rf /var/lib/apt/lists/* \
        ;

# Create MISP Modules
RUN set -eu \
        ;git clone https://github.com/MISP/misp-modules.git ${WORKDIR} \
        ;virtualenv -p python3 ${VENV_DIR}/venv \
        ;cd ${WORKDIR} \
        ;${VENV_DIR}/venv/bin/pip3 install -I -r REQUIREMENTS --no-cache-dir \
        ;${VENV_DIR}/venv/bin/pip3 install . --no-cache-dir \
        ;

#########################################
# Start Final Docker Image
#
FROM python:3.7-slim-buster AS final

ENV DEBIAN_FRONTEND noninteractive 
ENV VENV_DIR="/misp_modules"

# Copy all builded files from build stage
COPY --from=build ${VENV_DIR} ${VENV_DIR}

# Install Packages to run it
RUN set -eu \
        ;apt-get update  \
        ;apt-get install -y \
                curl \
                libpq5 \
                # libjpeg-dev \
                tesseract-ocr \
                libpoppler-cpp-dev \
                imagemagick \
                # virtualenv \
                # libopencv-dev \
                zbar-tools \
                libzbar0 \
                # libzbar-dev \
                # libfuzzy-dev \
        ;apt-get -y autoremove \
        ;apt-get -y clean \
        ;rm -rf /var/lib/apt/lists/* \
        ;chown -R nobody ${VENV_DIR} \
        ;

# Entrypoint
        COPY files/entrypoint.sh /entrypoint.sh
        ENTRYPOINT [ "/entrypoint.sh" ]

# Add Healthcheck Config
        COPY files/healthcheck.sh /healthcheck.sh
        HEALTHCHECK --interval=1m --timeout=45s --retries=3 CMD ["/healthcheck.sh"]

# Change Workdir
        WORKDIR ${VENV_DIR}

# Change from root to www-data
        USER nobody

# Expose Port
        EXPOSE 6666

# Shortterm ARG Variables:
        ARG VENDOR="MISP"
        ARG COMPONENT="misp-modules"
        ARG BUILD_DATE
        ARG GIT_REPO="https://github.com/MISP/misp-modules"
        ARG VCS_REF
        ARG RELEASE_DATE
        ARG NAME="MISP-dockerized-misp-modules"
        ARG DESCRIPTION="This docker container contains MISP modules in an Debian Container."
        ARG DOCUMENTATION="https://misp.github.io/misp-modules/"
        ARG AUTHOR="MISP"
        ARG LICENSE="BSD-3-Clause"

# Longterm Environment Variables
ENV \
        BUILD_DATE=${BUILD_DATE} \
        NAME=${NAME} \
        PATH=$PATH:${VENV_DIR}/venv/bin

# Labels
LABEL org.label-schema.build-date="${BUILD_DATE}" \
        org.label-schema.name="${NAME}" \
        org.label-schema.description="${DESCRIPTION}" \
        org.label-schema.vcs-ref="${VCS_REF}" \
        org.label-schema.vcs-url="${GIT_REPO}" \
        org.label-schema.url="${GIT_REPO}" \
        org.label-schema.vendor="${VENDOR}" \
        org.label-schema.version="${VERSION}" \
        org.label-schema.usage="${DOCUMENTATION}" \
        org.label-schema.schema-version="1.0.0-rc1"

LABEL   org.opencontainers.image.created="${BUILD_DATE}" \
        org.opencontainers.image.url="${GIT_REPO}" \
        org.opencontainers.image.source="${GIT_REPO}" \
        org.opencontainers.image.version="${VERSION}" \
        org.opencontainers.image.revision="${VCS_REF}" \
        org.opencontainers.image.vendor="${VENDOR}" \
        org.opencontainers.image.title="${NAME}" \
        org.opencontainers.image.description="${DESCRIPTION}" \
        org.opencontainers.image.documentation="${DOCUMENTATION}" \
        org.opencontainers.image.authors="${AUTHOR}" \
        org.opencontainers.image.licenses="${LICENSE}"

