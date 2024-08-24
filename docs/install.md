## Install from pip

It is strongly recommended to use a virtual environment (see here for instructions https://docs.python.org/3/tutorial/venv.html).

Once the virtual environment is loaded just use the command:

~~~~bash
pip install misp-modules
~~~~

Note that the dependencies will require a number of system packages installed. On Ubuntu these packages are `libpoppler-cpp-dev`, `libzbar0`, and `tesseract-ocr`. For an updated list, check the github action used to test the build inside `.github/workflows`.

Because PyPI does not support git for direct dependencies, the following packages will not be installed by default `otdreader`, `google-search-api`, `trustar`, `pydnstrails`, `pyonyphe`. You can either install them manually or let the modules depending on them gracefully fail.

~~~~bash
pip install \
	git+https://github.com/cartertemm/ODTReader.git \
	git+https://github.com/abenassi/Google-Search-API \
	git+https://github.com/SteveClement/trustar-python.git \
	git+https://github.com/sebdraven/pydnstrails.git \
	git+https://github.com/sebdraven/pyonyphe.git
~~~~

You can now run `misp-modules` by invoking it (you might need to reload the virtual environment to update the search path used for executables).

~~~~bash
misp-modules
~~~~


## Install from cloned repository

In this case the only requirement is to install `poetry`. Normally you just need to run `pip install poetry`, but see here for more alternatives https://python-poetry.org/docs/#installation.

Once `poetry` is installed, you can clone the repository and install `misp-modules` as follows:

~~~~bash
git clone https://github.com/MISP/misp-modules.git && cd misp-modules
git submodule update --init
poetry install --with unstable
~~~~

The switch `--with unstable` will also install dependencies available only on `git` repositories (which are manually installed when using pip).

Note that the dependencies will require a number of system packages installed. On Ubuntu these packages are `libpoppler-cpp-dev`, `libzbar0`, and `tesseract-ocr`. For an updated list, check the github action used to test the build inside `.github/workflows`.


## Install the systemd unit

To run `misp-modules` as a service on a distribution based on systemd, you need to create the unit as follows and store it in a file `/etc/systemd/system/misp-modules.service`:

~~~~bash
[Unit]
Description=MISP modules

[Service]
Type=simple
User=apache
Group=apache
ExecStart='/path/to/venv/bin/misp-modules -l 127.0.0.1 -s'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
~~~~

Then, enable the misp-modules service and start it:
~~~~bash
systemctl daemon-reload
systemctl enable --now misp-modules
~~~~


## Run the tests

To run tests you need to install misp-modules from the cloned repository, run the server, and then run the tests. You can do all these step with `poetry`.

~~~~bash
poetry install --with unstable
poetry run misp-modules
~~~~

And in another terminal:

~~~~bash
poetry run pytest
~~~~


## Build the documentation

To build the documentation you can use the provided `Makefile`.
Inside you will find three targets:

- `generate_docs`: install the depdendency and generate the documentation.

- `generate_docs`: build the documentation using `mkdocs`.

- `deploy`: deploy the documentation using `mkdocs gh-deploy`.

- `test-docs`: run a local server exposing the newly built documentation.

Note: you can either run the targets using `poetry` (default), or using the Docker image `squidfunk/mkdocs-material` by setting the environment variable `USE_DOCKER=true`.


## Run MISP modules

If you installed it using pip, you just need to execute the command `misp-modules` (source the virtual environment a second time to update the search paths). If you installed it from the cloned repository, just use poetry, i.e., `poetry run misp-modules`.


## Run MISP modules in Docker

You can find an up-to-date container image and related documentation at the following repository: https://github.com/MISP/misp-docker .


## Install misp-module on an offline instance

### If `misp-modules` is available on PyPI

Once `misp-modules` is available on PyPI, you can just download all the necessary packages:

~~~~bash
mkdir wheels
pip wheel misp-modules --no-cache-dir -w ./wheels
~~~~

Move the `wheels` directory to the target system, and install them there:

~~~~bash
pip install --no-cache-dir --use-deprecated=legacy-resolver /wheels/*.whl
~~~~

Once again, using a virtual environment is recommended.

### If `misp-modules` is not available on PyPI

You have two choices, the first approach uses `poetry export` to export the entire virtual environment so you can copy and run it on the target system; the second one uses `poetry bundle` to export a `requirements.txt` file.

#### Using `poetry bundle`

This is quite straightforward but it assumes your target system is relatively similar (same distribution, architecture, libaries).

~~~~bash
poetry install --with unstable
poetry self add poetry-plugin-bundle
poetry bundle venv /destination/path/
~~~~

#### Using `poetry export`

This is a bit more convoluted and it is similar to how you would install `misp-modules` on an offline instance.

Just follow those instructions but replace the package `misp-modules` with `-r requirements.txt`.

Before doing so you need to generate the `requirements.txt` file. Due to the fact we are still supporting Python 3.8 and that Poetry still has some limitations (soon to be resolved) you need to need to replace the line `python = ">=3.8.*,<3.13"` inside `pyproject.toml` with your exact version (just run `python --version`).

The following `sed` command does everything for you.

~~~~bash
sed -i "s/^python = .*/python = \"$(python -c 'import platform; print(platform.python_version())')\"/" pyproject.toml
~~~~

Then, run the following commands to generate your very own `requirements.txt`.

~~~~bash
poetry lock
poetry self add poetry-plugin-export
poetry export --with unstable --without-hashes -f requirements.txt -o requirements.txt
~~~~

Note that `misp-modules` will not be part of the `requirements.txt` file and you will need to create the wheel yourself:

~~~~bash
poetry build --output ./wheels
~~~~

