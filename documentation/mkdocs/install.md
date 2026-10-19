## Install via uv

If you don't have a recent version of Python or are missing some dependencies, `uv` can be used to install the required Python version.

- `curl -LsSf https://astral.sh/uv/install.sh | sh`
- `uv venv --python=3.12 .venv`
- `source .venv/bin/activate`
- `git clone https://github.com/MISP/misp-modules.git && cd misp-modules`
- `uv pip install .[all]`
- `misp-modules`

## Install from pip

It is strongly recommended to use a virtual environment 
(see here for instructions https://docs.python.org/3/tutorial/venv.html).

Once the virtual environment is loaded just use the following command for a minimal installation that only 
allows MISP workflows (and a few other modules) to work:

~~~~bash
pip install misp-modules
~~~~

The following command will install a list of modules that don’t require system packages. Most of them are included.

```bash
pip install misp-modules[minimal]
```

If you want to install *all* modules you might need a number of system packages installed. 
On Ubuntu these packages are `libpoppler-cpp-dev`, `libzbar0`, and `tesseract-ocr`. 

For an updated list, check the GitHub action used to test the build inside `.github/workflows`.
Once you installed those dependencies you can now install the optional `all` extra:

~~~~bash
pip install misp-modules[all]
~~~~

You can now run `misp-modules` by invoking it (you might need to reload the virtual environment to update the 
search path used for executables).

~~~~bash
misp-modules
~~~~

### Debugging outbound HTTP requests

Use `-d` / `--debug` for the usual server debug logs. To also trace HTTP requests
from modules to their services, enable extended debugging:

```bash
misp-modules --debug-extended
```

This option implies `--debug` and writes untruncated request methods, URLs, headers,
bodies, response status codes, headers, and bodies to the server logs on stderr.
Each exchange has a unique ID and the module name to help follow concurrent queries.
Custom modules starting their own worker threads must propagate the current Python
context to those workers to retain module attribution. WhoisFreaks does this for its
parallel domain and IP lookups.
It covers HTTP and HTTPS calls made through `requests` and service SDKs using its
standard HTTP adapter, including redirects. SDKs using other HTTP clients or custom
adapters that replace `HTTPAdapter.send` are not covered.

Bodies are logged using their Python representation to preserve binary data.
Streamed uploads and responses are logged in chunks as the module sends or reads
them, without buffering or consuming them in advance. Unread response data is not
logged. Response bodies are decompressed when the client normally decompresses them.

**These logs include credentials, API keys, cookies, and potentially sensitive
payloads without redaction.** Enable this option only while troubleshooting, protect
the logs, and disable it afterwards. Normal `--debug` does not enable HTTP tracing.

As a new feature, you can now run custom MISP modules installed on your system by using the `-c` option.

~~~~bash
misp-modules -c /path/to/your/module/root/
~~~~

Note that your module must be sited inside a directory identifying its type 
(e.g., `expansion`, `import_mod`, `export_mod`, `action_mod`).

For example your module is `custom_module.py` and its type is `expansion` the module's absolute path should be
`/path/to/your/module/root/expansion/custom_module.py` and the option to pass to `misp-modules` 
would be `-c /path/to/your/module/root/`.


## Install from cloned repository

In this case the only requirement is to install `poetry`.

Normally you just need to run `pip install poetry`, but see here for more alternatives 
https://python-poetry.org/docs/#installation.

Once `poetry` is installed, you can clone the repository and install `misp-modules` as follows:

~~~~bash
git clone https://github.com/MISP/misp-modules.git && cd misp-modules
poetry install
~~~~

If you want to install *all* modules, just run `poetry install -E all` instead.

Note that the dependencies will require a number of system packages installed.
On Ubuntu these packages are `libpoppler-cpp-dev`, `libzbar0`, and `tesseract-ocr`.

For an updated list, check the GitHub action used to test the build inside `.github/workflows`.

## Install the systemd unit

To run `misp-modules` as a service on a distribution based on systemd, you need to create the unit as follows 
and store it in a file `/etc/systemd/system/misp-modules.service`:

~~~~bash
[Unit]
Description=MISP modules

[Service]
Type=simple
User=apache
Group=apache
ExecStart=/path/to/venv/bin/misp-modules -l 127.0.0.1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
~~~~

Then, enable the `misp-modules` service and start it:
~~~~bash
systemctl daemon-reload
systemctl enable --now misp-modules
~~~~


## Run the tests

To run tests you need to install `misp-modules` from the cloned repository, run the server, and then run the tests. 
You can do all these step with `poetry`.

~~~~bash
poetry install --with test -E all
poetry run misp-modules
~~~~

And in another terminal:

~~~~bash
poetry run pytest
~~~~

## Develop

If you plan to open a pull request you might want to make sure that `black`, `isort`, and `flake8` are not 
raising any errors. First of all, install the test dependencies as detailed in the previous section.

Once you have done that you can run each tool using poetry (`poetry run black` for example), 
but you can also install `pre-commit` to run those tools automatically before each commit just on the files you have 
edited.

~~~~bash
pre-commit install
~~~~

## Build the documentation

To build the documentation you can use the provided `Makefile`.
Inside you will find three targets:

- `generate_docs`: install the dependency and generate the documentation.

- `generate_docs`: build the documentation using `mkdocs`.

- `deploy`: deploy the documentation using `mkdocs gh-deploy`.

- `test-docs`: run a local server exposing the newly built documentation.

Note: you can either run the targets using `poetry` (default), or using the Docker image `squidfunk/mkdocs-material` 
by setting the environment variable `USE_DOCKER=true`.

## Run MISP modules

If you installed it using pip, you just need to execute the command `misp-modules` 
(source the virtual environment a second time to update the search paths).

If you installed it from the cloned repository, just use poetry, i.e., `poetry run misp-modules`.

### Module statistics

Retrieve a live snapshot with:

```bash
curl http://localhost:6666/statistics
```

The JSON contains `started_at` (UTC), `uptime_seconds`, aggregate `totals`, and
`modules`, keyed by module name. Every loaded module, including custom modules,
appears with its `type`, even before its first query. Each entry and the totals contain:

| Field | Meaning |
| --- | --- |
| `queries`, `completed`, `in_flight` | Dispatched queries, finished queries, and queries still awaiting a response. |
| `successes`, `errors` | Successful and failed responses. `completed = successes + errors`. |
| `module_errors` | Responses with a nonempty top-level `error` or `errors` field, including partial results with errors. |
| `exceptions` | Unhandled module or response serialization failures. |
| `timeouts` | Queries whose response deadline expired. `errors = module_errors + exceptions + timeouts`. |
| `success_rate`, `error_rate` | Fractions of completed queries (0–1), or `null` before any complete. |
| `request_bytes`, `response_bytes` | Total JSON body sizes, including server-generated error responses; HTTP headers are excluded. |
| `last_query_at`, `last_completed_at` | UTC timestamps, or `null` before the corresponding event. |
| `response_time_seconds` | `count`, `total`, `min`, `max`, `average`, `last`, and cumulative `buckets`. |

Response times use a monotonic clock, include executor queueing, execution and
serialization, and end when the response is prepared or the timeout fires. They
exclude network transfer time. Timing count equals `completed`; min/max/average/last
are `null` before any completion. Each histogram bucket counts durations less than
or equal to its upper bound in seconds: `0.01`, `0.05`, `0.1`, `0.5`, `1`, `5`, `10`,
`30`, `60`, `300`, and `+Inf` (all completed queries).

Timeouts count exactly once as errors; a worker may continue executing afterwards.
`in_flight` measures queries awaiting a response, not active worker threads.
Malformed requests, invalid timeout values, unknown module names and calls to other
endpoints are excluded. Existing `/query` response bodies and status codes are unchanged.

Statistics are process-local, held in memory and reset when the server restarts.
Multiple server instances have separate counters. Storage is bounded by the number
of queried modules and histogram buckets; request bodies, results, credentials and
error messages are never retained by the statistics collector.

## Run MISP modules in Docker

You can find an up-to-date container image and related documentation at the following repository: 
https://github.com/MISP/misp-docker .

## Install misp-module on an offline instance

### Using the PyPI index

Once `misp-modules` is available on PyPI, you can just download all the necessary packages:

~~~~bash
mkdir wheels
pip wheel misp-modules --no-cache-dir -w ./wheels
~~~~

Move the `wheels` directory to the target system, and install them there:

~~~~bash
pip install --no-cache-dir /wheels/*.whl
~~~~

Once again, using a virtual environment is recommended.

### Using a local copy

You have two choices, the first approach uses `poetry bundle` to export the entire virtual environment so you can copy 
and run it on the target system; the second one uses `poetry export` to export a `requirements.txt` file.

#### Using `poetry bundle`

This is quite straightforward, but it assumes your target system is relatively similar 
(same distribution, architecture, libraries).

~~~~bash
poetry install
poetry self add poetry-plugin-bundle
poetry bundle venv /destination/path/
~~~~

Remember you can add the `-E all` switch to the `poetry install` command if you want to install all dependencies.

#### Using `poetry export`

This is a bit more convoluted, and it is similar to how you would install `misp-modules` on an online instance.

Run the following commands to generate your very own `requirements.txt`.

~~~~bash
poetry lock
poetry self add poetry-plugin-export
poetry export --without-hashes -f requirements.txt -o requirements.txt
~~~~

Remember you can add the `-E all` switch to the `poetry export` command if you want to install all dependencies.

Now create the wheels of all the dependencies:

~~~~bash
pip wheel -r requirements.txt --no-cache-dir -w ./wheels
~~~~

Note that `misp-modules` will not be part of the `requirements.txt` file, and you will need to create the wheel yourself:

~~~~bash
poetry build --output ./wheels
~~~~

Now you can move the wheels to your offline instance, and install them using the following command:

~~~~bash
pip install --no-cache-dir ./wheels/*.whl
~~~~
