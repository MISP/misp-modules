# MISP-module website

Use all modules with a dedicate website without any MISP

![home](https://github.com/MISP/misp-modules/blob/main/website/doc/home_misp_module.png?raw=true)

![query](https://github.com/MISP/misp-modules/blob/main/website/doc/query_misp_module.png?raw=true)

## Installation

**It is strongly recommended to use a virtual environment**

If you want to know more about virtual environments, [python has you covered](https://docs.python.org/3/tutorial/venv.html)

```bash
sudo apt-get install screen -y
pip install -r requirements.txt
git submodule init && git submodule update   ## Initialize misp-objects submodule
python3 app.py -i                            ## Initialize db
```

## Config

Edit `config.py` 

- `SECRET_KEY`: Secret key for the app

- `FLASK_URL` : url for the instance

- `FLASK_PORT`: port for the instance

- `MISP_MODULE`: url and port where misp-module is running

- `ADMIN_USER`: If True, config page will not be accessible

- `ADMIN_PASSWORD`: Password for Admin user if `ADMIN_USER` is True



Rename `config.cfg.sample` to `config.cfg` then edit it:

- `ADMIN_USER`: If True, config page will not be accessible

- `ADMIN_PASSWORD`: Password for Admin user if `ADMIN_USER` is True

## Launch

```bash
./launch.sh -l
```

## Admin user

If admin user is active, type `/login` in url to access a login page and type the password wrote in `config.py` in `ADMIN_PASSOWRD`.
