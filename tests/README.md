
## requirements

```bash
python3 -m venv testvenv
source testvenv/bin/activate
pip install -r tests/requirements-dev.txt
# or
pip install Jinja2 openpyxl pandas pwinput keyring requests rich pytest mypy pylint pytest_httpserver
```

## pytest

```bash
python -m pytest -v
python -m pytest -v -W ignore::DeprecationWarning
```

## mypy

```bash
mypy --strict --ignore-missing-imports .
```
