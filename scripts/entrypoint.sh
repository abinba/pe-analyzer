#!/bin/bash

alembic upgrade head
/opt/pysetup/.venv/bin/python -m pe_analyzer.__main__ 1000
