FROM apache/spark:3.5.1 as python-base

USER root

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        libpq-dev \
        zip \
        software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        python3.11 \
        python3.11-venv \
        python3.11-dev \
        python3-pip

# Ensure 'python' command points to 'python3.11'
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1

##########################################################################################

# builder-base is used to build dependencies
FROM python-base as builder-base

# Install Poetry - respects $POETRY_VERSION & $POETRY_HOME
ENV POETRY_VERSION=1.8.3
RUN curl -sSL https://install.python-poetry.org | python3 -

# We copy our Python requirements here to cache them
# and install only runtime deps using poetry
WORKDIR $PYSETUP_PATH
COPY ./poetry.lock ./pyproject.toml ./
RUN poetry install --without dev --no-root

# Copy the pe_analyzer directory and zip it
COPY ./pe_analyzer /pe_analyzer
COPY ./scripts /scripts
RUN zip -r /pe_analyzer.zip /pe_analyzer

##########################################################################################
FROM python-base as production

COPY --from=builder-base $VENV_PATH $VENV_PATH
COPY --from=builder-base /pe_analyzer.zip /service/pe_analyzer.zip
COPY --from=builder-base /scripts /service/scripts

COPY . /service/
WORKDIR /service

RUN /usr/bin/python3.11 --version

ENTRYPOINT ["bash", "/service/scripts/entrypoint.sh"]
