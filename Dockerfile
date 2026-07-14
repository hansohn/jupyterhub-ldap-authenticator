ARG PYTHON_VERSION=3.14

# python
FROM python:${PYTHON_VERSION} AS main
ARG PYTHON_VERSION
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y \
      bash \
      gpg-agent \
      jq \
      libnss3-tools \
      software-properties-common \
      tar \
      vim \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY dist/. .
RUN /bin/bash -c 'python${PYTHON_VERSION%%.*} -m pip install --no-cache-dir /app/jupyterhub?ldap?authenticator-*.tar.gz'
