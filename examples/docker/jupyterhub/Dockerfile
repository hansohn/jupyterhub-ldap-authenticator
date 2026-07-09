# JupyterHub image with the local jupyterhub-ldap-authenticator installed.
# Build context is the repository root (see docker-compose.yml).
# The official base image bundles jupyterhub + configurable-http-proxy (node).
FROM jupyterhub/jupyterhub:5

# setuptools-scm needs a version; supplied here so the source install works
# without the .git directory in the build context.
ARG PLUGIN_VERSION=1.0.0.dev0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${PLUGIN_VERSION}

RUN pip install --no-cache-dir jupyterlab notebook

# install the plugin from local source (only the files needed to build)
COPY pyproject.toml README.md /src/
COPY ldapauthenticator /src/ldapauthenticator
RUN pip install --no-cache-dir /src

COPY examples/docker/jupyterhub/jupyterhub_config.py /srv/jupyterhub/jupyterhub_config.py
WORKDIR /srv/jupyterhub
EXPOSE 8000
CMD ["jupyterhub", "-f", "/srv/jupyterhub/jupyterhub_config.py"]
