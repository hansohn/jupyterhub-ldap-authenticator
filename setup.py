#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from shutil import rmtree
from setuptools import find_packages, setup

# Package meta-data.
NAME = 'jupyterhub-ldap-authenticator'
VERSION = '0.1.0'
DESCRIPTION = 'LDAP Authenticator for JupyterHub'
AUTHOR = 'Ryan Hansohn'
EMAIL = 'info@imnorobot.com'
URL = 'https://github.com/hansohn/jupyterhub-ldap-authenticator'
REQUIRES_PYTHON = '~=3.4'
REQUIRED = ['ldap3', 'jupyterhub', 'traitlets']
KEYWORDS = ['ldap', 'authenticator', 'authentication', 'jupyterhub', 'jupyter']

# ------------------------------------------------------------------------------

about = {}
here = os.path.abspath(os.path.dirname(__file__))
pjoin = os.path.join

# readme
with open(pjoin(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# version
if not VERSION:
    with open(pjoin(here, NAME, '__version__.py')) as f:
        exec(f.read(), about)
else:
    about['__version__'] = VERSION

# setup args
setup_args = dict(
    name=NAME,
    version=about['__version__'],
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(exclude=('tests',)),
    install_requires=REQUIRED,
    include_package_data=True,
    license='MIT',
    keywords=KEYWORDS,
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ]
)

# setuptools requirements
if 'setuptools' in sys.modules:
    setup_args['install_requires'] = install_requires = []
    with open('requirements.txt') as f:
        for line in f.readlines():
            req = line.strip()
            if not req or req.startswith(('-e', '#')):
                continue
            install_requires.append(req)

def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()
