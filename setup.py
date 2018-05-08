from setuptools import setup

setup_args= dict(
    name = 'jupyterhub-ldap-authenticator',
    version = '0.1.0',
    description = 'LDAP Authenticator for JupyterHub',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3'
    ],
    keywords = ['Interactive', 'Interpreter', 'Shell', 'Web'],
    url = 'https://github.com/hansohn/jupyterhub-ldap-authenticator',
    author ='Ryan Hansohn',
    author_email = 'info@imnorobot.com',
    license = 'MIT',
    packages = ['ldapauthenticator'],
    install_requires= [ 
        'ldap3',
        'jupyterhub',
        'traitlets'
    ]
)

#------------------------------------------------------------------------------
# setup
#------------------------------------------------------------------------------

def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()
