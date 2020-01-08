# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](unreleased)

- no new features in development at this time

## [0.3.3](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.3.2...0.3.3) (Jan 08, 2020)

BUG FIXES:

- filter out user search results not containing the dn attribute
- only verify local user exists if create_user_home_dir is True

## [0.3.2](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.3.1...0.3.2) (Mar 20, 2019)

BUG FIXES:

- update group_search_filter documentation in README
- modify test_auth function to work with OTP passwords
- update rebind error statement

## [0.3.1](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.3.0...0.3.1) (Feb 5, 2019)

BUG FIXES:

- update documentation to reflect correct user_search_filter for active directory integration
- allow server_hosts to use non-standard ldap ports

## [0.3.0](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.2.0...0.3.0) (Nov 1, 2018)

FEATURES:

- set 'allowed_groups' to None to short-circuit user group membership check. For use in LDAP solutions that do not allow user group memberships to be easily queried.

BUG FIXES:

- add try/catch to pwd.getpwnam call
- fix Readme parameter typos
- fix Changelog linking

## [0.2.0](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.1.0...0.2.0) (May 31, 2018)

FEATURES:

- rename keyword substituion keys `user_logon` and `group_dn` to `username` and `group` to align with other ldap authenticator projects for easier transition.

BUG FIXES:

- fix nesting method to return proper results
- fix bug that permitted user login after being removed from allowed_groups memberships
- update code to adheare to pylint standards

## [0.1.0](https://github.com/hansohn/jupyterhub-ldap-authenticator/compare/0.1.0...0.1.0) (May 04, 2018)

FEATURES:

- initial commit
