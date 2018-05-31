# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](unreleased)

- no new features in development at this time

## [0.2.0](https://github.com/audio4ears/jupyterhub-ldap-authenticator/compare/0.1.0...0.2.0) (May 31, 2018)

FEATURES:

- rename keyword substituion keys `user_logon` and `group_dn` to `username` and `group` to align with other ldap authenticator projects for easier transition.

BUG FIXES:

- fix nesting method to return proper results
- fix bug that permitted user login after being removed from allowed_groups memberships
- update code to adheare to pylint standards

## [0.1.0](https://github.com/audio4ears/jupyterhub-ldap-authenticator/compare/0.1.0...0.1.0) (May 04, 2018)

FEATURES:

- initial commit
