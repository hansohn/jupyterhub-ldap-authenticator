# MIT License
#
# Copyright (c) 2018 Ryan Hansohn
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
LDAP Authenticator plugin for JupyterHub
"""

import os
import pwd
import re
import subprocess
import sys
import typing

import ldap3
import ldap3.core.exceptions
from jupyterhub.auth import Authenticator
from jupyterhub.orm import User
from jupyterhub.traitlets import Command
from jupyterhub.utils import maybe_future
from traitlets import Any, Bool, Dict, Enum, Int, List, Unicode, Union, default, observe


class LDAPAuthenticator(Authenticator):
    """
    LDAP Authenticator for Jupyterhub
    """

    server_hosts = Union(
        [List(), Unicode()],
        config=True,
        help="""
        List of Names, IPs, or the complete URLs in the scheme://host:port
        format of the server (required).
        """,
    )

    server_port = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The port where the LDAP server is listening. Typically 389, for a
        cleartext connection, and 636 for a secured connection (defaults to None).
        """,
    )

    server_use_ssl = Bool(
        default_value=False,
        config=True,
        help="""
        Deprecated since 1.0. Boolean specifying if the connection is on a
        secure port. Setting `server_use_ssl=True` is equivalent to configuring
        `server_tls_strategy='on_connect'`. Use `server_tls_strategy` instead
        (defaults to False).
        """,
    )

    server_tls_strategy = Enum(
        ["before_bind", "on_connect", "insecure"],
        default_value="before_bind",
        config=True,
        help="""
        Strategy used to establish a SSL/TLS connection to the LDAP server
        (defaults to 'before_bind').

        before_bind: Upgrade the connection to SSL/TLS before binding (sending
            credentials). This is the modern, recommended strategy (STARTTLS).
        on_connect: Establish a SSL/TLS connection directly on connect. This is
            the legacy LDAPS behavior, typically associated with port 636. When
            configured, the default `server_port` becomes 636.
        insecure: Do not use SSL/TLS. Credentials are sent in cleartext; only
            appropriate for trusted networks or testing.
        """,
    )

    server_tls_kwargs = Dict(
        config=True,
        help="""
        Dictionary of keyword arguments passed to the constructor of the ldap3
        package's `Tls` object, influencing encrypted connections to the LDAP
        server. Ignored when `server_tls_strategy='insecure'`. For example::

            c.LDAPAuthenticator.server_tls_kwargs = {
                'ca_certs_file': '/path/to/ca-bundle.pem',
            }

        See https://ldap3.readthedocs.io/en/latest/ssltls.html for details.
        """,
    )

    @observe("server_use_ssl")
    def _server_use_ssl_changed(self, change: dict) -> None:
        if change["new"]:
            self.log.warning(
                "LDAPAuthenticator.server_use_ssl is deprecated since 1.0 in "
                "favor of LDAPAuthenticator.server_tls_strategy. Instead of "
                "configuring server_use_ssl=True, configure "
                "server_tls_strategy='on_connect' from now on."
            )
            self.server_tls_strategy = "on_connect"

    server_connect_timeout = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        Timeout in seconds permitted when establishing an ldap connection before
        raising an exception (defaults to None).
        """,
    )

    server_receive_timeout = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        Timeout in seconds permitted for responses from established ldap
        connections before raising an exception (defaults to None).
        """,
    )

    server_pool_strategy = Unicode(
        default_value="FIRST",
        config=True,
        help="""
        Available Pool HA strategies (defaults to 'FIRST').

        FIRST: Gets the first server in the pool, if 'server_pool_active' is
            set to True gets the first available server.
        ROUND_ROBIN: Each time the connection is open the subsequent server in
            the pool is used. If 'server_pool_active' is set to True unavailable
            servers will be discarded.
        RANDOM: each time the connection is open a random server is chosen in the
            pool. If 'server_pool_active' is set to True unavailable servers
            will be discarded.
        """,
    )

    server_pool_active = Union(
        [Bool(), Int()],
        default_value=True,
        config=True,
        help="""
        If True the ServerPool strategy will check for server availability. Set
        to Integer for maximum number of cycles to try before giving up
        (defaults to True).
        """,
    )

    server_pool_exhaust = Union(
        [Bool(), Int()],
        default_value=False,
        config=True,
        help="""
        If True, any inactive servers will be removed from the pool. If set to
        an Integer, this will be the number of seconds an unreachable server is
        considered offline. When this timeout expires the server is reinserted
        in the pool and checked again for availability (defaults to False).
        """,
    )

    bind_user_dn = Unicode(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The account of the user to log in for simple bind (defaults to None).
        """,
    )

    bind_user_password = Unicode(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The password of the user for simple bind (defaults to None)
        """,
    )

    bind_dn_template = Union(
        [List(), Unicode()],
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        Template(s) from which to construct the full DN used to bind directly to
        the LDAP server as the authenticating user, bypassing the service-account
        search (`bind_user_dn`). '{username}' is replaced with the authenticating
        username. When set, authentication uses the direct-bind strategy instead
        of the search-bind strategy (defaults to None).

        String example::

            uid={username},ou=people,dc=example,dc=org

        List example (each template is tried in order until one binds)::

            [
                'uid={username},ou=people,dc=example,dc=org',
                'uid={username},ou=developers,dc=example,dc=org',
            ]
        """,
    )

    user_search_base = Unicode(
        config=True,
        help="""
        The location in the Directory Information Tree where the user search
        will start.
        """,
    )

    user_search_filter = Unicode(
        config=True,
        help="""
        LDAP search filter to validate that the authenticating user exists
        within the organization. Search filters containing '{username}' will
        have that value substituted with the username of the authenticating user.
        """,
    )

    user_membership_attribute = Unicode(
        default_value="memberOf",
        config=True,
        help="""
        LDAP Attribute used to associate user group membership
        (defaults to 'memberOf').
        """,
    )

    group_search_base = Unicode(
        config=True,
        help="""
        The location in the Directory Information Tree where the group search
        will start. Search string containing '{group}' will be substituted
        with entries taken from allow_nested_groups.
        """,
    )

    group_search_filter = Unicode(
        config=True,
        help="""
        LDAP search filter to return members of groups defined in the
        allowed_groups parameter. Search filters containing '{group}' will
        have that value substituted with the group dns provided in the
        allowed_groups parameter.
        """,
    )

    allowed_groups = Union(
        [Unicode(), List()],
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        List of LDAP group DNs that users must be a member of in order to be granted
        login.
        """,
    )

    allow_nested_groups = Bool(
        default_value=False,
        config=True,
        help="""
        Boolean allowing for recursive search of members within nested groups of
        allowed_groups (defaults to False).
        """,
    )

    auth_state_attributes = List(
        Unicode(),
        config=True,
        help="""
        List of LDAP attributes to fetch for the authenticating user and expose
        to JupyterHub as `auth_state`. When set, `authenticate()` returns a dict
        containing the username and an `auth_state` mapping of the requested
        attributes. Requires `Authenticator.enable_auth_state=True` to be stored
        (defaults to an empty list).
        """,
    )

    username_pattern = Unicode(
        config=True,
        help="""
        Regular expression pattern that a valid username must match. If a
        username does not match the pattern specified here, authentication will
        not be attempted. If not set, allow any username (defaults to None).
        """,
    )

    username_regex = Any(
        help="""
        Compiled regex kept in sync with `username_pattern`
        """
    )

    @observe("username_pattern")
    def _username_pattern_changed(self, change: dict) -> None:
        if not change["new"]:
            self.username_regex = None
        self.username_regex = re.compile(change["new"])

    create_user_home_dir = Bool(
        default_value=False,
        config=True,
        help="""
        If set to True, will attempt to create a user's home directory
        locally if that directory does not exist already.
        """,
    )

    create_user_home_dir_cmd = Command(
        config=True,
        help="""
        Command to create a users home directory.
        The command should be formatted as a list of strings.
        """,
    )

    @default("create_user_home_dir_cmd")
    def _default_create_user_home_dir_cmd(self) -> typing.List[str]:
        if sys.platform == "linux":
            home_dir_cmd = ["mkhomedir_helper"]
        else:
            self.log.debug(f"Not sure how to create a home directory on '{sys.platform}' system")
            home_dir_cmd = list()
        return home_dir_cmd

    async def add_user(self, user: User) -> None:
        if self.create_user_home_dir:
            username = user.name
            user_exists = await maybe_future(self.user_home_dir_exists(username))
            if not user_exists:
                await maybe_future(self.add_user_home_dir(username))
        await maybe_future(super().add_user(user))

    def user_home_dir_exists(self, username: str) -> bool:
        """
        Verify user home directory exists
        """
        try:
            user = pwd.getpwnam(username)
            home_dir = user.pw_dir
            return os.path.isdir(home_dir)
        except KeyError:
            return False

    def add_user_home_dir(self, username: str) -> None:
        """
        Creates user home directory
        """
        cmd = self.create_user_home_dir_cmd + [username]
        self.log.info(
            "Creating '{}' user home directory using command '{}'".format(username, " ".join(cmd))
        )
        # cmd is assembled from the admin-configured create_user_home_dir_cmd trait
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        out, err = proc.communicate()
        if proc.returncode:
            raise RuntimeError(f"Failed to create '{username}' user home directory: {err}")

    def validate_username(self, username: str) -> bool:
        """
        Validate a username
        Return True if username is valid, False otherwise.
        """
        if "/" in username:
            # / is not allowed in usernames
            return False
        if not username:
            # empty usernames are not allowed
            return False
        if not self.username_regex:
            return True
        return bool(self.username_regex.match(username))

    def validate_host(self, host: str) -> bool:
        """
        Validate hostname
        Return True if host is valid, False otherwise.
        """
        ip_address_regex = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        )
        hostname_regex = re.compile(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
        )
        url_regex = re.compile(
            r"^(ldaps?)://"
            r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]):"
            r"([0-9]{1,5})$"
        )
        if bool(ip_address_regex.match(host)):
            # using ipv4 address
            valid = True
        elif bool(hostname_regex.match(host)):
            # using a hostname address
            valid = True
        elif bool(url_regex.match(host)):
            # using host url address
            match = url_regex.match(host)
            proto = match.group(1)
            if proto == "ldaps":
                self.server_tls_strategy = "on_connect"
            valid = True
        else:
            # unsupported host format
            valid = False
        return valid

    def create_ldap_server_pool_obj(
        self, ldap_servers: typing.List[str] = None
    ) -> ldap3.ServerPool:
        """
        Create ldap3 ServerPool Object
        """
        server_pool = ldap3.ServerPool(
            ldap_servers,
            pool_strategy=self.server_pool_strategy.upper(),
            active=self.server_pool_active,
            exhaust=self.server_pool_exhaust,
        )
        return server_pool

    def create_ldap_server_obj(self, host: str) -> ldap3.Server:
        """
        Create ldap3 Server Object
        """
        tls = None
        if self.server_tls_strategy != "insecure":
            tls = ldap3.Tls(**self.server_tls_kwargs)
        server = ldap3.Server(
            host,
            port=self.server_port,
            use_ssl=(self.server_tls_strategy == "on_connect"),
            tls=tls,
            connect_timeout=self.server_connect_timeout,
        )
        return server

    def ldap_connection(
        self, server_pool: ldap3.ServerPool, username: str, password: str
    ) -> ldap3.Connection:
        """
        Create ldap(s) Connection Object
        """
        # select auto_bind behavior based on the configured TLS strategy;
        # 'before_bind' upgrades the connection with STARTTLS prior to binding
        if self.server_tls_strategy == "before_bind":
            auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND
        else:
            auto_bind = ldap3.AUTO_BIND_NO_TLS
        # attempt connection
        try:
            conn = ldap3.Connection(
                server_pool,
                user=username,
                password=password,
                auto_bind=auto_bind,
                read_only=True,
                receive_timeout=self.server_receive_timeout,
            )
        except ldap3.core.exceptions.LDAPBindError as exc:
            msg = "\n{exc_type}: {exc_msg}".format(
                exc_type=exc.__class__.__name__, exc_msg=exc.args[0] if exc.args else ""
            )
            self.log.error(f"Failed to connect to ldap: {msg}")
            conn = None
        return conn

    def get_nested_groups(self, conn, group: str) -> typing.List[str]:
        """
        Recursively search group for nested memberships
        """
        nested_groups = list()
        conn.search(
            search_base=self.group_search_base,
            search_filter=self.group_search_filter.format(group=group),
            search_scope=ldap3.SUBTREE,
        )
        if conn.response:
            for nested_group in conn.response:
                if "dn" in nested_group:
                    nested_groups.extend([nested_group["dn"]])
                    groups = self.get_nested_groups(conn, nested_group["dn"])
                    nested_groups.extend(groups)
        nested_groups = list(set(nested_groups))
        return nested_groups

    def test_auth(self, conn: ldap3.Connection, auth_user_dn: str, password: str) -> bool:
        """
        Test User Authentication
        rebind ldap connection with authenticating user,
        gather results, and close connection
        """
        try:
            auth_bound = conn.rebind(user=auth_user_dn, password=password)
        except ldap3.core.exceptions.LDAPBindError:
            auth_bound = False
        finally:
            conn.unbind()
        return auth_bound

    def _search_attributes(self) -> typing.List[str]:
        """
        Compile the list of LDAP attributes to request during the user search:
        the group-membership attribute (when enforcing allowed_groups) plus any
        configured auth_state_attributes.
        """
        attributes = set()
        if self.allowed_groups:
            attributes.add(self.user_membership_attribute)
        attributes.update(self.auth_state_attributes)
        return list(attributes)

    def _build_auth_response(
        self, username: str, attributes: typing.Optional[dict]
    ) -> typing.Union[str, dict]:
        """
        Build the authenticate() return value, attaching an auth_state mapping of
        the configured auth_state_attributes when requested.
        """
        if not self.auth_state_attributes:
            return username
        attributes = attributes or {}
        auth_state = {attr: attributes.get(attr) for attr in self.auth_state_attributes}
        return {"name": username, "auth_state": auth_state}

    def _read_user_attributes(
        self, conn: ldap3.Connection, auth_user_dn: str, attributes: typing.List[str]
    ) -> typing.Optional[dict]:
        """
        Read attributes directly from the authenticating user's own LDAP entry
        (BASE scope). Used by the direct-bind strategy, which has no search
        response to draw from.
        """
        conn.search(
            search_base=auth_user_dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=list(attributes),
        )
        if conn.response and "attributes" in conn.response[0]:
            return conn.response[0]["attributes"]
        return None

    def _user_in_allowed_groups(
        self, conn: ldap3.Connection, username: str, auth_user_dn: str
    ) -> bool:
        """
        Enforce allowed_groups membership for the direct-bind strategy by reading
        the user's group-membership attribute from their own entry.
        """
        user_attributes = self._read_user_attributes(
            conn, auth_user_dn, [self.user_membership_attribute]
        )
        if not user_attributes:
            self.log.error(
                f"Could not read '{self.user_membership_attribute}' "
                f"attribute for user '{username}'."
            )
            return False
        user_groups = user_attributes.get(self.user_membership_attribute) or []

        # normalize allowed_groups (Union of str or list) and expand nested groups
        permitted_groups = self.allowed_groups
        if isinstance(permitted_groups, str):
            permitted_groups = [permitted_groups]
        permitted_groups = list(permitted_groups)
        if self.allow_nested_groups:
            for group in list(permitted_groups):
                permitted_groups.extend(self.get_nested_groups(conn, group))

        allowed_memberships = list(set(user_groups).intersection(permitted_groups))
        if allowed_memberships:
            self.log.debug(
                f"User '{username}' found in the following allowed ldap "
                f"groups {allowed_memberships}."
            )
            return True
        self.log.error(
            f"User '{username}' is not a member of any permitted groups {permitted_groups}."
        )
        return False

    def _authenticate_direct_bind(
        self,
        username: str,
        password: str,
        server_pool: ldap3.ServerPool,
        conn_servers: typing.List[str],
    ) -> typing.Optional[typing.Union[str, dict]]:
        """
        Authenticate using the direct-bind strategy: bind to the LDAP server as
        the authenticating user via bind_dn_template, trying each template in
        turn. The user's password is verified by the bind itself.
        """
        templates = self.bind_dn_template
        if isinstance(templates, str):
            templates = [templates]
        templates = [t for t in templates if t and t.strip()]
        if not templates:
            self.log.error("'bind_dn_template' is set but contains no usable templates.")
            return None

        for template in templates:
            auth_user_dn = template.format(username=username)
            self.log.debug(f"Attempting direct bind to {conn_servers} as '{auth_user_dn}'.")
            conn = self.ldap_connection(server_pool, auth_user_dn, password)
            if not conn or not conn.bind():
                self.log.debug(f"Direct bind failed for '{auth_user_dn}'.")
                continue

            self.log.info(
                f"User '{username}' successfully authenticated against ldap server {conn_servers}."
            )

            # optional group membership enforcement
            if self.allowed_groups and not self._user_in_allowed_groups(
                conn, username, auth_user_dn
            ):
                conn.unbind()
                return None

            # optional auth_state attributes
            attributes = None
            if self.auth_state_attributes:
                attributes = self._read_user_attributes(
                    conn, auth_user_dn, self.auth_state_attributes
                )

            conn.unbind()
            return self._build_auth_response(username, attributes)

        self.log.error(
            f"User '{username}' authentication failed against ldap "
            f"server {conn_servers} (direct bind)."
        )
        return None

    async def authenticate(
        self, handler: typing.Any, data: dict
    ) -> typing.Optional[typing.Union[str, dict]]:

        # define vars
        username = data["username"]
        password = data["password"]
        server_pool = self.create_ldap_server_pool_obj()
        conn_servers = list()

        # validate credentials
        username = username.lower()
        if not self.validate_username(username):
            self.log.error("Unsupported username supplied")
            return None
        if not password or not password.strip():
            self.log.error("Empty password supplied")
            return None

        # cast server_hosts to list
        if isinstance(self.server_hosts, str):
            self.server_hosts = self.server_hosts.split(",")

        # validate hosts and populate server_pool object
        for raw_host in self.server_hosts:
            host = raw_host.strip().lower()
            if not self.validate_host(host):
                self.log.warning(
                    (
                        "Host '{}' not supplied in approved format. "
                        + "Removing host from Server Pool"
                    ).format(host)
                )
                break
            server = self.create_ldap_server_obj(host)
            server_pool.add(server)
            conn_servers.extend([host])

        # verify ldap connection object parameters are defined
        if not server_pool.servers:
            self.log.error(
                "No hosts provided. ldap connection requires at least 1 host to connect to."
            )
            return None

        # direct-bind strategy: bind to the server as the authenticating user
        # using bind_dn_template, bypassing the service-account search.
        if self.bind_dn_template:
            return self._authenticate_direct_bind(username, password, server_pool, conn_servers)

        # search-bind strategy: connect as the service account and search for
        # the authenticating user before verifying their password.
        if self.bind_user_dn is None or not self.bind_user_dn.strip():
            self.log.error("'bind_user_dn' config value undefined. required for ldap connection")
            return None
        if self.bind_user_password is None or not self.bind_user_password.strip():
            self.log.error(
                "'bind_user_password' config value undefined. required for ldap connection"
            )
            return None

        # verify ldap search object parameters are defined
        if not self.user_search_base or not self.user_search_base.strip():
            self.log.error("'user_search_base' config value undefined. required for ldap search")
            return None
        if not self.user_search_filter or not self.user_search_filter.strip():
            self.log.error("'user_search_filter' config value undefined. required for ldap search")
            return None

        # open ldap connection and authenticate
        self.log.debug(
            f"Attempting ldap connection to {conn_servers} with user '{self.bind_user_dn}'"
        )
        conn = self.ldap_connection(server_pool, self.bind_user_dn, self.bind_user_password)

        # proceed if connection has been established
        if not conn or not conn.bind():
            self.log.error(
                (
                    "Could not establish ldap connection to {} using '{}' "
                    + "and supplied bind_user_password."
                ).format(conn_servers, self.bind_user_dn)
            )
            return None
        else:
            self.log.debug(
                f"Successfully established connection to {conn_servers} "
                f"with user '{self.bind_user_dn}'"
            )

            # format user search filter
            auth_user_search_filter = self.user_search_filter.format(username=username)

            # search for authenticating user in ldap
            self.log.debug(
                f"Attempting LDAP search using search_filter '{auth_user_search_filter}'."
            )
            conn.search(
                search_base=self.user_search_base,
                search_filter=auth_user_search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=self._search_attributes(),
                paged_size=2,
            )

            # handle abnormal search results
            if not conn.response or len(conn.response) > 1:
                self.log.error(
                    (
                        "LDAP search '{}' returned {} results. "
                        + "Please narrow search to 1 result"
                    ).format(auth_user_search_filter, len(conn.response))
                )
                return None
            elif self.allowed_groups and "attributes" not in conn.response[0].keys():
                self.log.error(
                    (
                        "LDAP search '{}' did not return results for requested "
                        + "search attribute(s) '{}'"
                    ).format(auth_user_search_filter, self.user_membership_attribute)
                )
                return None
            else:
                self.log.debug(
                    f"LDAP search '{auth_user_search_filter}' found {len(conn.response)} result(s)."
                )

                # copy response to var
                search_response = conn.response[0]

                # get authenticating user's ldap attributes
                if "dn" not in search_response or not search_response["dn"].strip():
                    self.log.error(
                        (
                            "Search results for user '{}' returned 'dn' attribute with "
                            + "undefined or null value."
                        ).format(username)
                    )
                    conn.unbind()
                    return None
                else:
                    self.log.debug(
                        "Search results for user '{}' returned 'dn' attribute as '{}'".format(
                            username, search_response["dn"]
                        )
                    )
                    auth_user_dn = search_response["dn"]

                # is authenticating user allowed
                if self.allowed_groups:
                    # compile list of user groups
                    if not search_response["attributes"][self.user_membership_attribute]:
                        self.log.error(
                            (
                                "Search results for user '{}' returned '{}' attribute "
                                + "with undefined or null value."
                            ).format(username, self.user_membership_attribute)
                        )
                        conn.unbind()
                        return None
                    else:
                        self.log.debug(
                            "Search results for user '{}' returned '{}' attribute as {}".format(
                                username,
                                self.user_membership_attribute,
                                search_response["attributes"][self.user_membership_attribute],
                            )
                        )
                        user_groups = search_response["attributes"][self.user_membership_attribute]

                    # compile list of permitted groups
                    permitted_groups = list()
                    permitted_groups.extend(self.allowed_groups)
                    if self.allow_nested_groups:
                        for group in self.allowed_groups:
                            nested_groups = self.get_nested_groups(conn, group)
                            permitted_groups.extend(nested_groups)

                    # is authenticating user a member of permitted_groups
                    allowed_memberships = list(set(user_groups).intersection(permitted_groups))
                    if allowed_memberships:
                        self.log.debug(
                            (
                                "User '{}' found in the following allowed ldap groups "
                                + "{}. Proceeding with authentication."
                            ).format(username, allowed_memberships)
                        )
                    else:
                        self.log.error(
                            f"User '{username}' is not a member of any "
                            f"permitted groups {permitted_groups}"
                        )
                        return None
                else:
                    self.log.debug(
                        (
                            "User '{}' will not be verified against allowed_groups due "
                            + "to feature short-circuiting. Proceeding with "
                            + "authentication."
                        ).format(username)
                    )

                # return auth results
                auth_bound = self.test_auth(conn, auth_user_dn, password) or False
                if auth_bound:
                    self.log.info(
                        f"User '{username}' successfully authenticated "
                        f"against ldap server {conn_servers}."
                    )
                    auth_response = self._build_auth_response(
                        username, search_response.get("attributes")
                    )
                else:
                    self.log.error(
                        f"User '{conn_servers}' authentication failed "
                        f"against ldap server {auth_user_dn}."
                    )
                    auth_response = None
                return auth_response
