import copy
from jupyterhub.auth import Authenticator 
import ldap3 
from ldap3.utils.conv import escape_filter_chars
import os
import pipes
import pwd
import re
import sys
from subprocess import Popen, PIPE, STDOUT
from tornado import gen
from traitlets import Any, Int, Bool, Bytes, Int, List, Unicode, Union, default, observe

from jupyterhub.traitlets import Command

class LDAPAuthenticator(Authenticator):
    server_hosts = Union(
        [List(),Unicode()],
        config=True,
        help="""
        List of Names, IPs, or the complete URLs in the scheme://hostname:hostport 
        format of the server (required).
        """
    )

    server_port = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The port where the LDAP server is listening. Typically 389, for a 
        cleartext connection, and 636 for a secured connection (defaults to None).
        """
    )

    server_use_ssl = Bool(
        default_value=False,
        config=True,
        help="""
        Boolean specifying if the connection is on a secure port (defaults to False).
        """
    )

    server_connect_timeout = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        Timeout in seconds permitted when establishing an ldap connection before 
        raising an exception (defaults to None).
        """
    )

    server_receive_timeout = Int(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        Timeout in seconds permitted for responses from established ldap 
        connections before raising an exception (defaults to None).
        """
    )

    server_pool_strategy = Unicode(
        default_value='FIRST',
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
        """
    )

    server_pool_active = Union(
        [Bool(),Int()],
        default_value=True,
        config=True,
        help="""
        If True the ServerPool strategy will check for server availability. Set 
        to Integer for maximum number of cycles to try before giving up 
        (defaults to True).
        """
    )

    server_pool_exhaust = Union(
        [Bool(),Int()],
        default_value=False,
        config=True,
        help="""
        If True, any inactive servers will be removed from the pool. If set to 
        an Integer, this will be the number of seconds an unreachable server is 
        considered offline. When this timeout expires the server is reinserted 
        in the pool and checked again for availability (defaults to False).
        """
    )

    bind_user_dn = Unicode(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The account of the user to log in for simple bind (defaults to None).
        """
    )

    bind_user_password = Unicode(
        allow_none=True,
        default_value=None,
        config=True,
        help="""
        The password of the user for simple bind (defaults to None)
        """
    )

    user_search_base = Unicode(
        config=True,
        help="""
        The location in the Directory Information Tree where the user search 
        will start.
        """
    )

    user_search_filter = Unicode(
        config=True,
        help="""
        LDAP search filter to validate that the authenticating user exists 
        within the organization. Search filters containing '{user_logon}' will 
        have that value substituted with the username of the authenticating user.
        """
    )

    user_membership_attribute = Unicode(
        default_value='memberOf',
        config=True,
        help="""
        LDAP Attribute used to associate user group membership 
        (defaults to 'memberOf').
        """
    )

    group_search_base = Unicode(
        config=True,
        help="""
        The location in the Directory Information Tree where the group search 
        will start. Search string containing '{group_dn}' will be substituted 
        with entries taken from allow_nested_groups.
        """
    )

    group_search_filter = Unicode(
        config=True,
        help="""
        LDAP search filter to return members of groups defined in the 
        allowed_groups parameter. Search filters containing '{group_dn}' will 
        have that value substituted with the group dns provided in the 
        allowed_groups parameter.
        """
    )

    allowed_groups = Union(
        [Unicode(),List()],
        config=True,
        help="""
        List of LDAP group DNs that users must be a member of in order to be granted
        login.
        """
    )

    allow_nested_groups = Bool(
        default_value=False,
        config=True,
        help="""
        Boolean allowing for recursive search of members within nested groups of
        allowed_groups (defaults to False).
        """
    )

    username_pattern = Unicode(
        config=True,
        help="""
        Regular expression pattern that all valid usernames must match. If a 
        username does not match the pattern specified here, authentication will 
        not be attempted. If not set, allow any username (defaults to None).
        """
    )
    
    username_regex = Any(
        help="""
        Compiled regex kept in sync with `username_pattern`
        """
    )

    @observe('username_pattern')
    def _username_pattern_changed(self, change):
        if not change['new']:
            self.username_regex = None
        self.username_regex = re.compile(change['new'])

    create_user_home_dir = Bool(
        default_value=False,
        config=True,
        help="""
        If set to True, will attempt to create a domain user's home directory 
        locally if that directory does not exist already.
        """
    )

    create_user_home_dir_cmd = Command(
        config=True,
        help="""
        Command to create a domain users home directory.
        """
    )
    @default('create_user_home_dir_cmd')
    def _default_create_user_home_dir_cmd(self):
        if sys.platform == 'linux':
            return ['mkhomedir_helper']
        else:
            self.log.debug("Not sure how to create a home directory on '%s' system", sys.platform)
            return ['']

    @gen.coroutine
    def add_user(self, user):
        username = user.name
        user_exists = yield gen.maybe_future(self.domain_user_exists(username))
        if not user_exists:
            if self.create_user_home_dir:
                yield gen.maybe_future(self.add_user_home_dir(username))
            else:
                raise KeyError("Domain user '%s' does not exists locally." % username)
        yield gen.maybe_future(super().add_user(user))

    def domain_user_exists(self, username):
        user = pwd.getpwnam(username)
        home_dir = user[5]
        if os.path.isdir(home_dir):
            return True
        else:
            return False

    def add_user_home_dir(self, username):
        cmd = [ arg.replace('USERNAME', username) for arg in self.create_user_home_dir_cmd ] + [username]
        self.log.info("Creating '%s' user home directory using command '%s'", username, ' '.join(map(pipes.quote, cmd)))
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        p.wait()
        if p.returncode:
            err = p.stdout.read().decode('utf8', 'replace')
            raise RuntimeError("Failed to create system user %s: %s" % (username, err))

    def normalize_username(self, username):
        username = username.lower()
        username = escape_filter_chars(username)
        return username

    def normalize_host(self, host):
        host = host.lower()
        host = host.strip()
        return host

    def validate_username(self, username):
        """
        Validate a normalized username
        Return True if username is valid, False otherwise.
        """
        if '/' in username:
            # / is not allowed in usernames
            return False
        if not username:
            # empty usernames are not allowed
            return False
        if not self.username_regex:
            return True
        return bool(self.username_regex.match(username))

    def validate_host(self, host):
        """
        Validate a normalized host
        Return True if host is valid, False otherwise.
        """
        host_ip_regex = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        host_name_regex = re.compile('^((?!-)[a-z0-9\-]{1,63}(?<!-)\.){1,}((?!-)[a-z0-9\-]{1,63}(?<!-)){1}$')
        host_url_regex = re.compile('^(ldaps?://)(((?!-)[a-z0-9\-]{1,63}(?<!-)\.){1,}((?!-)[a-z0-9\-]{1,63}(?<!-)){1}):([0-9]{3})$')
        if bool(host_ip_regex.match(host)):
            # using ipv4 address
            return True
        elif bool(host_name_regex.match(host)):
            # using a hostname address
            return True
        elif bool(host_url_regex.match(host)):
            # using host url address
            return True
        else:
            # unsupported host format
            return False

    def create_ldap_server_pool_obj(self, ldap_servers=None):
        server_pool = ldap3.ServerPool(
            ldap_servers,
            pool_strategy=self.server_pool_strategy.upper(),
            active=self.server_pool_active,
            exhaust=self.server_pool_exhaust
        )
        return server_pool

    def create_ldap_server_obj(self, host):
        server = ldap3.Server(
            host,
            port=self.server_port,
            use_ssl=self.server_use_ssl,
            connect_timeout=self.server_connect_timeout
        )
        return server

    def ldap_connection(self, server_pool, username, password):
        try:
            conn = ldap3.Connection(
                server_pool,
                user=username,
                password=password,
                auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                read_only=True,
                receive_timeout=self.server_receive_timeout)
        except ldap3.core.exceptions.LDAPBindError as exc:
            msg = '\n{exc_type}: {exc_msg}'.format(
                    exc_type=exc.__class__.__name__,
                    exc_msg=exc.args[0] if exc.args else '')
            return None
        return conn

    def get_nested_groups(self, conn, group_dn):
        nested_groups = list()
        conn.search(
                search_base = self.group_search_base,
                search_filter = self.group_search_filter.format_map(locals()),
                search_scope = ldap3.SUBTREE)
        if len(conn.response) > 0:
            for nested_group in conn.response:
                nested_groups.extend([nested_group['dn']])
                nested_groups.extend(self.get_nested_groups(conn, nested_group['dn']))
        nested_groups = list(set(nested_groups))
        return nested_groups


    @gen.coroutine
    def authenticate(self, handler, data):

        # define vars
        username = data['username']
        password = data['password']
        server_pool = self.create_ldap_server_pool_obj()
        conn_servers = list()

        # validate credentials
        username = self.normalize_username(username)
        if not self.validate_username(username):
            self.log.error('Unsupported username supplied')
            return None
        if password is None or password.strip() == '':
            self.log.error('Empty password supplied')
            return None

        # cast server_hosts to list
        if isinstance(self.server_hosts, str):
            self.server_hosts = self.server_hosts.split()

        # validate hosts and populate server_pool object
        for host in self.server_hosts:
            host = self.normalize_host(host)
            if not self.validate_host(host):
                self.log.warning("Host '%s' not supplied in approved format. Removing host from Server Pool", host)
                break
            server = self.create_ldap_server_obj(host)
            server_pool.add(server)
            conn_servers.extend([host])

        # verify ldap connection object parameters are defined
        if len(server_pool.servers) < 1:
            self.log.error("No hosts provided. ldap connection requires at least 1 host to connect to.")
            return None
        if not self.bind_user_dn or self.bind_user_dn.strip() == '':
            self.log.error("'bind_user_dn' config value undefined. requried for ldap connection")
            return None
        if not self.bind_user_password or self.bind_user_password.strip() == '':
            self.log.error("'bind_user_password' config value undefined. requried for ldap connection")
            return None

        # verify ldap search object parameters are defined
        if not self.user_search_base or self.user_search_base.strip() == '':
            self.log.error("'user_search_base' config value undefined. requried for ldap search")
            return None
        if not self.user_search_filter or self.user_search_filter.strip() == '':
            self.log.error("'user_search_filter' config value undefined. requried for ldap search")
            return None

        # open ldap connection and authenticate
        self.log.debug("Attempting ldap connection to %s with user '%s'", conn_servers, self.bind_user_dn)
        conn = self.ldap_connection(
                server_pool, 
                self.bind_user_dn, 
                self.bind_user_password)

        # proceed if connection has been established
        if not conn or not conn.bind():
            self.log.error(
                    "Could not establish ldap connection to %s using '%s' and supplied bind_user_password.", 
                    conn_servers, self.ldap_bind_user_dn)
            return None
        else:
            self.log.debug(
                    "Successfully established connection to %s with user '%s'", 
                    conn_servers, self.bind_user_dn)

            # populate allowed_groups with nested groups
            if self.allow_nested_groups:
                for group in self.allowed_groups:
                    nested_groups = self.get_nested_groups(conn, group)
                self.allowed_groups.extend(nested_groups)

            # format user search filter
            auth_user_search_filter = self.user_search_filter.format(
                user_logon = username)
            
            # search for authenticating user in ldap
            self.log.debug("Attempting LDAP search using search_filter '%s'.", auth_user_search_filter)
            found = conn.search(
                    search_base = self.user_search_base, 
                    search_filter = auth_user_search_filter, 
                    search_scope = ldap3.SUBTREE, 
                    attributes = self.user_membership_attribute,
                    paged_size=2)

            # handle abnormal search results
            if len(conn.response) == 0 or 'attributes' not in conn.response[0].keys():
                self.log.error(
                        "LDAP search '%s' found %i result(s).", 
                        auth_user_search_filter, len(conn.response))
                return None
            elif len(conn.response) > 1:
                self.log.error(
                        "LDAP search '%s' found %i result(s). Please narrow search to 1 result.", 
                        auth_user_search_filter, len(conn.response))
                return None
            else:
                self.log.debug("LDAP search '%s' found %i result(s).", auth_user_search_filter, len(conn.response))

                # copy response to var
                search_response = copy.deepcopy(conn.response[0])

                # get authenticating user's ldap attributes
                if not search_response['dn'] or search_response['dn'].strip == '':
                    self.log.error(
                            "Search results for user '%s' returned 'dn' attribute with undefined or null value.", 
                            username)
                    conn.unbind()
                    return None
                else:
                    self.log.debug(
                            "Search results for user '%s' returned 'dn' attribute as '%s'", 
                            username, search_response['dn'])
                    auth_user_dn = search_response['dn']
                if not search_response['attributes'][self.user_membership_attribute] or \
                    len(search_response['attributes'][self.user_membership_attribute]) == 0:
                        self.log.error(
                                "ERROR: Search results for user '%s' returned '%s' attribute with undefned or null value.", 
                                username, self.user_membership_attribute)
                        conn.unbind()
                        return None
                else:
                    self.log.debug(
                            "Search results for user '%s' returned '%s' attribute as %s", 
                            username, self.user_membership_attribute, 
                            search_response['attributes'][self.user_membership_attribute])
                    auth_user_memberships = search_response['attributes'][self.user_membership_attribute]

                # is authenticating user a member of allowed_groups
                allowed_memberships = list(set(auth_user_memberships).intersection(self.allowed_groups))
                if bool(allowed_memberships):
                    self.log.debug(
                            "User '%s' found in the following allowed ldap groups %s. Proceeding with authentication.", 
                            username, allowed_memberships)
                    
                    # rebind ldap connection with authenticating user, gather results, and close connection
                    rebind = conn.rebind(
                            user = auth_user_dn, 
                            password = password)
                    auth_bound = copy.deepcopy(conn.bind())
                    conn.unbind()
                    if not auth_bound:
                        self.log.error(
                                "Could not establish ldap connection to %s using '%s' and supplied bind_user_password.", 
                                conn_servers, self.bind_user_dn)
                        return None
                    else:
                        self.log.info("User '%s' sucessfully authenticated against ldap server %r.", username, conn_servers)
                        return username
                else:
                    self.log.error("User '%s' is not a member of any allowed_groups %s", username, self.allowed_groups)
                    return None
