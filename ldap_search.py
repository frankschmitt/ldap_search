#!/usr/bin/env python3

# Author: m8r0wn
# License: GPL-3.0
# Description: Perform Ldap queries and enumerate Active Directory environments.
# Credit / Resources: https://github.com/SecureAuthCorp/impacket

# @todo add ability to create custom queries
# @todo add attributes to predefined searches
# @todo brute force with hash authentication
# @todo output formatting

from impacket.ldap import ldap

class LdapEnum():
    def __init__(self, user, passwd, hash, domain, host, timeout):
        self.ldaps = False
        self.domain = domain
        self.baseDN = ''

        # Set domain name for baseDN
        try:
            for x in self.domain.split('.'):
                self.baseDN += 'dc={},'.format(x)

            # Remove last ','
            self.baseDN = self.baseDN[:-1]
        except:
            self.baseDN = 'dc={}'.format(self.domain)

        # If srv not provided, use domain name
        if not host:
            self.host = self.domain
        else:
            self.host = host

        # Create Ldap(s) Connection
        try:
            self.ldap_connect(self.host)
        except:
            self.ldaps_connect(self.host)
        self.con._socket.settimeout(timeout)

        # Authentication
        self.ldap_auth(user, passwd, hash, self.domain)

    #########################################
    # Ldap Connection & Authentication
    #########################################
    def ldap_connect(self, srv):
        self.con = ldap.LDAPConnection("ldap://{}".format(srv), )

    def ldaps_connect(self, srv):
        self.con = ldap.LDAPConnection("ldaps://{}".format(srv), )

    def ldap_auth(self, user, passwd, hash, domain):
        if hash:
            lm = ''
            nt = ''
            try:
                lm, nt = hash.split(':')
            except:
                nt = hash
            self.con.login(user, '', domain, lmhash=lm, nthash=nt)
        else:
            self.con.login(user, passwd, domain, '', '')

    def ldap_query(self, searchFilter, attrs, parser):
        sc = ldap.SimplePagedResultsControl(size=9000)
        try:
            resp = self.con.search(searchBase=self.baseDN, searchFilter=searchFilter, attributes=attrs,
                                   searchControls=[sc], sizeLimit=0, timeLimit=50, perRecordCallback=parser)
        except ldap.LDAPSearchError as e:
            raise Exception("ldap_query error: {}".format(str(e)))

    #########################################
    # Ldap search Filters
    #########################################
    def user_query(self, query):
        self.data = {}
        attrs = ['sAMAccountName']
        # All users even disabled
        if query == 'all':
            search = "(&(objectCategory=person)(objectClass=user))"
        # Lookup user by email
        elif '@' in query:
            attrs = ['Name', 'userPrincipalName', 'sAMAccountName', 'mail', 'company', 'department', 'mobile',
                     'telephoneNumber', 'badPwdCount']
            search = '(&(objectClass=user)(mail:={}))'.format(query.lower())
        # Lookup user by username
        elif query and query not in ['active', 'Active']:
            attrs = ['Name', 'userPrincipalName', 'sAMAccountName', 'mail', 'company', 'department', 'mobile',
                     'telephoneNumber', 'badPwdCount']
            search = "(&(objectClass=user)(sAMAccountName:={}))".format(query.lower())
        # DEFAULT: Show only active users
        else:
            search = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        self.ldap_query(search, attrs, self.generic_parser)
        return self.data

    def computer_query(self, ):
        self.data = {}
        # return a list of all domain computers
        attrs = ['dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']
        # attrs = ['dNSHostName']
        search = '(&(objectClass=Computer))'
        self.ldap_query(search, attrs, self.generic_parser)
        return self.data

    def group_query(self, ):
        self.data = {}
        # return a list of all domain groups
        attrs = ['distinguishedName', 'cn']
        search = '(&(objectCategory=group))'
        self.ldap_query(search, attrs, self.generic_parser)
        return self.data

    def group_membership(self, group):
        self.data = {}
        # return members of a specific group
        attrs = ['member']
        search = '(&(objectCategory=group)(cn={}))'.format(group)
        self.ldap_query(search, attrs, self.group_membership_parser)
        return self.data

    #########################################
    # Ldap Results Parser
    #########################################
    def generic_parser(self, resp):
        tmp = {}
        dtype = ''
        resp_data = ''
        try:
            for attr in resp['attributes']:
                dtype = str(attr['type'])

                # catch formatting issues
                if "SetOf:" in str(attr['vals']):
                    resp_data = str(attr['vals'][0])
                else:
                    resp_data = str(attr['vals'])

                tmp[dtype] = resp_data
            # Add to class obj & cleanup
            self.categorize(tmp)
            del (tmp)
        except Exception as e:
            if "list indices must be integers or slices, not str" not in str(e):
                raise Exception(e)

    def group_membership_parser(self, resp):
        try:
            for attr in resp['attributes']:
                for member in attr['vals']:
                    attrs = ['sAMAccountName']
                    cn = str(member).split(',')[0]
                    search = "(&({}))".format(cn)
                    self.ldap_query(search, attrs, self.generic_parser)
        except Exception as e:
            pass

    def close(self):
        # Manually close ldap socket - This caused a lot of headaches
        self.con._socket.close()
        self.con._socket.shutdown()

    def categorize(self, tmp):
        # Take temp data, sort and move to class object
        for x in ['sAMAccountName', 'dNSHostName', 'cn']:
            try:
                self.data[tmp[x].lower()] = tmp
            except:
                pass


###################################################
# Import class or use as stand-alone script
###################################################
def print_success(msg):
    print('\033[1;32m[+] \033[1;m{}'.format(msg))


def print_status(msg):
    print('\033[1;34m[*] \033[1;m{}'.format(msg))


def print_failure(msg):
    print('\033[1;31m[-] \033[1;m{}'.format(msg))


def print_error(msg):
    print('\033[1;33m[!] \033[1;m{}'.format(msg))


def file_exists(parser, filename):
    # Used with argparse to check if input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]


def get_ip(domain):
    from socket import gethostbyname
    try:
        return gethostbyname(domain)
    except:
        return "Unable to resolve LDAP server"


def main(args):
    run_query = True
    for user in args.user:
        for passwd in args.passwd:
            try:
                # Set server if not set
                if not args.srv:
                    args.srv = get_ip(args.domain)

                # Init Class / Con
                query = LdapEnum(user, passwd, args.hash, args.domain, args.srv, args.timeout)

                start = datetime.now()
                print_success("Ldap Connection - {}:{}@{} (Domain: {}) (LDAPS: {})".format(user, passwd, args.srv, args.domain,query.ldaps))

                # Only run query once, then continue to check login status
                if not run_query: break

                # Send Query
                if args.lookup_type in ['user', 'users']:
                    resp = query.user_query(args.query)
                elif args.lookup_type in ['group', 'groups']:
                    if args.query:
                        resp = query.group_membership(args.query)
                    else:
                        resp = query.group_query()
                elif args.lookup_type in ['computer', 'computers']:
                    resp = query.computer_query()

                # Display results
                if args.lookup_type and resp:
                    print_status("Query Results:")
                    for result in resp:
                        for k, v in resp[result].items():
                            if args.verbose:
                                print("{}\t{}\t{}".format(result, k, v))
                            else:
                                print(v)
                    # If successful, dont search again
                    run_query = False

            except Exception as e:
                if args.debug:
                    if "ACCOUNT_LOCKED_OUT" in str(e):
                        print_failure("Account Locked Out - {}:{}@{}".format(user, passwd, args.srv))

                    elif "LOGON_FAILURE" in str(e):
                        print_failure("Login Failed - {}:{}@{}".format(user, passwd, args.srv))

                    elif "invalidCredentials:" in str(e):
                        print_failure("Login Failed - {}:{}@{}".format(user, passwd, args.srv))

                    elif "Connection error" in str(e):
                        print_error("Connection Error - {} (Domain: \"{}\")".format(args.srv, args.domain))
                    else:
                        print_error("Error - {}".format(str(e)))

            finally:
                try:
                    count = query.data
                    query.con.close()
                    del (query)
                    stop = datetime.now()
                    print_status("{} results in {}\n".format(len(count), stop - start))
                except Exception as e:
                    pass


if __name__ == '__main__':
    import argparse
    from os import path
    from sys import argv, exit
    from getpass import getpass
    from datetime import datetime

    version = '0.0.1'
    try:
        args = argparse.ArgumentParser(description="""
               {0}   (v{1})
--------------------------------------------------
Perform LDAP search queries to enumerate Active Directory environments.

Usage:
    python3 {0} group -q "Domain Admins" -u user1 -p Password1 -d demo.local
    python3 {0} users -q active -u admin -p Welcome1 -d demo.local 
    """.format(argv[0], version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
        # Main Ldap query type
        args.add_argument('lookup_type', nargs='?', help='Lookup Types: user, group, computer')
        args.add_argument('-q', dest='query', type=str, default='', help='Specify user or group to query')

        # Domain Authentication
        user = args.add_mutually_exclusive_group(required=True)
        user.add_argument('-u', dest='user', type=str, action='append', help='Single username')
        user.add_argument('-U', dest='user', default=False, type=lambda x: file_exists(args, x), help='Users.txt file')

        passwd = args.add_mutually_exclusive_group()
        passwd.add_argument('-p', dest='passwd', action='append', default=[], help='Single password')
        passwd.add_argument('-P', dest='passwd', default=False, type=lambda x: file_exists(args, x), help='Password.txt file')
        passwd.add_argument('-H', dest='hash', type=str, default='', help='Use Hash for Authentication')

        args.add_argument('-d', dest='domain', type=str, default='', required=True, help='Domain (Ex. demo.local)')
        args.add_argument('-s', '-srv', dest='srv', type=str, default='', help='LDAP Server (optional)')

        # Alt program arguments
        args.add_argument('-t', dest='timeout', type=int, default=3, help='Connection Timeout (Default: 4)')
        args.add_argument('-v', dest="verbose", action='store_true', help="Show search result Field names")
        args.add_argument('-vv', dest="debug", action='store_true', help="Show Failed logons & Errors")
        args = args.parse_args()

        if args.hash:
            args.passwd.append(False)
        elif not args.passwd:
            # Get password if not provided
            args.passwd = getpass("Enter password, or continue with null-value: ")

        main(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)