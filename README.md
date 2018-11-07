## LDAP_Search

![](https://img.shields.io/badge/Python-3.6-blue.svg)&nbsp;&nbsp;

ldap_search is an LDAP query tool that can be used to to enumerate Users, Groups, and Computers on a Windows Domain. In addition, this tool to identify valid accounts through bruteforce/password-spraying via LDAP. It makes use of Impackets python36 branch (still in dev) to perform its main operations and allows login via traditional passwords or hashes.

*Note:* ldap_search, although functional, is more of a PoC. Stay tuned for updates in functionality and formatting.

### Installation
```bash
git clone --recursive https://github.com/m8r0wn/ldap_search
cd ldap_search
sudo chmod +x setup.sh
sudo ./setup.sh
```

### Usage

Enumerate all active users on a domain:
```bash
python3 ldap_search.py users -u user1 -p Password1 -d demo.local
```

Lookup a single user:
```bash
python3 ldap_search.py users -q AdminUser -u user1 -p Password1 -d demo.local
```

Enumerate all computers on a domain:
```bash
python3 ldap_search.py computers -u user1 -p Password1 -d demo.local
```

Enumerate all groups on the domain:
```bash
python3 ldap_search.py groups -u user1 -p Password1 -d demo.local
```

Query group members:
```bash
python3 ldap_search.py groups -q "Domain Admins" -u user1 -p Password1 -d demo.local
```

### Credits
* ![Impacket](https://github.com/SecureAuthCorp/impacket/tree/python36)&nbsp;&nbsp;*(v.0.9.18-dev)*
