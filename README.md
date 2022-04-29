# PassTheCert

Sometimes, Domain Controllers do not support PKINIT. This can be because their
certificates do not have the `Smart Card Logon EKU`. However, several
protocols, including LDAP, support Schannel, thus authentication through TLS.
We created a small Proof-of-Concept tool that allows authenticating against an
LDAP/S server with a certificate to perform different attack actions.

More information in the [accompanying blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

This repository contains a C# version, by [the-useless-one](https://github.com/the-useless-one),
and a Python version, by [ThePirateWhoSmellsOfSunflowers](https://github.com/ThePirateWhoSmellsOfSunflowers) / drm ([@lowercase_drm](https://twitter.com/lowercase_drm))

