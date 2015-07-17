[![License](https://img.shields.io/github/license/Torchmind/Padlock.svg?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0.txt)
[![Latest Tag](https://img.shields.io/github/tag/Torchmind/Padlock.svg?style=flat-square&label=Latest Tag)](https://github.com/Torchmind/Padlock/tags)
[![Latest Release](https://img.shields.io/github/release/Torchmind/Padlock.svg?style=flat-square&label=Latest Release)](https://github.com/Torchmind/Padlock/releases)

Padlock Authentication System
=============================

Table of Contents
-----------------
* [About](#about)
* [Contacts](#contacts)
* [Issues](#issues)
* [Building](#building)
* [Contributing](#contributing)

About
-----

A simple authentication system designed for API clients.

Supported token verification schemes:

* Asymmetric Cryptography
    * RSA
    * DSA
    * etc.
* Symmetric Cryptography
    * HmacMD5
    * HmacSHA1
    * HmacSHA256

Contacts
--------

* [IRC #Akkarin on irc.spi.gt](http://irc.spi.gt/iris/?nick=Guest....&channels=Akkarin&prompt=1) (alternatively #Akkarin on esper.net)
* [GitHub](https://github.com/Torchmind/Padlock)

Using
-----

When running maven you may simply add a new dependency along with our repository to your ```pom.xml```:

```xml
<repository>
        <id>torchmind</id>
        <url>https://maven.torchmind.com/snapshot/</url>
</repository>

<dependencies>
        <dependency>
                <groupId>com.torchmind</groupId>
                <artifactId>padlock</artifactId>
                <version>1.0-SNAPSHOT</version>
        </dependency>
</dependencies>
```

En/De-Coding authentication claims:
```java
String encodedClaim = ...;
Padlock padlock = Padlock.builder ().build ();

IAuthenticationClaim claim = padlock.decode (encodedClaim);
encodedClaim = padlock.encode (claim);
```

Signing/Verifying authentication claims:
```java
AuthenticationClaimMetadata claimMetadata = ...;
ISignatureProvider signatureProvider = ...;
IVerificationProvider verificationProvider = ...;
Padlock padlock = Padlock.builder ().signatureProvider (signatureProvider).verificationProvider (verificationProvider).build ();

IAuthenticationClaim claim = padlock.sign (claimMetadata);
boolean verified = padlock.verify (claim);
```

Issues
------

You encountered problems with the library or have a suggestion? Create an issue!

1. Make sure your issue has not been fixed in a newer version (check the list of [closed issues](https://github.com/Torchmind/Padlock/issues?q=is%3Aissue+is%3Aclosed)
1. Create [a new issue](https://github.com/Torchmind/Padlock/issues/new) from the [issues page](https://github.com/Torchmind/Padlock/issues)
1. Enter your issue's title (something that summarizes your issue) and create a detailed description containing:
   - What is the expected result?
   - What problem occurs?
   - How to reproduce the problem?
   - Crash Log (Please use a [Pastebin](http://www.pastebin.com) service)
1. Click "Submit" and wait for further instructions

Building
--------

1. Clone this repository via ```git clone https://github.com/Torchmind/Padlock.git``` or download a [zip](https://github.com/Torchmind/Padlock/archive/master.zip)
1. Build the modification by running ```mvn clean install```
1. The resulting jars can be found in ```target```

Contributing
------------

Before you add any major changes to the library you may want to discuss them with us (see [Contact](#contact)) as
we may choose to reject your changes for various reasons. All contributions are applied via [Pull-Requests](https://help.github.com/articles/creating-a-pull-request).
Patches will not be accepted. Also be aware that all of your contributions are made available under the terms of the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt). Please read the [Contribution Guidelines](CONTRIBUTING.md)
for more information.
