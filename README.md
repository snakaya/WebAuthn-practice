# WebAuthn-practice

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/snakaya/WebAuthn-practice/master/LICENSE)

**Now, In Progress...**

WebAuthn-practice works as WebAuthn RP Server and can be used as testing tool for WebAuthn Authenticator and Client. i.e.) Windows10 Edge, Chrome, Firefox and macOS Touch Id, Android Chrome.

The app outputs and records logs of Attestation and Assertion's Response and Options.

If you are WebAuthn/FIDO2 developer, Their output and logs are useful well.

## Feature
* Registration(Attestation) and Authentication(Assertion).
    * Support Attestation Statement Type ('packed', 'android-saftynet', 'fido-u2f' and 'none').
    * Support signature algorithm EC256 and RS256.
* Register users with credential info.
* Change request options(Credential and Assertion).
* Records Attestation Response and View details.

## Requirement
* python >=2.7 + Flask >=1.0.2
* WebAuthn RP Server MUST be HTTPS. WebAuthn-practice works as uWSGI service. You need to HTTPS Web server(Nginx, Apache) and setup to connect to WebAuthn-practice using uWSGI.
Please refer under sample directory.

## Target OS/Browser and Devices
* Windows10 >= 1809
    * *Browser*
        * Edge
        * Chrome >= 70
        * Firefox >= 63
    * *Devices*
        * Face-Camera and Fingerprint-Sensor on Windows Hallo
        * YubiKey
        * FIDO U2F Security Key
* macOS >= 10.14
    * *Browser*
        * Chrome >= 70
        * Firefox >= 63
    * *Devices*
        * TouchID
        * YubiKey
        * FIDO U2F Security Key
* Android >= N
    * *Browser*
        * Chrome >= 70
    * *Devices*
        * Fingerprint-Sensor
        * YubiKey
        * FIDO U2F Security Key

**I do not guarantee of a suitable operation at all.**

## Installation


## Environment Variables
* **WEBAUTHN_RP_ID**
    * (Required) set your RP ID.  i.e.) 'www.example.com'
* **WEBAUTHN_ORIGIN**
    * (Required) set your origin URL. It MUST be match to your site's canonical URL.  i.e.) 'https://www.example.com'

## TODO
* Support Python3
* make Docker-compose

## License
[BSD-3-Clause](https://raw.githubusercontent.com/snakaya/WebAuthn-practice/master/LICENSE)

## Author
Seiji Nakaya / LOOSEDAYS (snakaya-+-loosedays.jp)
