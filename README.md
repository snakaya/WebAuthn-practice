# WebAuthn-practice

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/snakaya/WebAuthn-practice/master/LICENSE)

WebAuthn-practice works as WebAuthn/FIDO2 RP Server and can be used as testing tool for WebAuthn Authenticator and Client. i.e.) Windows10 Edge, Chrome, Firefox and macOS Touch Id, Android Chrome.

The app outputs and records logs of Attestation and Assertion's Response and Options.

If you are WebAuthn/FIDO2 developer, Their output and logs will be useful well.

## Feature
* Registration(Attestation) and Authentication(Assertion).
    * Support Attestation Statement Type ('packed', 'android-saftynet', 'fido-u2f' and 'none', expect 'tpm', 'android-key' and 'ECDAA').
    * Support signature algorithm EC256 and RS256.
* Change request options(Credential and Assertion).
* Register users with credential info.
* Records Attestation Response and View details.

## Requirement
* python >=2.7 + Flask >=1.0.2
* WebAuthn RP Server need to Frontend HTTPS Web server. WebAuthn-practice works as uWSGI service. You have to setup HTTPS Web server(Nginx, Apache) and connect to WebAuthn-practice via WSGI.
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

## Environment Variables
* **WEBAUTHN_RP_ID**
    * (Required) set your RP ID.  i.e.) 'www.example.com'
* **WEBAUTHN_ORIGIN**
    * (Required) set your origin URL. It MUST be match to your site's canonical URL.  i.e.) 'https://www.example.com'

## Installation
**[NOTICE]** WebAuthn RP Server need HTTPS Web server as frontend. Because of security cause.
You MUST setup HTTPS Web server (i.e.  Nginx, Apache httpd) after setting RP server up.

1.Download source from GitHub to your app's directory.

    $ cd /var/www/webauthn-practice
    $ git clone https://github.com/snakaya/WebAuthn-practice.git .

2.Set Environment Variable for RP ID and ORIGIN URL.

    $ export WEBAUTHN_RP_ID=<Your RP ID>             # i.e.) www.example.com
    $ export WEBAUTHN_ORIGIN=<Your Origin URL>       # i.e.) https://www.example.com

3.Set Your Database settings.
  Please Edit app/app.py.

    # DB Settings
    DB_USERNAME = ''             # Set DB Username
    DB_PASSWORD = ''             # Set DB User's Password
    DB_HOST     = '127.0.0.1'    # Set DB Server DNS Name or IP Address
    DB_NAME     = 'webauthn.db'  # Set DB Name(SID)
    # Choose your DB type
    #DB_CONNECT_URI = 'mysql://{}:{}@{}/{}'.format(DB_USERNAME, DB_PASSWORD, DB_HOST, DB_NAME)                    # MySQL
    #DB_CONNECT_URI = 'postgresql://{}:{}@{}/{}'.format(DB_USERNAME, DB_PASSWORD, DB_HOST, DB_NAME)               # PostgreSQL
    #DB_CONNECT_URI = 'oracle://{}:{}@{}/{}'.format(DB_USERNAME, DB_PASSWORD, DB_HOST, DB_NAME)                   # Oracle
    DB_CONNECT_URI = 'sqlite:///{}'.format(os.path.join(os.path.dirname(os.path.abspath(__name__)), DB_NAME))    # SQLite

4.Setup Database.

    $ cd /var/www/webauthn-practice/app
    $ python create_db.py

5.Start Quickly

    $ python app.py

  You can access to http://localhost:5000/ .

6.You want to use uWSGI?

    Yes, It is good idea.
    Please refer sample/uwsgi.ini.sample and sample/webauthn-practice.service.sample .

7.Setup HTTPS Web server

    Please setup HTTPS Web server and connect upstream to WebAuthn-practice RP server.
    You need to access via Origin URL.


## TODO
* Support Python3
* make Docker-compose

## License
[BSD-3-Clause](https://raw.githubusercontent.com/snakaya/WebAuthn-practice/master/LICENSE)

## Author
Seiji Nakaya / LOOSEDAYS (snakaya-+-loosedays.jp)
