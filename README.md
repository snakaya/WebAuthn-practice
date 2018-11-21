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

* python >=2.7 + Flask >=1.0.2 (Not support python3 yet)

**[NOTICE]** WebAuthn RP Server need HTTPS Web server as FrontEnd. Because of WebAuthn's security cause.
You MUST setup HTTPS Web server (i.e.  Nginx, Apache httpd) after setting RP server up.

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

## Basic Installation

1.Download source from GitHub to your app's directory.

    $ cd /var/www/webauthn-practice
    $ git clone https://github.com/snakaya/WebAuthn-practice.git .

2.Install required python modules.

    $ pip install -r requirements.txt

3.Setup Database.

    $ cd /var/www/webauthn-practice/app
    $ python create_db.py

4.Start WebAuthn-practice

    $ python app.py

  You can access to http://localhost:5000/ .

## Configuration

### Database Setting

Please set Database connection info via Environment Variables.

* **WEBAUTHN_DB_TYPE**
  * (Required) set your DB Type the followings:
    * SQLite:     'sqlite'  (default)
    * MySQL:      'mysql'
    * PostgreSQL: 'postgresql'
    * Oracle:      'oracle'
* **WEBAUTHN_DB_USERID**
  * set DB UserID.
* **WEBAUTHN_DB_PASSWORD**
  * set DB UserID's Password.
* **WEBAUTHN_DB_HOST**
  * set Database HostName or IP Address.
* **WEBAUTHN_DB_NAME**
  * set Database Name (SID in Oracle, DB FileName in SQLite).

if you change DB Type, Please retry to create db.

### RP ID and Origin

WebAuthn RP need to be set RP ID and Origin URL before of startup via Environment Variables.

    $ export WEBAUTHN_RP_ID=<Your RP ID>             # i.e.) www.example.com
    $ export WEBAUTHN_ORIGIN=<Your Origin URL>       # i.e.) https://www.example.com

* **WEBAUTHN_RP_ID**
  * (Required) set your RP ID.  i.e.) 'www.example.com'
* **WEBAUTHN_ORIGIN**
  * (Required) set your origin URL. It MUST be match to your site's canonical URL.  i.e.) 'https://www.example.com'

### Run using uWSGI

Yes, It is good idea.
Please refer sample/uwsgi.ini.sample. Edit it and copy to your app directory.

    $ uwsgi --ini uwsgi.ini

## TODO

[ ] Support Python3

[ ] make docker-compose

## License

[BSD-3-Clause](https://raw.githubusercontent.com/snakaya/WebAuthn-practice/master/LICENSE)

## Author

Seiji Nakaya / LOOSEDAYS (snakaya-(^^)-loosedays.jp)
