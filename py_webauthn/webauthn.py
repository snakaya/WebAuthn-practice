from __future__ import print_function

import os
import sys
import logging
import codecs
import base64
import hashlib
import json
import struct
import re
import cbor2
import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ObjectIdentifier, load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto

#
# App Const for classes
#

# Authenticator data flags.
# https://www.w3.org/TR/webauthn/#authenticator-data
USER_PRESENT = 1 << 0
USER_VERIFIED = 1 << 2
ATTESTATION_DATA_INCLUDED = 1 << 6
EXTENSION_DATA_INCLUDED = 1 << 7
# REF: https://www.iana.org/assignments/cose/cose.xhtml
# COSE Key Name
COSE_KEYNAME_KTY = 1
COSE_KEYNAME_KID = 2
COSE_KEYNAME_ALG = 3
COSE_KEYNAME_KEYOPS = 4
COSE_KEYNAME_BASEIV = 5
# COSE Key Label
COSE_KEYLABEL_KTY = 'kty'
COSE_KEYLABEL_KID = 'kid'
COSE_KEYLABEL_ALG = 'alg'
COSE_KEYLABEL_KEYOPS = 'key_ops'
COSE_KEYLABEL_BASEIV = 'Base IV'
# COSE Algorithms
COSE_ALG_ES256 = -7    # ECDSA w/ SHA-256  a.k.a. ES256
COSE_ALG_RS256 = -257  # RSASSA-PKCS1-v1_5 w/ SHA-256  a.k.a. RS256
# COSE Algorithms Label
COSE_ALGLABEL_ES256 = 'ES256'
COSE_ALGLABEL_RS256 = 'RS256'
# COSE Algorithms Numbers
COSE_ALG_ES256_X = -2
COSE_ALG_ES256_Y = -3
COSE_ALG_RS256_N = -1
COSE_ALG_RS256_E = -2
# X5C Certificate OID
OID_AAGUID = '1.3.6.1.4.1.45724.1.1.4'
# Attestation Types
AT_BASIC = 'Basic'
AT_ECDAA = 'ECDAA'            # Not supported now.
AT_NONE = 'None'
AT_ATTESTATION_CA = 'AttCA'   # Not supported now.
AT_SELF_ATTESTATION = 'Self'
AT_OTHER = 'Other'            # Unknown Format.    
# Supported Attestation Types now
SUPPORTED_ATTESTATION_TYPES = (
    AT_BASIC,
    AT_NONE,
    AT_SELF_ATTESTATION
)
# Supported Attestation Types now
# ('android-key', 'tpm' are not supported yet.)
SUPPORTED_ATTESTATION_FORMATS = (
    'packed',
    'fido-u2f',
    'android-safetynet',
    'none',
)
# Trust anchors (trusted attestation roots directory).
DEFAULT_TRUST_ANCHOR_DIR = 'trusted_attestation_roots'
# Client data type.
TYPE_CREATE = 'webauthn.create'
TYPE_GET = 'webauthn.get'
# Expected client extensions
EXPECTED_CLIENT_EXTENSIONS = {
    #'appid': None,
    #'loc': None
}
# Expected authenticator extensions
EXPECTED_AUTHENTICATOR_EXTENSIONS = {
}


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class AuthenticationRejectedException(Exception):
    pass

class RegistrationRejectedException(Exception):
    pass

class CommonRejectedException(Exception):
    pass

class WebAuthnLogger(object):

    def __init__(self):
        self.debug_log = []

    def add(self, msg):
        if type(msg) == str or type(msg) == unicode:
            self.debug_log.append(msg)
        elif type(msg) == list:
            for m in msg:
                self.debug_log.append(m)
    def get(self):
        return self.debug_log


class WebAuthnTools(object):
    
    def __init__(self):
        pass
    
    def format_user_pubkey(self, pub_key):
        return _encodeToJWK_public_key(_webauthn_b64_decode(pub_key))

    def view_attestation(self, response):
        credential_id = response.get('id')
        raw_id = response.get('rawId')
        attestation_object = response.get('attObj')
        registrationClientExtensions = response.get('registrationClientExtensions')
        rce = json.loads(registrationClientExtensions)

        decoded_clientdata = _webauthn_b64_decode(response.get('clientData', '').decode('utf-8'))
        clientdata = json.loads(decoded_clientdata)

        att_obj = cbor2.loads(_webauthn_b64_decode(attestation_object))
        att_stmt = att_obj.get('attStmt', None)
        auth_data = att_obj.get('authData')
        fmt = att_obj.get('fmt')

        auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
        flags = struct.unpack('!B', auth_data[32])[0]
        flags_dict = []
        if (flags & USER_PRESENT) == 0x01:
            flags_dict.append('UP')
        if (flags & USER_VERIFIED) == 0x04:
            flags_dict.append('UV')
        if (flags & ATTESTATION_DATA_INCLUDED) == 0x40:
            flags_dict.append('AT')
        if (flags & EXTENSION_DATA_INCLUDED) == 0x80:
            flags_dict.append('ED')

        sc = auth_data[33:37]
        sign_count = struct.unpack('!I', sc)[0]

        attestation_data = auth_data[37:]
        aaguid = attestation_data[:16]
        credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
        cred_id = attestation_data[18:18 + credential_id_len]
        credential_pub_key = attestation_data[18 + credential_id_len:]

        cpk = cbor2.loads(credential_pub_key)

        credential_alg, public_key = _get_publickey(cpk)
        public_key_encoded = _encode_public_key(credential_alg, public_key)
        print(_webauthn_b64_encode(public_key_encoded))

        cpk_dict = {}
        for k, v in cpk.items():
            if(isinstance(v, str)):
                cpk_dict[k] = _webauthn_b64_encode(v)
            else:
                cpk_dict[k] = v

        if fmt == 'packed':
            alg = att_stmt['alg']
            signature = att_stmt['sig']
            if 'x5c' in att_stmt:
                x509_list = []
                for x5c in att_stmt.get('x5c'):
                    x509_list.append(load_der_x509_certificate(x5c, default_backend()))

            elif 'ecdaaKeyId' in att_stmt:
                ecdaaKeyId = att_stmt.get['ecdaaKeyId']

            else:  # Unknown fmt
                pass

            attStmt = {
                'alg' : alg,
                'sig' : _webauthn_b64_encode(signature)
            }
            if 'x5c' in att_stmt:
                attStmt['x5c'] = []
                for x5c in x509_list:
                    attStmt['x5c'].append(x5c.public_bytes(Encoding.PEM))
            elif 'ecdaaKeyId' in att_stmt:
                attStmt['ecdaaKeyId'] = _webauthn_b64_encode(ecdaaKeyId)

        elif fmt == 'tpm': #ver, alg, x5c or ecdaaKeyId, sig, certInfo, pubArea
            ver = att_stmt['ver']
            alg = att_stmt['alg']
            signature = att_stmt['sig']
            certInfo = att_stmt['certInfo']
            pubArea = att_stmt['pubArea']

            if 'x5c' in att_stmt:
                x509_list = []
                for x5c in att_stmt.get('x5c'):
                    x509_list.append(load_der_x509_certificate(x5c, default_backend()))

            elif 'ecdaaKeyId' in att_stmt:
                ecdaaKeyId = att_stmt.get['ecdaaKeyId']

            else:  # Unknown fmt
                pass

            attStmt = {
                'ver' : ver,
                'alg' : alg,
                'sig' : _webauthn_b64_encode(signature),
                'certInfo' : _webauthn_b64_encode(certInfo),
                'pubArea' : _webauthn_b64_encode(pubArea)
            }
            if 'x5c' in att_stmt:
                attStmt['x5c'] = []
                for x5c in x509_list:
                    attStmt['x5c'].append(x5c.public_bytes(Encoding.PEM))
            elif 'ecdaaKeyId' in att_stmt:
                attStmt['ecdaaKeyId'] = _webauthn_b64_encode(ecdaaKeyId)

        elif fmt == 'android-key': #alg, x5c, sig
            alg = att_stmt['alg']
            signature = att_stmt['sig']

            if 'x5c' in att_stmt:
                x509_list = []
                for x5c in att_stmt.get('x5c'):
                    x509_list.append(load_der_x509_certificate(x5c, default_backend()))

            attStmt = {
                'alg' : alg,
                'sig' : _webauthn_b64_encode(signature)
            }
            if 'x5c' in att_stmt:
                attStmt['x5c'] = []
                for x5c in x509_list:
                    attStmt['x5c'].append(x5c.public_bytes(Encoding.PEM))

        elif fmt == 'android-safetynet':
            api_ver = att_stmt['ver']
            api_response = att_stmt['response']

            res_header_encoded, res_payload_encoded, res_sig = api_response.split('.')
            res_header_decoded = _webauthn_b64_decode(res_header_encoded)
            res_payload_decoded = _webauthn_b64_decode(res_payload_encoded)

            attestation_type = AT_BASIC

            attStmt = {
                'ver' : api_ver,
                'response' : {'header': json.loads(res_header_decoded), 'payload': json.loads(res_payload_decoded), 'sig': res_sig}
            }
        
        elif fmt == 'fido-u2f': #sig, x5c
            signature = att_stmt['sig']
            x509_list = []
            for x5c in att_stmt.get('x5c'):
                x509_list.append(load_der_x509_certificate(x5c, default_backend()))

            attestation_type = AT_BASIC

            attStmt = {
                'sig' : _webauthn_b64_encode(signature)
            }
            if 'x5c' in att_stmt:
                attStmt['x5c'] = []
                for x5c in x509_list:
                    attStmt['x5c'].append(x5c.public_bytes(Encoding.PEM))

        elif fmt == 'none':
            attestation_type = AT_NONE

            attStmt = att_stmt
        else:
            attStmt = att_stmt

        att_dict = {
            'id' : credential_id,
            'rawId' : raw_id,
            "response" : {
                'clientDataJSON' : clientdata,
                'attestationObject' : {
                    'fmt' : fmt,
                    'authenticatorData' : {
                        'rpIdHashk' : _webauthn_b64_encode(auth_data_rp_id_hash),
                        'flags' : flags_dict,
                        'signCount' : sign_count,
                        'attestedCredentialData' : {
                            'aaguid' : codecs.encode(aaguid, 'hex_codec'),
                            'credentialIdLength' : credential_id_len,
                            'credentialId' : _webauthn_b64_encode(cred_id),
                            'credentialPublicKey' : cpk_dict
                        },
                        'extensions' : rce
                    }
                }
            }
        }
        if attStmt is not None:
            att_dict['response']['attestationObject']['attStmt'] = attStmt

        return att_dict
    
    def view_assertion(self, response):
        credential_id = response.get('id')
        raw_id = response.get('rawId')
        user_handle = response.get('userHandle', '')
        sig = response.get('signature').decode('hex')
        assertion_client_extensions = response.get('assertionClientExtensions', '{}')
        ace = json.loads(assertion_client_extensions)
        
        decoded_clientdata = _webauthn_b64_decode(response.get('clientData', '').decode('utf-8'))
        clientdata = json.loads(decoded_clientdata)

        auth_data = response.get('authData')
        decoded_auth_data = _webauthn_b64_decode(auth_data)
        
        auth_data_rp_id_hash = _get_auth_data_rp_id_hash(decoded_auth_data)
        flags = struct.unpack('!B', decoded_auth_data[32])[0]
        flags_dict = []
        if (flags & USER_PRESENT) == 0x01:
            flags_dict.append('UP')
        if (flags & USER_VERIFIED) == 0x04:
            flags_dict.append('UV')
        if (flags & ATTESTATION_DATA_INCLUDED) == 0x40:
            flags_dict.append('AT')
        if (flags & EXTENSION_DATA_INCLUDED) == 0x80:
            flags_dict.append('ED')

        sc = decoded_auth_data[33:37]
        sign_count = struct.unpack('!I', sc)[0]

        return {
            'id' : credential_id,
            'rawId' : raw_id,
            "response" : {
                'clientDataJSON' : clientdata,
                'authenticatorData' : {
                    'rpIdHash' : _webauthn_b64_encode(auth_data_rp_id_hash),
                    'flags' : flags_dict,
                    'signCount' : sign_count,
                    'extensions' : ace
                },
                'signature' : _webauthn_b64_encode(sig),
                'userHandle' : user_handle
            }
        }


class WebAuthnOptions(object):

    SUPPORTED_CONVEYANCE_PREFARENCE = (
        '',                  # 'not set'
        'none',
        'indirect',
        'direct',
    )
    SUPPORTED_AUTHENTICATIONSELECTION_USERVERIFICATION = (
        '',                  # 'not set'
        'required',
        'preferred',
        'discouraged',
    )
    SUPPORTED_REQUIRE_REDIDENTKEY = (
        '',                  # 'not set'
        'true',
        'false',
    )
    SUPPORTED_AUTHENTICATIONSELECTION_ATTACHIMENT = (
        '',                  # 'not set'
        'cross-platform',
        'platform',
    )
    SUPPORTED_TRANSPORTS = (
        '',                  # 'not set'
        'usb',
        'nfc',
        'ble',
        'internal',
    )
    SUPPORTED_ENABLE_CREDENTIALS = (
        'true',
        'false',
    )

    def __init__(self):
        self.settings = {                            # Initial Data.
            'attestation' : {
                'conveyancePreference': '',          # 'none', 'indirect', 'direct'
                'authenticatorSelection': {
                    'userVerification': '',          # 'required', 'preferred', 'discouraged'
                    'requireResidentKey': '',        # 'true', 'false'
                    'authenticatorAttachment': ''    # 'cross-platform', 'platform'
                },
                'excludeCredentials': {
                    'enabled': '',                     # 'true', 'false'
                    'id': [],
                    'transports': []                   # 'usb', 'nfc', 'ble', 'internal'
                },
                'extensions': {}
            },
            'assertion' : {
                'allowCredentials': {
                    'enabled': '',                     # 'true', 'false'
                    'id': [],
                    'transports': []                   # 'usb', 'nfc', 'ble', 'internal'
                },
                'extensions': {}
            }
        }
    
    def get(self):
        return self.settings

    def set(self, content):
        # TODO: check tree-structure in detail.
        try:
            self.settings = content
        except Exception as e:
            raise CommonRejectedException('Options Setting Error: {} .'.format(e))


    @property
    def conveyancePreference(self):
        return self.settings.get('attestation', {}).get('conveyancePreference', '')
    @conveyancePreference.setter
    def conveyancePreference(self, val):
        if val not in self.SUPPORTED_CONVEYANCE_PREFARENCE:
            raise CommonRejectedException('Option Selection Error (conveyancePreference).')
        if 'attestation' in self.settings:
            if 'conveyancePreference' in self.settings['attestation']:
                self.settings['attestation']['conveyancePreference'] = val
            else:
                raise CommonRejectedException('Dictionary broken Error (conveyancePreference).')
        else:
            raise CommonRejectedException('Dictionary broken Error (conveyancePreference).')

    @property
    def userVerification(self):
        return self.settings.get('attestation', {}).get('authenticatorSelection', {}).get('userVerification', '')
    @userVerification.setter
    def userVerification(self, val):
        if val not in self.SUPPORTED_AUTHENTICATIONSELECTION_USERVERIFICATION:
            raise CommonRejectedException('Option Selection Error (userVerification).')
        if 'attestation' in self.settings:
            if 'authenticatorSelection' in self.settings['attestation']:
                if 'userVerification' in self.settings['attestation']['authenticatorSelection']:
                    self.settings['attestation']['authenticatorSelection']['userVerification'] = val
                else:
                    raise CommonRejectedException('Dictionary broken Error (userVerification).')
            else:
                raise CommonRejectedException('Dictionary broken Error (userVerification).')
        else:
            raise CommonRejectedException('Dictionary broken Error (userVerification).')
    
    @property
    def requireResidentKey(self):
        return self.settings.get('attestation', {}).get('authenticatorSelection', {}).get('requireResidentKey', '')
    @requireResidentKey.setter
    def requireResidentKey(self, val):
        if val not in self.SUPPORTED_REQUIRE_REDIDENTKEY:
            raise CommonRejectedException('Option Type Error (requireResidentKey).')
        if 'attestation' in self.settings:
            if 'authenticatorSelection' in self.settings['attestation']:
                if 'requireResidentKey' in self.settings['attestation']['authenticatorSelection']:
                    self.settings['attestation']['authenticatorSelection']['requireResidentKey'] = val
                else:
                    raise CommonRejectedException('Dictionary broken Error (requireResidentKey).')
            else:
                raise CommonRejectedException('Dictionary broken Error (requireResidentKey).')
        else:
            raise CommonRejectedException('Dictionary broken Error (requireResidentKey).')
    
    @property
    def authenticatorAttachment(self):
        return self.settings.get('attestation', {}).get('authenticatorSelection', {}).get('authenticatorAttachment', '')
    @authenticatorAttachment.setter
    def authenticatorAttachment(self, val):
        if val not in self.SUPPORTED_AUTHENTICATIONSELECTION_ATTACHIMENT:
            raise CommonRejectedException('Option Selection Error (authenticatorAttachment).')
        if 'attestation' in self.settings:
            if 'authenticatorSelection' in self.settings['attestation']:
                if 'authenticatorAttachment' in self.settings['attestation']['authenticatorSelection']:
                    self.settings['attestation']['authenticatorSelection']['authenticatorAttachment'] = val
                else:
                    raise CommonRejectedException('Dictionary broken Error (authenticatorAttachment).')
            else:
                raise CommonRejectedException('Dictionary broken Error (authenticatorAttachment).')
        else:
            raise CommonRejectedException('Dictionary broken Error (authenticatorAttachment).')
    
    @property
    def enableAttestationExcludeCredentials(self):
        return self.settings.get('attestation', {}).get('excludeCredentials', {}).get('enabled', '')
    @enableAttestationExcludeCredentials.setter
    def enableAttestationExcludeCredentials(self, val):
        if val not in self.SUPPORTED_ENABLE_CREDENTIALS:
            raise CommonRejectedException('Option Type Error (enableAttestationExcludeCredentials).')
        if 'attestation' in self.settings:
            if 'excludeCredentials' in self.settings['attestation']:
                if 'enabled' in self.settings['attestation']['excludeCredentials']:
                    self.settings['attestation']['excludeCredentials']['enabled'] = val
                else:
                    raise CommonRejectedException('Dictionary broken Error (enableAttestationExcludeCredentials).')
            else:
                raise CommonRejectedException('Dictionary broken Error (enableAttestationExcludeCredentials).')
        else:
            raise CommonRejectedException('Dictionary broken Error (enableAttestationExcludeCredentials).')

    @property
    def attestationExcludeCredentialsUsers(self):
        return self.settings.get('attestation', {}).get('excludeCredentials', {}).get('id', [])
    @attestationExcludeCredentialsUsers.setter
    def attestationExcludeCredentialsUsers(self, val):
        if type(val) != list:
            raise CommonRejectedException('Option Type Error (attestationExcludeCredentialsUsers).')
        if str(re.sub(r'\d', '', ''.join(val))) != '':
            raise CommonRejectedException('Option Selection Error (attestationExcludeCredentialsUsers).')
        if 'attestation' in self.settings:
            if 'excludeCredentials' in self.settings['attestation']:
                if 'id' in self.settings['attestation']['excludeCredentials']:
                    self.settings['attestation']['excludeCredentials']['id'] = [] if (len(val) == 1 and val[0] == '') else val
                else:
                    raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsUsers).')
            else:
                raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsUsers).')
        else:
            raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsUsers).')

    @property
    def attestationExcludeCredentialsTransports(self):
        return self.settings.get('attestation', {}).get('excludeCredentials', {}).get('transports', [])
    @attestationExcludeCredentialsTransports.setter
    def attestationExcludeCredentialsTransports(self, val):
        if type(val) != list:
            raise CommonRejectedException('Option Type Error (attestationExcludeCredentialsTransports).')
        if not set(val).issubset(self.SUPPORTED_TRANSPORTS):
            raise CommonRejectedException('Option Selection Error (attestationExcludeCredentialsTransports).')
        if 'attestation' in self.settings:
            if 'excludeCredentials' in self.settings['attestation']:
                if 'transports' in self.settings['attestation']['excludeCredentials']:
                    self.settings['attestation']['excludeCredentials']['transports'] = [] if (len(val) == 1 and val[0] == '') else val
                else:
                    raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsTransports).')
            else:
                raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsTransports).')
        else:
            raise CommonRejectedException('Dictionary broken Error (attestationExcludeCredentialsTransports).')

    @property
    def attestationExtensions(self):
        return self.settings.get('attestation', {}).get('extensions', {})
    @attestationExtensions.setter
    def attestationExtensions(self, val):
        if type(val) != dict:
            raise CommonRejectedException('Option Type Error (attestationExtensions).')
        if 'attestation' in self.settings:
            if 'extensions' in self.settings['attestation']:
                self.settings['attestation']['extensions'] = val
            else:
                raise CommonRejectedException('Dictionary broken Error (attestationExtensions).')
        else:
            raise CommonRejectedException('Dictionary broken Error (attestationExtensions).')

    @property
    def enableAssertionAllowCredentials(self):
        return self.settings.get('assertion', {}).get('allowCredentials', {}).get('enabled', '')
    @enableAssertionAllowCredentials.setter
    def enableAssertionAllowCredentials(self, val):
        if val not in self.SUPPORTED_ENABLE_CREDENTIALS:
            raise CommonRejectedException('Option Type Error (enableAssertionAllowCredentials).')
        if 'assertion' in self.settings:
            if 'allowCredentials' in self.settings['assertion']:
                if 'enabled' in self.settings['assertion']['allowCredentials']:
                    self.settings['assertion']['allowCredentials']['enabled'] = val
                else:
                    raise CommonRejectedException('Dictionary broken Error (enableAssertionAllowCredentials).')
            else:
                raise CommonRejectedException('Dictionary broken Error (enableAssertionAllowCredentials).')
        else:
            raise CommonRejectedException('Dictionary broken Error (enableAssertionAllowCredentials).')

    @property
    def assertionAllowCredentialsUsers(self):
        return self.settings.get('assertion', {}).get('allowCredentials', {}).get('id', [])
    @assertionAllowCredentialsUsers.setter
    def assertionAllowCredentialsUsers(self, val):
        if type(val) != list:
            raise CommonRejectedException('Option Type Error (assertionAllowCredentialsUsers).')
        if re.sub(r'\d', '', ''.join(val)).encode() != '':
            raise CommonRejectedException('Option Selection Error (assertionAllowCredentialsUsers).')
        if 'assertion' in self.settings:
            if 'allowCredentials' in self.settings['assertion']:
                if 'id' in self.settings['assertion']['allowCredentials']:
                    self.settings['assertion']['allowCredentials']['id'] = [] if (len(val) == 1 and val[0] == '') else val
                else:
                    raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsUsers).')
            else:
                raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsUsers).')
        else:
            raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsUsers).')

    @property
    def assertionAllowCredentialsTransports(self):
        return self.settings.get('assertion', {}).get('allowCredentials', {}).get('transports', [])
    @assertionAllowCredentialsTransports.setter
    def assertionAllowCredentialsTransports(self, val):
        if type(val) != list:
            raise CommonRejectedException('Option Type Error (assertionAllowCredentialsTransports).')
        if not set(val).issubset(self.SUPPORTED_TRANSPORTS):
            raise CommonRejectedException('Option Selection Error (assertionAllowCredentialsTransports).')
        if 'assertion' in self.settings:
            if 'allowCredentials' in self.settings['assertion']:
                if 'transports' in self.settings['assertion']['allowCredentials']:
                    self.settings['assertion']['allowCredentials']['transports'] = [] if (len(val) == 1 and val[0] == '') else val
                else:
                    raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsTransports).')
            else:
                raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsTransports).')
        else:
            raise CommonRejectedException('Dictionary broken Error (assertionAllowCredentialsTransports).')

    @property
    def assertionExtensions(self):
        return self.settings.get('assertion', {}).get('extensions', {})
    @assertionExtensions.setter
    def assertionExtensions(self, val):
        if type(val) != dict:
            raise CommonRejectedException('Option Type Error (assertionExtensions).')
        if 'assertion' in self.settings:
            if 'extensions' in self.settings['assertion']:
                self.settings['assertion']['extensions'] = val
            else:
                raise CommonRejectedException('Dictionary broken Error (assertionExtensions).')
        else:
            raise CommonRejectedException('Dictionary broken Error (assertionExtensions).')


class WebAuthnMakeCredentialOptions(object):

    def __init__(self,
                webauthn_options,
                credentialid_list,
                challenge,
                rp_name,
                rp_id,
                user_id,
                username,
                display_name,
                icon_url):
        self.webauthn_options = webauthn_options,
        self.credentialid_list = credentialid_list,
        self.challenge = challenge
        self.rp_name = rp_name
        self.rp_id = rp_id
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url

    @property
    def registration_dict(self):
        if not self.challenge:
            raise RegistrationRejectedException('Invalid challenge.')

        registration_dict = {
            'challenge': self.challenge,
            'rp': {
                'name': self.rp_name,
                'id': self.rp_id
            },
            'user': {
                'id': self.user_id,
                'name': self.username,
                'displayName': self.display_name,
                'icon': self.icon_url
            },
            'pubKeyCredParams': [
                {
                    'alg': -257,                                # RS256
                    'type': 'public-key',
                },
                {
                    'alg': -7,                                  # ES256
                    'type': 'public-key',
                },
                {"type":"public-key","alg":-37},
                {"type":"public-key","alg":-35},
                {"type":"public-key","alg":-258},
                {"type":"public-key","alg":-38},
                {"type":"public-key","alg":-36},
                {"type":"public-key","alg":-259},
                {"type":"public-key","alg":-39},
                {"type":"public-key","alg":-65535}
            ],
            'timeout': 60000,  # 1 min.
        }

        if self.webauthn_options[0].conveyancePreference != '':
            registration_dict['attestation'] = self.webauthn_options[0].conveyancePreference
        if self.webauthn_options[0].userVerification != '' or self.webauthn_options[0].requireResidentKey != '' or self.webauthn_options[0].authenticatorAttachment != '':
            registration_dict['authenticatorSelection'] = {}
            if self.webauthn_options[0].userVerification != '':
                registration_dict['authenticatorSelection']['userVerification'] = self.webauthn_options[0].userVerification
            if self.webauthn_options[0].requireResidentKey != '':
                registration_dict['authenticatorSelection']['requireResidentKey'] = self.webauthn_options[0].requireResidentKey
            if self.webauthn_options[0].authenticatorAttachment != '':
                registration_dict['authenticatorSelection']['authenticatorAttachment'] = self.webauthn_options[0].authenticatorAttachment

        exclude_cred_list = []
        for credid in self.credentialid_list[0]:
            tmp_dict = {
                'type': 'public-key',
                'id': credid
            }
            if self.webauthn_options[0].attestationExcludeCredentialsTransports != []:
                tmp_dict['transports'] = self.webauthn_options[0].attestationExcludeCredentialsTransports
            exclude_cred_list.append(tmp_dict)
        registration_dict['excludeCredentials'] = exclude_cred_list

        if self.webauthn_options[0].attestationExtensions != {}:
            registration_dict['extensions'] = self.webauthn_options[0].attestationExtensions

        return registration_dict

    @property
    def json(self):
        return json.dumps(self.registration_dict)


class WebAuthnAssertionOptions(object):

    def __init__(self, webauthn_options, credentialid_list, challenge, rp_id):
        self.webauthn_options = webauthn_options
        self.credentialid_list = credentialid_list
        self.challenge = challenge
        self.rp_id = rp_id

    @property
    def assertion_dict(self):
        if not self.challenge:
            raise AuthenticationRejectedException('Invalid challenge.')
        if not isinstance(self.credentialid_list, list):
            raise AuthenticationRejectedException('Invalid user type.')

        assertion_dict = {
            'challenge': self.challenge,
            'timeout': 60000,  # 1 min.
            'rpId': self.rp_id
        }

        allow_cred_list = []

        for credid in self.credentialid_list:
            tmp_dict = {
                'type': 'public-key',
                'id': credid
            }
            if self.webauthn_options.assertionAllowCredentialsTransports != []:
                tmp_dict['transports'] = self.webauthn_options.assertionAllowCredentialsTransports
            allow_cred_list.append(tmp_dict)
        assertion_dict['allowCredentials'] = allow_cred_list

        if self.webauthn_options.assertionExtensions != {}:
            assertion_dict['extensions'] = self.webauthn_options.assertionExtensions

        return assertion_dict

    @property
    def json(self):
        return json.dumps(self.assertion_dict)


class WebAuthnUser(object):

    def __init__(self,
                 user_id,
                 username,
                 display_name,
                 icon_url,
                 credential_id,
                 public_key,
                 sign_count,
                 rp_id):
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.rp_id = rp_id

    def __str__(self):
        return '{} ({}, {}, {})'.format(
            self.user_id,
            self.username,
            self.display_name,
            self.sign_count)


class WebAuthnCredential(object):

    def __init__(self,
                 rp_id,
                 origin,
                 credential_id,
                 public_key,
                 sign_count,
                 fmt,
                 attestation_type,
                 attestation_flags):
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.fmt = fmt
        self.attestation_type = attestation_type
        self.attestation_flags = attestation_flags

    def __str__(self):
        return '{} ({}, {}, {})'.format(
            self.credential_id,
            self.rp_id,
            self.origin,
            self.sign_count)


class WebAuthnRegistrationResponse(object):

    def __init__(self,
                 rp_id,
                 origin,
                 registration_response,
                 challenge,
                 trust_anchor_dir=DEFAULT_TRUST_ANCHOR_DIR,
                 trusted_attestation_cert_required=False,
                 self_attestation_permitted=False,
                 none_attestation_permitted=False,
                 uv_required=False):
        self.rp_id = rp_id
        self.origin = origin
        self.registration_response = registration_response
        self.challenge = challenge
        self.trust_anchor_dir = trust_anchor_dir
        self.trusted_attestation_cert_required = trusted_attestation_cert_required
        self.uv_required = uv_required

        # With self attestation, the credential public key is
        # also used as the attestation public key.
        self.self_attestation_permitted = self_attestation_permitted

        # `none` AttestationConveyancePreference
        # Replace potentially uniquely identifying information
        # (such as AAGUID and attestation certificates) in the
        # attested credential data and attestation statement,
        # respectively, with blinded versions of the same data.
        # **Note**: If True, authenticator attestation will not
        #           be performed.
        self.none_attestation_permitted = none_attestation_permitted

        self.logger = WebAuthnLogger()

    def getLog(self):
        return self.logger.get()

    def _verify_attestation_statement(self, fmt, att_stmt, auth_data, client_data_hash):
        '''Verification procedure: The procedure for verifying an attestation statement,
        which takes the following verification procedure inputs:

            * attStmt: The attestation statement structure
            * authenticatorData: The authenticator data claimed to have been used for
                                 the attestation
            * clientDataHash: The hash of the serialized client data

        The procedure returns either:

            * An error indicating that the attestation is invalid, or
            * The attestation type, and the trust path. This attestation trust path is
              either empty (in case of self attestation), an identifier of an ECDAA-Issuer
              public key (in the case of ECDAA), or a set of X.509 certificates.

        TODO:
        Verification of attestation objects requires that the Relying Party has a trusted
        method of determining acceptable trust anchors in step 15 above. Also, if
        certificates are being used, the Relying Party MUST have access to certificate
        status information for the intermediate CA certificates. The Relying Party MUST
        also be able to build the attestation certificate chain if the client did not
        provide this chain in the attestation information.
        '''
        logger.debug('----- [Registration] [Verify_AttStmt] Start -----')
        logger.debug('Stmt fmt=' + fmt)

        if fmt == 'packed':
            # Step 1.
            if 'x5c' in att_stmt: # Basic
                logger.debug('packed AttStmtFmt: x5c/Basic')
                
                # Step 1-1.
                # Get crtificate's publickey.
                att_cert = att_stmt.get('x5c')[0]
                x509_att_cert = load_der_x509_certificate(att_cert, default_backend())
                certificate_public_key = x509_att_cert.public_key()
                if not isinstance(certificate_public_key.curve, SECP256R1):
                    logger.debug('Bad certificate public key.')
                    raise RegistrationRejectedException('Bad certificate public key.')
                alg_type = None
                if isinstance(certificate_public_key, EllipticCurvePublicKey):
                    alg_type = COSE_ALG_ES256
                elif isinstance(certificate_public_key, RSAPublicKey):
                    alg_type = COSE_ALG_RS256
                else:
                    logger.debug('Bad certificate public key.')
                    raise RegistrationRejectedException('Bad certificate public key.')

                # Step 1-2.
                # Verify signature by certificate's publickey.
                alg = att_stmt['alg']
                signature = att_stmt['sig']
                verification_data = ''.join([
                    auth_data,
                    client_data_hash ])

                if alg not in [COSE_ALG_ES256, COSE_ALG_RS256]:
                    raise RegistrationRejectedException('Invalid algorithm of x5c certificate.')
                try:
                    _verify_signature(alg, signature, verification_data, certificate_public_key)
                except InvalidSignature:
                    logger.debug('Invalid signature received.')
                    raise RegistrationRejectedException('Invalid signature received.')

                # Step 1-3.
                #
                #  If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
                #  verify that the value of this extension matches the aaguid in authenticatorData.
                attestation_data = auth_data[37:]
                aaguid = attestation_data[:16]

                try:
                    cert_attrib_value = x509_att_cert.extensions.get_extension_for_oid(ObjectIdentifier(OID_AAGUID)).value.value
                    if len(cert_attrib_value) == 18:  # Wrapped strings is added in first block('\x04\x10'). Refer at 8.2.1
                        cert_attrib_value = cert_attrib_value[2:]
                    elif len(cert_attrib_value) != 16:
                        logger.debug('Certificate attribute value length is not 16bytes.')
                        raise RegistrationRejectedException('Certificate attribute value length is not 16bytes.')
                    if codecs.encode(cert_attrib_value, 'hex_codec') != codecs.encode(aaguid, 'hex_codec'):
                        logger.debug('Certificate attribute value is not match to AAGUID.')
                        raise RegistrationRejectedException('Certificate attribute value is not match to AAGUID.')
                except Exception as e:
                    logger.debug('Certificate verify failed. Error: {}'.format(e))
                    raise e

                # Step 1-4.
                #
                # If successful, return attestation type Basic with the
                # attestation trust path set to x5c.
                credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
                cred_id = attestation_data[18:18 + credential_id_len]
                credential_pub_key = attestation_data[18 + credential_id_len:]
                cpk = cbor2.loads(credential_pub_key)

                credential_alg, public_key = _get_publickey(cpk)
                public_key_encoded = _encode_public_key(credential_alg, public_key)

                attestation_type = AT_BASIC
                trust_path = [x509_att_cert]
                return (attestation_type, trust_path, public_key_encoded, cred_id)

            # Step 2.
            elif 'ecdaaKeyId' in att_stmt: # ECDAA
                logger.debug('packed AttStmtFmt: ecdaaKeyId/ECDAA')

                logger.debug('Unsupported packed semantic (ECDAA), However It regard as fmt=\'none\'.')

                fmt = 'packed-ecdaa'

            # Step 3.
            else:  # Self
                logger.debug('packed AttStmtFmt: nor/Self')
                # Step 3-1.
                #
                # Get statement's algorithm and signature.
                alg = att_stmt['alg']
                if alg not in [COSE_ALG_ES256, COSE_ALG_RS256]:
                    logger.debug('Unsupported algorithm ({}).'.format(alg))
                    raise RegistrationRejectedException('Unsupported algorithm.')
                signature = att_stmt['sig']

                # Step 3-2.
                #
                # Check credential's algorithm type as one in authenticatorData.
                attestation_data = auth_data[37:]
                credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
                cred_id = attestation_data[18:18 + credential_id_len]
                credential_pub_key = attestation_data[18 + credential_id_len:]
                cpk = cbor2.loads(credential_pub_key)

                if cpk[COSE_KEYNAME_ALG] != COSE_ALG_ES256 and cpk[COSE_KEYNAME_ALG] != COSE_ALG_RS256:
                    logger.debug('Unsupported algorithm.')
                    raise RegistrationRejectedException('Unsupported algorithm.')
                if cpk[COSE_KEYNAME_ALG] != alg:
                    logger.debug('Unmatch algorithm as authenticatorData.')
                    raise RegistrationRejectedException('Unmatch algorithm as authenticatorData.')
                
                # Step 3-2.
                #
                # Verify sig by credential publickey.
                credential_alg, public_key = _get_publickey(cpk)
                public_key_encoded = _encode_public_key(credential_alg, public_key)

                verification_data = ''.join([
                    auth_data,
                    client_data_hash ])

                try:
                    _verify_signature(credential_alg, signature, verification_data, public_key)
                except InvalidSignature:
                    logger.debug('Invalid signature received.')
                    raise RegistrationRejectedException('Invalid signature received.')

                attestation_type = AT_SELF_ATTESTATION
                trust_path = []
                return (attestation_type, trust_path, public_key_encoded, cred_id)

        elif fmt == 'android-safetynet': # Basic
            # Step 1.
            #
            # Get and decode JWS response.
            api_ver = att_stmt['ver']
            api_response = att_stmt['response']

            res_header_encoded, res_payload_encoded, res_sig = api_response.split('.')
            res_header_decoded = _webauthn_b64_decode(res_header_encoded)
            res_payload_decoded = _webauthn_b64_decode(res_payload_encoded)
            res_sig_decoded = _webauthn_b64_decode(res_sig)

            res_header = json.loads(res_header_decoded)
            res_payload = json.loads(res_payload_decoded)

            attestation_data = auth_data[37:]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            credential_pub_key = attestation_data[18 + credential_id_len:]
            cpk = cbor2.loads(credential_pub_key)
            credential_alg, public_key = _get_publickey(cpk)
            public_key_encoded = _encode_public_key(credential_alg, public_key)

            # Step 2.
            #
            # Verify that response is a valid SafetyNet response of version ver.
            # TODO: What's mean?

            # Step 3.
            #
            # Verify that the nonce in the response is identical to 
            # the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
            verification_data = ''.join([
                    auth_data,
                    client_data_hash ])
            hash = base64.b64encode(hashlib.sha256(verification_data).digest())
            if res_payload.get('nonce') != hash:
                logger.debug('Invalid nonce hash.')
                raise RegistrationRejectedException('Invalid nonce hash.')

            # Step 4.
            #
            # Verify that the attestation certificate is issued to the hostname "attest.android.com"
            if 'x5c' not in res_header or 'alg' not in res_header:
                logger.debug('Attestation statement must be a valid CBOR object.')
                raise RegistrationRejectedException('Attestation statement must be a valid CBOR object.')
            
            certs = []
            
            for att_cert in res_header.get('x5c'):
                x509_att_cert = load_der_x509_certificate(base64.b64decode(att_cert), default_backend())
                certs.append(x509_att_cert)
            if len(certs) == 0:
                logger.debug('No X.509 certs available.')
                raise RegistrationRejectedException('No X.509 certs available.')
            
            success = False 
            for crt in certs:
                for attr in crt.subject:
                    if attr.oid.dotted_string == '2.5.4.3' and attr.value == 'attest.android.com':
                        certificate_public_key = crt.public_key()
                        verification_data = ''.join([res_header_encoded, '.', res_payload_encoded])
                        certificate_alg = COSE_ALG_ES256 if res_header['alg'] == COSE_ALGLABEL_ES256 else (COSE_ALG_RS256 if res_header['alg'] == COSE_ALGLABEL_RS256 else '')
                        try:
                            _verify_signature(certificate_alg, res_sig_decoded, verification_data, certificate_public_key)
                            success = True
                            break
                        except InvalidSignature:
                            logger.debug('Invalid certificate\'s signature received.')
                            raise RegistrationRejectedException('Invalid certificate\'s signature received.')
                if success:
                    break
            if success == False:
                logger.debug('Cannot valid certificate\'s signature.')
                raise RegistrationRejectedException('Cannot valid certificate\'s signature.')

            # Step 5.
            #
            # Verify that the ctsProfileMatch attribute in the payload of response is true.
            if res_payload.get('ctsProfileMatch') == False:
                logger.debug('ctsProfileMatch is not True.')
                raise RegistrationRejectedException('ctsProfileMatch is not True.')

            attestation_type = AT_BASIC
            trust_path = certs
            return (attestation_type, trust_path, public_key_encoded, cred_id)

        elif fmt == 'fido-u2f':
            # Step 1.
            #
            # Verify that attStmt is valid CBOR conforming to the syntax
            # defined above and perform CBOR decoding on it to extract the
            # contained fields.
            if 'x5c' not in att_stmt or 'sig' not in att_stmt:
                logger.debug('Attestation statement must be a valid CBOR object.')
                raise RegistrationRejectedException('Attestation statement must be a valid CBOR object.')

            # Step 2.
            #
            # Let attCert be the value of the first element of x5c. Let certificate
            # public key be the public key conveyed by attCert. If certificate public
            # key is not an Elliptic Curve (EC) public key over the P-256 curve,
            # terminate this algorithm and return an appropriate error.
            att_cert = att_stmt.get('x5c')[0]
            x509_att_cert = load_der_x509_certificate(att_cert, default_backend())
            certificate_public_key = x509_att_cert.public_key()
            if not isinstance(certificate_public_key.curve, SECP256R1):
                logger.debug('Bad certificate public key.')
                raise RegistrationRejectedException('Bad certificate public key.')

            # Step 3.
            #
            # Extract the claimed rpIdHash from authenticatorData, and the
            # claimed credentialId and credentialPublicKey from
            # authenticatorData.attestedCredentialData.
            attestation_data = auth_data[37:]
            aaguid = attestation_data[:16]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            credential_pub_key = attestation_data[18 + credential_id_len:]

            # The credential public key encoded in COSE_Key format, as defined in Section 7
            # of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded
            # credential public key MUST contain the optional "alg" parameter and MUST NOT
            # contain any other optional parameters. The "alg" parameter MUST contain a
            # COSEAlgorithmIdentifier value. The encoded credential public key MUST also
            # contain any additional required parameters stipulated by the relevant key type
            # specification, i.e., required for the key type "kty" and algorithm "alg" (see
            # Section 8 of [RFC8152]).
            cpk = cbor2.loads(credential_pub_key)

            credential_alg, public_key = _get_publickey(cpk)
            public_key_encoded = _encode_public_key(credential_alg, public_key)

            # Step 5.
            #
            # Let verificationData be the concatenation of (0x00 || rpIdHash ||
            # clientDataHash || credentialId || publicKeyU2F) (see Section 4.3
            # of [FIDO-U2F-Message-Formats]).
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            signature = att_stmt['sig']
            verification_data = ''.join([
                '\0',
                auth_data_rp_id_hash,
                client_data_hash,
                cred_id,
                public_key_encoded])

            # Step 6.
            #
            # Verify the sig using verificationData and certificate public
            # key per [SEC1].
            try:
                _verify_signature(credential_alg, signature, verification_data, certificate_public_key)
            except InvalidSignature:
                logger.debug('Invalid signature received.')
                raise RegistrationRejectedException('Invalid signature received.')

            # Step 7.
            #
            # If successful, return attestation type Basic with the
            # attestation trust path set to x5c.
            attestation_type = AT_BASIC
            trust_path = [x509_att_cert]
            return (attestation_type, trust_path, public_key_encoded, cred_id)

        elif fmt == 'tpm':
            if 'x5c' in att_stmt: # AttCA
                logger.debug('tpm AttStmtFmt: x5c/AttCA')
                fmt = 'tpm-attca'
            elif 'ecdaaKeyId' in att_stmt: # ECDAA
                logger.debug('tpm AttStmtFmt: ecdaaKeyId/ECDAA')
                logger.debug('Unsupported packed semantic (ECDAA), However It regard as fmt=\'none\'.')

                fmt = 'tpm-ecdaa'

        # Unsupported format regards as 'none'.
        if not(fmt == 'packed' or fmt == 'android-safetynet' or fmt == 'fido-u2f'):
            # `none` - indicates that the Relying Party is not interested in
            # authenticator attestation.

            if not self.none_attestation_permitted:
                logger.debug('Authenticator attestation is required.')
                raise RegistrationRejectedException('Authenticator attestation is required.')

            attestation_data = auth_data[37:]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            credential_pub_key = attestation_data[18 + credential_id_len:]

            cpk = cbor2.loads(credential_pub_key)

            credential_alg, public_key = _get_publickey(cpk)
            public_key_encoded = _encode_public_key(credential_alg, public_key)

            # Step 1.
            #
            # Return attestation type None with an empty trust path.
            if fmt == 'none':
                attestation_type = AT_NONE
            elif fmt == 'packed-ecdaa':
                attestation_type = AT_ECDAA
            elif fmt == 'android-key':
                attestation_type = AT_BASIC
            elif fmt == 'tpm-attca':
                attestation_type = AT_ATTESTATION_CA
            elif fmt == 'tpm-ecdaa':
                attestation_type = AT_ECDAA
            else:
                attestation_type = AT_OTHER
            trust_path = []
            return (attestation_type, trust_path, public_key_encoded, cred_id)
        else:
            logger.debug('Invalid format.')
            raise RegistrationRejectedException('Invalid format.')
        logger.debug('----- [Registration] [Verify_AttStmt] End -----')

    def verify(self):
        try:
            # Step 1.
            #
            # Let JSONtext be the result of running UTF-8 decode on the value of
            # response.clientDataJSON.
            logger.debug('----- [Registration] [Verify:Step1/2] Parse Posted FormData. -----')
            u8_clientdata = self.registration_response.get('clientData', '').decode('utf-8')

            # Step 2.
            #
            # Let C, the client data claimed as collected during the credential
            # creation, be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(u8_clientdata)
            c = json.loads(decoded_cd)

            attestation_object = self.registration_response.get('attObj')

            # Step 3.
            #
            # Verify that the value of C.type is webauthn.create.
            logger.debug('----- [Registration] [Verify:Step3] Verify "type" value. -----')
            received_type = c.get('type')
            if not _verify_type(received_type, TYPE_CREATE):
                logger.debug('Invalid type.')
                raise RegistrationRejectedException('Invalid type.')

            # Step 4.
            #
            # Verify that the value of C.challenge matches the challenge that was sent
            # to the authenticator in the create() call.
            logger.debug('----- [Registration] [Verify:Step4] Verify "challenge" value. -----')
            received_challenge = c.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                logger.debug('Unable to verify challenge.')
                raise RegistrationRejectedException('Unable to verify challenge.')

            # Step 5.
            #
            # Verify that the value of C.origin matches the Relying Party's origin.
            logger.debug('----- [Registration] [Verify:Step5] Verify "origin" value. -----')
            if not _verify_origin(c, self.origin):
                logger.debug('Unable to verify origin.')
                raise RegistrationRejectedException('Unable to verify origin.')

            # Step 6.
            #
            # Verify that the value of C.tokenBinding.status matches the state of
            # Token Binding for the TLS connection over which the assertion was
            # obtained. If Token Binding was used on that TLS connection, also verify
            # that C.tokenBinding.id matches the base64url encoding of the Token
            # Binding ID for the connection.
            logger.debug('----- [Registration] [Verify:Step6] Verify binding ID. (Ignored) -----')
            #if not _verify_token_binding_id(c):
            #    raise RegistrationRejectedException('Unable to verify token binding ID.')

            # Step 7.
            #
            # Compute the hash of response.clientDataJSON using SHA-256.
            logger.debug('----- [Registration] [Verify:Step7] Compute ClientData Hash value. -----')
            client_data_hash = _get_client_data_hash(decoded_cd)

            # Step 8.
            #
            # Perform CBOR decoding on the attestationObject field of
            # the AuthenticatorAttestationResponse structure to obtain
            # the attestation statement format fmt, the authenticator
            # data authData, and the attestation statement attStmt.
            logger.debug('----- [Registration] [Verify:Step8] Parse AttestationObject. -----')
            att_obj = cbor2.loads(_webauthn_b64_decode(attestation_object))
            att_stmt = att_obj.get('attStmt')
            auth_data = att_obj.get('authData')
            fmt = att_obj.get('fmt')
            if not auth_data or len(auth_data) < 37:
                logger.debug('Auth data must be at least 37 bytes.')
                raise RegistrationRejectedException('Auth data must be at least 37 bytes.')

            # Step 9.
            #
            # Verify that the RP ID hash in authData is indeed the
            # SHA-256 hash of the RP ID expected by the RP.
            logger.debug('----- [Registration] [Verify:Step9] Verify "RP ID" Hash value. -----')
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.rp_id):
                logger.debug('Unable to verify RP ID hash.')
                raise RegistrationRejectedException('Unable to verify RP ID hash.')

            # Step 10.
            #
            # If user verification is required for this registration,
            # verify that the User Verified bit of the flags in authData
            # is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            logger.debug('----- [Registration] [Verify:Step10/11] Verify user verification flag. -----')
            flags = struct.unpack('!B', auth_data[32])[0]
            flags_dict = []
            if (flags & USER_PRESENT) == 0x01:
                flags_dict.append('UP')
            if (flags & USER_VERIFIED) == 0x04:
                flags_dict.append('UV')
            if (flags & ATTESTATION_DATA_INCLUDED) == 0x40:
                flags_dict.append('AT')
            if (flags & EXTENSION_DATA_INCLUDED) == 0x80:
                flags_dict.append('ED')

            if (self.uv_required and (flags & USER_VERIFIED) != 0x04):
                logger.debug('Malformed request received.')
                raise RegistrationRejectedException('Malformed request received.')

            # Step 11.
            #
            # If user verification is not required for this registration,
            # verify that the User Present bit of the flags in authData
            # is set.
            if (not self.uv_required and (flags & USER_PRESENT) != 0x01):
                logger.debug('Malformed request received.')
                raise RegistrationRejectedException('Malformed request received.')

            # Step 12.
            #
            # Verify that the values of the client extension outputs in
            # clientExtensionResults and the authenticator extension outputs
            # in the extensions in authData are as expected, considering the
            # client extension input values that were given as the extensions
            # option in the create() call. In particular, any extension
            # identifier values in the clientExtensionResults and the extensions
            # in authData MUST be also be present as extension identifier values
            # in the extensions member of options, i.e., no extensions are
            # present that were not requested. In the general case, the meaning
            # of "are as expected" is specific to the Relying Party and which
            # extensions are in use.
            logger.debug('----- [Registration] [Verify:Step12] Verify client and authenticator extension. -----')
            registration_client_extensions = self.registration_response.get('registrationClientExtensions')
            rce = json.loads(registration_client_extensions)
            if not _verify_client_extensions(rce):
                logger.debug('Unable to verify client extensions.')
                raise RegistrationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(c):
                logger.debug('Unable to verify authenticator extensions.')
                raise RegistrationRejectedException('Unable to verify authenticator extensions.')

            # Step 13.
            #
            # Determine the attestation statement format by performing
            # a USASCII case-sensitive match on fmt against the set of
            # supported WebAuthn Attestation Statement Format Identifier
            # values. The up-to-date list of registered WebAuthn
            # Attestation Statement Format Identifier values is maintained
            # in the in the IANA registry of the same name
            # [WebAuthn-Registries].
            logger.debug('----- [Registration] [Verify:Step13] Verify Attestation Statement Format. -----')
            if not _verify_attestation_statement_format(fmt):
                logger.debug('Unable to verify attestation statement format ({}).'.format(fmt))
                raise RegistrationRejectedException(
                    'Unable to verify attestation statement format ({}).'.format(fmt))

            # Step 14.
            #
            # Verify that attStmt is a correct attestation statement, conveying
            # a valid attestation signature, by using the attestation statement
            # format fmt's verification procedure given attStmt, authData and
            # the hash of the serialized client data computed in step 7.
            logger.debug('----- [Registration] [Verify:Step14] Attestation Statement verification START. -----')
            (attestation_type, trust_path, credential_public_key_encoded, cred_id) = self._verify_attestation_statement(fmt, att_stmt, auth_data, client_data_hash)
            logger.debug('----- [Registration] [Verify:Step14] Attestation Statement verification END. -----')

            # Step 15.
            #
            # If validation is successful, obtain a list of acceptable trust
            # anchors (attestation root certificates or ECDAA-Issuer public
            # keys) for that attestation type and attestation statement format
            # fmt, from a trusted source or from policy. For example, the FIDO
            # Metadata Service [FIDOMetadataService] provides one way to obtain
            # such information, using the aaguid in the attestedCredentialData
            # in authData.
            logger.debug('----- [Registration] [Verify:Step15] Verify trust anchors. -----')
            trust_anchors = _get_trust_anchors(attestation_type, fmt, self.trust_anchor_dir)
            if not trust_anchors and self.trusted_attestation_cert_required:
                logger.debug('No trust anchors available to verify attestation certificate.')
                raise RegistrationRejectedException('No trust anchors available to verify attestation certificate.')

            # Step 16.
            #
            # Assess the attestation trustworthiness using the outputs of the
            # verification procedure in step 14, as follows:
            #
            #     * If self attestation was used, check if self attestation is
            #       acceptable under Relying Party policy.
            #     * If ECDAA was used, verify that the identifier of the
            #       ECDAA-Issuer public key used is included in the set of
            #       acceptable trust anchors obtained in step 15.
            #     * Otherwise, use the X.509 certificates returned by the
            #       verification procedure to verify that the attestation
            #       public key correctly chains up to an acceptable root
            #       certificate.
            logger.debug('----- [Registration] [Verify:Step16] Verify attestation type. -----')
            logger.debug('>>> attestation type=' + str(attestation_type))
            if attestation_type == AT_SELF_ATTESTATION:
                if not self.self_attestation_permitted:
                    raise RegistrationRejectedException('Self attestation is not permitted.')
            elif attestation_type == AT_ATTESTATION_CA:
                logger.debug('Attestation CA attestation type is not currently supported.')
                raise NotImplementedError(
                    'Attestation CA attestation type is not currently supported.')
            elif attestation_type == AT_ECDAA:
                logger.debug('ECDAA attestation type is not currently supported.')
                raise NotImplementedError(
                    'ECDAA attestation type is not currently supported.')
            elif attestation_type == AT_BASIC:
                if self.trusted_attestation_cert_required:
                    logger.debug('>>> trust_path=' + str(trust_path))
                    logger.debug('>>> trust_anchors=' + str(trust_anchors))
                    # TODO: This function not work by modules error. We SHOULD check trust chain.
                    """
                    if not _is_trusted_attestation_cert(trust_path, trust_anchors):
                        logger.debug('Untrusted attestation certificate.')
                        raise RegistrationRejectedException(
                            'Untrusted attestation certificate.')
                    """
            elif attestation_type == AT_NONE:
                pass
            else:
                raise RegistrationRejectedException('Unknown attestation type.')

            # Step 17.
            #
            # Check that the credentialId is not yet registered to any other user.
            # If registration is requested for a credential that is already registered
            # to a different user, the Relying Party SHOULD fail this registration
            # ceremony, or it MAY decide to accept the registration, e.g. while deleting
            # the older registration.
            #
            # NOTE: This needs to be done by the Relying Party by checking the
            #       `credential_id` property of `WebAuthnCredential` against their
            #       database. See `flask_demo/app.py`.
            logger.debug('----- [Registration] [Verify:Step17] (Skipped) -----')

            # Step 18.
            #
            # If the attestation statement attStmt verified successfully and is
            # found to be trustworthy, then register the new credential with the
            # account that was denoted in the options.user passed to create(),
            # by associating it with the credentialId and credentialPublicKey in
            # the attestedCredentialData in authData, as appropriate for the
            # Relying Party's system.
            logger.debug('----- [Registration] [Verify:Step18] (Skipped) -----')

            # Step 19.
            #
            # If the attestation statement attStmt successfully verified but is
            # not trustworthy per step 16 above, the Relying Party SHOULD fail
            # the registration ceremony.
            #
            #     NOTE: However, if permitted by policy, the Relying Party MAY
            #           register the credential ID and credential public key but
            #           treat the credential as one with self attestation (see
            #           6.3.3 Attestation Types). If doing so, the Relying Party
            #           is asserting there is no cryptographic proof that the
            #           public key credential has been generated by a particular
            #           authenticator model. See [FIDOSecRef] and [UAFProtocol]
            #           for a more detailed discussion.
            logger.debug('----- [Registration] [Verify:Step19] Verification ended, return credential data. -----')
            sc = auth_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]

            credential = WebAuthnCredential(
                self.rp_id,
                self.origin,
                _webauthn_b64_encode(cred_id),
                _webauthn_b64_encode(credential_public_key_encoded),
                sign_count,
                fmt,
                attestation_type,
                ' '.join(flags_dict)
            )

            return credential

        except Exception as e:
            logger.debug('Registration rejected. Error: {}.'.format(e))
            raise RegistrationRejectedException(
                'Registration rejected. Error: {}.'.format(e))


class WebAuthnAssertionResponse(object):

    def __init__(self,
                 webauthn_user,
                 assertion_response,
                 challenge,
                 origin,
                 allow_credentials=None,
                 uv_required=False):
        self.webauthn_user = webauthn_user
        self.assertion_response = assertion_response
        self.challenge = challenge
        self.origin = origin
        self.allow_credentials = allow_credentials
        self.uv_required = uv_required

        self.logger = WebAuthnLogger()
    
    def getLog(self):
        return self.logger.get()

    def verify(self):
        try:
            # Step 1.
            #
            # If the allowCredentials option was given when this authentication
            # ceremony was initiated, verify that credential.id identifies one
            # of the public key credentials that were listed in allowCredentials.
            logger.debug('----- [Authentication] [Verify:Step1] Verify "id" value. -----')
            cid = self.assertion_response.get('id')
            if self.allow_credentials:
                if cid not in self.allow_credentials:
                    logger.debug('Invalid credential.')
                    raise AuthenticationRejectedException('Invalid credential.')

            # Step 2.
            #
            # If credential.response.userHandle is present, verify that the user
            # identified by this value is the owner of the public key credential
            # identified by credential.id.
            logger.debug('----- [Authentication] [Verify:Step2] Verify "userHandle" value. -----')
            user_handle = self.assertion_response.get('userHandle')
            if user_handle:
                if not user_handle == self.webauthn_user.username:
                    logger.debug('Invalid credential.')
                    raise AuthenticationRejectedException('Invalid credential.')

            # Step 3.
            #
            # Using credential's id attribute (or the corresponding rawId, if
            # base64url encoding is inappropriate for your use case), look up
            # the corresponding credential public key.
            logger.debug('----- [Authentication] [Verify:Step3] Verify credential id and Decode PublicKey. -----')
            if not _validate_credential_id(self.webauthn_user.credential_id):
                logger.debug('Invalid credential ID.')
                raise AuthenticationRejectedException('Invalid credential ID.')

            if not isinstance(self.webauthn_user, WebAuthnUser):
                logger.debug('Invalid user type.')
                raise AuthenticationRejectedException('Invalid user type.')

            credential_public_key = self.webauthn_user.public_key
            public_key_numberd = _decode_public_key(_webauthn_b64_decode(credential_public_key))
            public_key = public_key_numberd.public_key(backend=default_backend())
            logger.debug('>>> Encoded Credential Public Key  START <<<')
            logger.debug(_encodeToJWK_public_key(_webauthn_b64_decode(credential_public_key)))
            logger.debug('>>>                     END   <<<')

            # Step 4.
            #
            # Let cData, aData and sig denote the value of credential's
            # response's clientDataJSON, authenticatorData, and signature
            # respectively.
            logger.debug('----- [Authentication] [Verify:Step4] Parse Posted FormData. -----')
            c_data = self.assertion_response.get('clientData')
            a_data = self.assertion_response.get('authData')
            decoded_a_data = _webauthn_b64_decode(a_data)
            sig = self.assertion_response.get('signature').decode('hex')

            # Step 5.
            #
            # Let JSONtext be the result of running UTF-8 decode on the
            # value of cData.
            logger.debug('----- [Authentication] [Verify:Step5/6] Parse Posted FormData. -----')
            u8_clientdata = c_data.decode('utf-8')

            # Step 6.
            #
            # Let C, the client data claimed as used for the signature,
            # be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(u8_clientdata)
            c = json.loads(decoded_cd)

            # Step 7.
            #
            # Verify that the value of C.type is the string webauthn.get.
            logger.debug('----- [Authentication] [Verify:Step7] Verify "type" value. -----')
            received_type = c.get('type')
            if not _verify_type(received_type, TYPE_GET):
                logger.debug('Invalid type.')
                raise RegistrationRejectedException('Invalid type.')

            # Step 8.
            #
            # Verify that the value of C.challenge matches the challenge
            # that was sent to the authenticator in the
            # PublicKeyCredentialRequestOptions passed to the get() call.
            logger.debug('----- [Authentication] [Verify:Step8] Verify "challenge" value. -----')
            received_challenge = c.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                logger.debug('Unable to verify challenge.')
                raise AuthenticationRejectedException('Unable to verify challenge.')

            # Step 9.
            #
            # Verify that the value of C.origin matches the Relying
            # Party's origin.
            logger.debug('----- [Authentication] [Verify:Step9] Verify "origin" value. -----')
            if not _verify_origin(c, self.origin):
                logger.debug('Unable to verify origin.')
                raise AuthenticationRejectedException('Unable to verify origin.')
            
            # Step 10.
            #
            # Verify that the value of C.tokenBinding.status matches
            # the state of Token Binding for the TLS connection over
            # which the attestation was obtained. If Token Binding was
            # used on that TLS connection, also verify that
            # C.tokenBinding.id matches the base64url encoding of the
            # Token Binding ID for the connection.
            #if not _verify_token_binding_id(c):
            #    raise AuthenticationRejectedException('Unable to verify token binding ID.')
            logger.debug('----- [Authentication] [Verify:Step10] Verify binding ID. (Ignored) -----')

            # Step 11.
            #
            # Verify that the rpIdHash in aData is the SHA-256 hash of
            # the RP ID expected by the Relying Party.
            logger.debug('----- [Authentication] [Verify:Step11] Verify "RP ID" Hash value. -----')
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(decoded_a_data)
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.webauthn_user.rp_id):
                logger.debug('Unable to verify RP ID hash.')
                raise AuthenticationRejectedException('Unable to verify RP ID hash.')

            # Step 12.
            #
            # If user verification is required for this assertion, verify
            # that the User Verified bit of the flags in aData is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            logger.debug('----- [Authentication] [Verify:Step12/13] Verify user verification flag. -----')
            flags = struct.unpack('!B', decoded_a_data[32])[0]

            if (self.uv_required and (flags & USER_VERIFIED) != 0x04):
                logger.debug('Malformed request received.')
                raise AuthenticationRejectedException('Malformed request received.')

            # Step 13.
            #
            # If user verification is not required for this assertion, verify
            # that the User Present bit of the flags in aData is set.
            if (not self.uv_required and (flags & USER_PRESENT) != 0x01):
                logger.debug('Malformed request received.')
                raise AuthenticationRejectedException('Malformed request received.')

            # Step 14.
            #
            # Verify that the values of the client extension outputs in
            # clientExtensionResults and the authenticator extension outputs
            # in the extensions in authData are as expected, considering the
            # client extension input values that were given as the extensions
            # option in the get() call. In particular, any extension identifier
            # values in the clientExtensionResults and the extensions in
            # authData MUST be also be present as extension identifier values
            # in the extensions member of options, i.e., no extensions are
            # present that were not requested. In the general case, the meaning
            # of "are as expected" is specific to the Relying Party and which
            # extensions are in use.
            logger.debug('----- [Authentication] [Verify:Step14] Verify client and authenticator extension. -----')
            assertion_client_extensions = self.assertion_response.get(
                'assertionClientExtensions')
            ace = json.loads(assertion_client_extensions)
            if not _verify_client_extensions(ace):
                logger.debug('Unable to verify client extensions.')
                raise AuthenticationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(c):
                logger.debug('Unable to verify authenticator extensions.')
                raise AuthenticationRejectedException('Unable to verify authenticator extensions.')

            # Step 15.
            #
            # Let hash be the result of computing a hash over the cData
            # using SHA-256.
            logger.debug('----- [Authentication] [Verify:Step15] Compute ClientData Hash value. -----')
            client_data_hash = _get_client_data_hash(decoded_cd)

            # Step 16.
            #
            # Using the credential public key looked up in step 3, verify
            # that sig is a valid signature over the binary concatenation
            # of aData and hash.
            logger.debug('----- [Authentication] [Verify:Step16] Verify Signature. -----')
            verification_data = ''.join([
                decoded_a_data,
                client_data_hash])
            try:
                if isinstance(public_key, EllipticCurvePublicKey):
                    credential_alg = COSE_ALG_ES256
                elif isinstance(public_key, RSAPublicKey):
                    credential_alg = COSE_ALG_RS256
                else:
                    logger.debug('Invalid instance of publickey.')
                    raise AuthenticationRejectedException('Invalid instance of publickey.')

                _verify_signature(credential_alg, sig, verification_data, public_key)

            except InvalidSignature:
                logger.debug('Invalid signature received.')
                raise AuthenticationRejectedException('Invalid signature received.')

            # Step 17.
            #
            # If the signature counter value adata.signCount is nonzero or
            # the value stored in conjunction with credential's id attribute
            # is nonzero, then run the following sub-step:
            #     If the signature counter value adata.signCount is
            #         greater than the signature counter value stored in
            #         conjunction with credential's id attribute.
            #             Update the stored signature counter value,
            #             associated with credential's id attribute,
            #             to be the value of adata.signCount.
            #         less than or equal to the signature counter value
            #         stored in conjunction with credential's id attribute.
            #             This is a signal that the authenticator may be
            #             cloned, i.e. at least two copies of the credential
            #             private key may exist and are being used in parallel.
            #             Relying Parties should incorporate this information
            #             into their risk scoring. Whether the Relying Party
            #             updates the stored signature counter value in this
            #             case, or not, or fails the authentication ceremony
            #             or not, is Relying Party-specific.
            logger.debug('----- [Authentication] [Verify:Step17] Verify Sign Count. -----')
            sc = decoded_a_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]
            if sign_count or self.webauthn_user.sign_count:
                if sign_count <= self.webauthn_user.sign_count:
                    logger.debug('Duplicate authentication detected.')
                    raise AuthenticationRejectedException('Duplicate authentication detected.')

            # Step 18.
            #
            # If all the above steps are successful, continue with the
            # authentication ceremony as appropriate. Otherwise, fail the
            # authentication ceremony.
            logger.debug('----- [Authentication] [Verify:Step18] retuen Sign Count. -----')
            return sign_count

        except Exception as e:
            logger.debug('Authentication rejected. Error: {}.'.format(e))
            raise AuthenticationRejectedException(
                'Authentication rejected. Error: {}.'.format(e))


def _encode_public_key(alg_type, public_key):
    '''Extracts the x, y coordinates from a public point on a Cryptography elliptic
    curve, packs them into a standard byte string representation, and returns
    them
    :param public_key: an EllipticCurvePublicKey object
    :return: a 65-byte string. decode_public_key().public_key() can invert this
    function.
    '''
    if alg_type == COSE_ALG_ES256:
        numbers = public_key.public_numbers()
        return '\x04' + '{:064x}{:064x}'.format(numbers.x, numbers.y).decode('hex')
    elif alg_type == COSE_ALG_RS256:
        numbers = public_key.public_numbers()
        return '\x0b' + '{:06x}{:0512x}'.format(numbers.e, numbers.n).decode('hex')
    else:
        raise RegistrationRejectedException('bad algorithm type.')


def _decode_public_key(key_bytes):
    '''Decode a packed SECP256r1 public key into an EllipticCurvePublicKey
    '''
    # Parsing this structure by hand, following SEC1, section 2.3.4
    # An alternative is to hack on the OpenSSL CFFI bindings so we
    # can call EC_POINT_oct2point on the contents of key_bytes. Please
    # believe me when I say that this is much simpler - mainly because
    # we can make assumptions about /exactly/ which EC curve we're
    # using!)

    # https://os.mbed.com/users/markrad/code/mbedtls/docs/cdf462088d13/oid_8h_source.html
    # MBEDTLS_OID_ECDSA_SHA256            MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x02"
    # MBEDTLS_OID_PKCS1_SHA256            MBEDTLS_OID_PKCS1 "\x0b" /**< sha256WithRSAEncryption ::= { pkcs-1 11 } */
    #

    # x and y coordinates are each 32-bytes long, encoded as big-endian binary
    # strings. Without calling unsupported C API functions (i.e.
    # _PyLong_FromByteArray), converting to hex-encoding and then parsing
    # seems to be the simplest way to make these into python big-integers.
    if key_bytes[0] == '\x04':
        curve = SECP256R1()
        x = long(key_bytes[1:33].encode('hex'), 16)
        y = long(key_bytes[33:].encode('hex'), 16)
        return EllipticCurvePublicNumbers(x, y, curve)
    elif key_bytes[0] == '\x0b':
        e = long(key_bytes[1:4].encode('hex'), 16)
        n = long(key_bytes[4:].encode('hex'), 16)
        return RSAPublicNumbers(e, n)
    else:
        raise AuthenticationRejectedException('Decoded Public key format is Invalid.')

def _encodeToJWK_public_key(key_bytes):
    if key_bytes[0] == '\x04':
        #x = key_bytes[1:33].encode('hex')
        #y = key_bytes[33:].encode('hex')
        x = _webauthn_b64_encode(key_bytes[1:33])
        y = _webauthn_b64_encode(key_bytes[33:])
        return {
            'alg': COSE_ALGLABEL_ES256,
            'kty': 'EC',
            'use': 'sig',
            'x': x,
            'y': y
        }
    elif key_bytes[0] == '\x0b':
        #e = key_bytes[1:9].encode('hex')
        #n = key_bytes[9:].encode('hex')
        e = _webauthn_b64_encode(key_bytes[1:4])
        n = _webauthn_b64_encode(key_bytes[4:])
        return {
            'alg': COSE_ALGLABEL_RS256,
            'kty': 'RSA',
            'use': 'sig',
            'n': n,
            'e': e
        }
    else:
        return {
            'alg': 'Unknown'
        }

def _webauthn_b64_decode(encoded):
    '''WebAuthn specifies web-safe base64 encoding *without* padding.
    Python implementation requires padding. We'll add it and then
    decode'''
    # Ensure that this is encoded as ascii, not unicode.
    encoded = encoded.encode('ascii')
    # Add '=' until length is a multiple of 4 bytes, then decode.
    padding_len = (-len(encoded) % 4)
    encoded += '=' * padding_len
    return base64.urlsafe_b64decode(encoded)


def _webauthn_b64_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip('=')


def _get_trust_anchors(attestation_type,
                       attestation_fmt,
                       trust_anchor_dir):
    '''Return a list of trusted attestation root certificates.
    '''
    if attestation_type not in SUPPORTED_ATTESTATION_TYPES:
        return []
    if attestation_fmt not in SUPPORTED_ATTESTATION_FORMATS:
        return []

    if trust_anchor_dir == DEFAULT_TRUST_ANCHOR_DIR:
        ta_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            trust_anchor_dir)
    else:
        ta_dir = trust_anchor_dir

    trust_anchors = []

    if os.path.isdir(ta_dir):
        for ta_name in os.listdir(ta_dir):
            ta_path = os.path.join(ta_dir, ta_name)
            if os.path.isfile(ta_path):
                with open(ta_path, 'rb') as f:
                    crt_data = f.read().strip()
                    try:
                        pem = crypto.load_certificate(
                            crypto.FILETYPE_PEM, crt_data)
                        trust_anchors.append(pem)
                    except Exception:
                        try:
                            der = crypto.load_certificate(
                                crypto.FILETYPE_ASN1, crt_data)
                            trust_anchors.append(der)
                        except Exception:
                            pass

    return trust_anchors


def _is_trusted_attestation_cert(trust_path, trust_anchors):
    #return True

    
    if not trust_path or not isinstance(trust_path, list):
        return False
    # NOTE: Only using the first attestation cert in the
    #       attestation trust path for now, but should be
    #       able to build a chain.
    attestation_cert = trust_path[0]
    store = crypto.X509Store()
    for _ta in trust_anchors:
        store.add_cert(_ta)
    store_ctx = crypto.X509StoreContext(store, attestation_cert)

    try:
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print('Unable to verify certificate: {}.'.format(e), file=sys.stderr)

    return False
    

def _verify_type(received_type, expected_type):
    if received_type == expected_type:
        return True

    return False


def _verify_challenge(received_challenge, sent_challenge):
    if not isinstance(received_challenge, six.string_types):
        return False
    if not isinstance(sent_challenge, six.string_types):
        return False
    if not received_challenge:
        return False
    if not sent_challenge:
        return False
    if sent_challenge != received_challenge:
        return False

    return True


def _verify_origin(client_data, origin):
    if not isinstance(client_data, dict):
        return False

    client_data_origin = client_data.get('origin')

    if not client_data_origin:
        return False
    if client_data_origin != origin:
        return False

    return True


def _verify_token_binding_id(client_data):
    '''The tokenBinding member contains information about the state of the
    Token Binding protocol used when communicating with the Relying Party.
    The status member is one of:

        not-supported: when the client does not support token binding.

            supported: the client supports token binding, but it was not
                       negotiated when communicating with the Relying
                       Party.

              present: token binding was used when communicating with the
                       Relying Party. In this case, the id member MUST be
                       present and MUST be a base64url encoding of the
                       Token Binding ID that was used.
    '''
    # TODO: Add support for verifying token binding ID.
    token_binding_status = client_data['tokenBinding']['status']
    token_binding_id = client_data['tokenBinding'].get('id', '')
    if token_binding_status in ('supported', 'not-supported'):
        return True
    return False


def _verify_client_extensions(client_extensions):
    if set(EXPECTED_CLIENT_EXTENSIONS.keys()).issuperset(client_extensions.keys()):
        return True
    return False


def _verify_authenticator_extensions(client_data):
    # TODO
    return True


def _verify_rp_id_hash(auth_data_rp_id_hash, rp_id):
    rp_id_hash = hashlib.sha256(rp_id).digest()

    return auth_data_rp_id_hash == rp_id_hash


def _verify_attestation_statement_format(fmt):
    # TODO: Handle other attestation statement formats.
    '''Verify the attestation statement format.
    '''
    if not isinstance(fmt, six.string_types):
        return False

    return fmt in SUPPORTED_ATTESTATION_FORMATS


def _get_auth_data_rp_id_hash(auth_data):
    if not isinstance(auth_data, six.string_types):
        return False

    auth_data_rp_id_hash = auth_data[:32]

    return auth_data_rp_id_hash


def _get_client_data_hash(decoded_client_data):
    if not isinstance(decoded_client_data, six.string_types):
        return ''

    return hashlib.sha256(decoded_client_data).digest()


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, six.string_types):
        return False

    return True


def _get_publickey(keydict):
    alg = None

    if COSE_KEYNAME_ALG not in keydict:
        raise RegistrationRejectedException("Credential public key missing required algorithm parameter.")
    if keydict[COSE_KEYNAME_ALG] != COSE_ALG_ES256 and keydict[COSE_KEYNAME_ALG] != COSE_ALG_RS256:
        raise RegistrationRejectedException('Unsupported algorithm.')
    if (keydict[COSE_KEYNAME_ALG] == COSE_ALG_ES256 and not set(keydict.keys()).issuperset({COSE_ALG_ES256_X, COSE_ALG_ES256_Y})) or (keydict[COSE_KEYNAME_ALG] == COSE_ALG_RS256 and not set(keydict.keys()).issuperset({COSE_ALG_RS256_N, COSE_ALG_RS256_E})):
        raise RegistrationRejectedException('Credential public key must match COSE_Key spec.')

    if keydict[COSE_KEYNAME_ALG] == COSE_ALG_ES256:  # ES256
        alg = COSE_ALG_ES256

        x = keydict[COSE_ALG_ES256_X].encode('hex')
        if len(x) != 64:
            raise RegistrationRejectedException('Bad public key(x).')
        x_long = long(x, 16)

        y = keydict[COSE_ALG_ES256_Y].encode('hex')
        if len(y) != 64:
            raise RegistrationRejectedException('Bad public key(y).')
        y_long = long(y, 16)

        public_key_ec = EllipticCurvePublicNumbers(x_long, y_long,SECP256R1()).public_key(backend=default_backend())

        return alg, public_key_ec

    elif keydict[COSE_KEYNAME_ALG] == COSE_ALG_RS256:  # RS256
        alg = COSE_ALG_RS256

        n = keydict[COSE_ALG_RS256_N].encode('hex')
        if len(n) != 512:
            raise RegistrationRejectedException('Bad public key(n).')
        n_long = long(n, 16)

        e = keydict[COSE_ALG_RS256_E].encode('hex')
        if len(e) != 6:
            raise RegistrationRejectedException('Bad public key(e).')
        e_long = long(e, 16)

        public_key_rsa = RSAPublicNumbers(e_long, n_long,).public_key(backend=default_backend())

        return alg, public_key_rsa

    else:
        return None, None
        
def _verify_signature(alg, signature, verification_data, pub_key):
    if alg not in [COSE_ALG_ES256, COSE_ALG_RS256]:
        raise RegistrationRejectedException('Invalid parameter algorithm.')

    if alg == COSE_ALG_ES256:
        pub_key.verify(signature, verification_data, ECDSA(SHA256()))
    elif alg == COSE_ALG_RS256:
        pub_key.verify(signature, verification_data, PKCS1v15(), SHA256())
 

