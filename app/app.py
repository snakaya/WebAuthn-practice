import os
import json

from flask import Flask
from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import Response
from flask import session
from flask import url_for
from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

import util

from db import db
from context import webauthn
from models import Users


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(os.path.join(os.path.dirname(os.path.abspath(__name__)), 'webauthn.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
sk = os.environ.get('FLASK_SECRET_KEY')
app.secret_key = sk if sk else os.urandom(40)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

_version_ = '0.8'

#
# NOTE: PLEASE CHANGE TO YOUR RP_ID , ORIGIN URL AND PORT NUMBER FROM OS ENVIRONMENT VARIBLES.
#
RP_ID = os.getenv('WEBAUTHN_RP_ID', 'www.example.com')
ORIGIN = os.getenv('WEBAUTHN_ORIGIN', 'https://www.example.com')
PORT = os.getenv('WEBAUTHN_PORT', '5000')

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None

    return Users.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html', app_version = _version_)


@app.route('/users', methods=['GET'])
def get_userlist():
    if request.method == 'GET':
        user_list = []
        webauthn_tools = webauthn.WebAuthnTools()
        for u in Users.query.all():
            u.pub_key = webauthn_tools.format_user_pubkey(u.pub_key)
            user_list.append(Users.to_dict(u))
        return jsonify({'users': user_list})

@app.route("/user/<id>", methods=['GET'])
def get_user(id):
    if request.method == 'GET':
        u = Users.query.get(id)
        u_dict = Users.to_dict(u)
        webauthn_tools = webauthn.WebAuthnTools()
        u_dict['pub_key'] = webauthn_tools.format_user_pubkey(u_dict['pub_key'])
        return jsonify(u_dict),

@app.route("/users", methods=['DELETE'])
def delete_alluser(id):
    if request.method == 'DELETE':
        users = Users.query.all()
        db.session.delete(users)
        db.session.commit()
        return make_response(jsonify({'success': 'All Users successfully deleted.'}), 204)

@app.route("/user/<id>", methods=['DELETE'])
def delete_user(id):
    if request.method == 'DELETE':
        u = Users.query.get(id)
        db.session.delete(u)
        db.session.commit()
        return make_response(jsonify({'success': 'User successfully deleted.'}), 204)


@app.route('/webauthn_begin_activate', methods=['POST'])
def webauthn_begin_activate():
    # MakeCredentialOptions
    username = request.form.get('username')
    display_name = request.form.get('displayName')

    if 'register_ukey' in session:
        del session['register_ukey']
    if 'register_username' in session:
        del session['register_username']
    if 'register_display_name' in session:
        del session['register_display_name']
    if 'challenge' in session:
        del session['challenge']
    if 'att_option' in session:
        del session['att_option']

    if username == "" or username is None:
        username = util.random_username(8)

    session['register_username'] = username
    session['register_display_name'] = display_name

    rp_name = RP_ID
    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()

    session['challenge'] = challenge
    session['register_ukey'] = ukey

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge,
        rp_name,
        RP_ID,
        ukey,
        username,
        display_name,
        'https://example.com')

    print(make_credential_options.registration_dict)
    retres = json.dumps(make_credential_options.registration_dict, indent=2)
    session['att_option'] = retres

    return jsonify(make_credential_options.registration_dict)


@app.route('/webauthn_begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    username = request.form.get('username')

    #if not util.validate_username(username):
    #    return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    user = Users.query.filter_by(username=username).first()
    if not user:
        app.logger.debug('User does not exist.')
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not user.credential_id:
        app.logger.debug('Unknown credential ID.')
        return make_response(jsonify({'fail': 'Unknown credential ID.'}), 401)

    if 'challenge' in session:
        del session['challenge']

    challenge = util.generate_challenge(32)

    session['challenge'] = challenge

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey,
        user.username,
        user.display_name,
        user.icon_url,
        user.credential_id,
        user.pub_key,
        user.sign_count,
        user.rp_id)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user,
        challenge)

    return jsonify(webauthn_assertion_options.assertion_dict)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():

    app.logger.debug('----- [Registration] Authenticator Response (Native) from Authenticator/Client -----')
    app.logger.debug(str(request.form.to_dict()))
    app.logger.debug('----- End -----')

    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']
    att_option = session['att_option']

    registration_response = request.form
    stringlyResponse = request.form['stringlyResponse']
    trust_anchor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    webauthn_registration_response.addLog('----- [Registration] Server Received Data -----')

    try:
        webauthn_registration_response.addLog('----- [Registration] Authenticator Response (Decoded) from Authenticator/Client -----')
        attestation_response = webauthn_registration_response.view()
        webauthn_registration_response.addLog(json.dumps(attestation_response, indent=4))
        webauthn_registration_response.addLog('----- End -----')
    except Exception as e:
        app.logger.debug('Attestation view failed. Error: {}'.format(e))
        webauthn_registration_response.addLog('Attestation view failed. Error: {}'.format(e))
        return jsonify({'fail': 'Attestation view failed. Error: {}'.format(e), 'debug_log': webauthn_registration_response.getLog()})

    try:
        webauthn_registration_response.addLog('----- [Registration] [Verify] Start -----')
        webauthn_credential = webauthn_registration_response.verify()
        webauthn_registration_response.addLog('----- [Registration] [Verify] End   -----')
    except Exception as e:
        app.logger.debug('Registration failed. Error: {}'.format(e))
        webauthn_registration_response.addLog('Registration failed. Error: {}'.format(e))
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e), 'debug_log': webauthn_registration_response.getLog()})

    # Step 17.
    #
    # Check that the credentialId is not yet registered to any other user.
    # If registration is requested for a credential that is already registered
    # to a different user, the Relying Party SHOULD fail this registration
    # ceremony, or it MAY decide to accept the registration, e.g. while deleting
    # the older registration.
    credential_id_exists = Users.query.filter_by(
        credential_id=webauthn_credential.credential_id).first()
    if credential_id_exists:
        app.logger.debug('Credential ID already exists.')
        webauthn_registration_response.addLog('Credential ID already exists.')
        return make_response(jsonify({'fail': 'Credential ID already exists.', 'debug_log': webauthn_registration_response.getLog()}), 401)

    user = Users(
        ukey=ukey,
        username=username,
        display_name=display_name,
        pub_key=webauthn_credential.public_key,
        credential_id=webauthn_credential.credential_id,
        sign_count=webauthn_credential.sign_count,
        att_option=att_option,
        response=stringlyResponse,
        response_dec=json.dumps(attestation_response, indent=4),
        rp_id=RP_ID,
        icon_url='https://example.com')
    db.session.add(user)
    db.session.commit()

    webauthn_registration_response.addLog('----- [Registration] Server Successfully Return. -----')
    return jsonify({'success': 'User successfully registered.', 'debug_log': webauthn_registration_response.getLog()})


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    app.logger.debug('----- [Log-in] Authenticator Response (Native) from Authenticator/Client -----')
    app.logger.debug(str(request.form.to_dict()))
    app.logger.debug('----- End -----')

    challenge = session.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    user = Users.query.filter_by(credential_id=credential_id).first()
    if not user:
        app.logger.debug('User does not exist.')
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey,
        user.username,
        user.display_name,
        user.icon_url,
        user.credential_id,
        user.pub_key,
        user.sign_count,
        user.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        allow_credentials=None,
        uv_required=False)  # User Verification

    webauthn_assertion_response.addLog('----- [Log-in] Received Data -----')

    try:
        webauthn_assertion_response.addLog('----- [Log-in] Authenticator Response (Decoded) from Authenticator/Client -----')
        assersion_response = webauthn_assertion_response.view()
        webauthn_assertion_response.addLog(json.dumps(assersion_response, indent=4))
        webauthn_assertion_response.addLog('----- End -----')
    except Exception as e:
        app.logger.debug('Assertion view failed. Error: {}'.format(e))
        webauthn_assertion_response.addLog('Attestation view failed. Error: {}'.format(e))
        return jsonify({'fail': 'Attestation view failed. Error: {}'.format(e), 'debug_log': webauthn_assertion_response.getLog()})

    try:
        webauthn_assertion_response.addLog('----- [Log-in] [Verify] Start -----')
        sign_count = webauthn_assertion_response.verify()
        webauthn_assertion_response.addLog('----- [Log-in] [Verify] End   -----')
    except Exception as e:
        app.logger.debug('Assertion failed. Error: {}'.format(e))
        webauthn_assertion_response.addLog('Assertion failed. Error: {}'.format(e))
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e), 'debug_log': webauthn_assertion_response.getLog()})

    # Update counter.
    user.sign_count = sign_count
    db.session.add(user)
    db.session.commit()

    login_user(user)

    webauthn_assertion_response.addLog('----- [Log-in] Server Successfully Return. -----')
    return jsonify({
        'success': u'Successfully authenticated as {}'.format(user.username),
        'debug_log': webauthn_assertion_response.getLog()
    })


@app.route('/view/attestation', methods=['POST'])
def view_attestation():
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']

    registration_response = request.form
    trust_anchor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = False
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        attestation_response = webauthn_registration_response.view()
    except Exception as e:
        app.logger.debug('Registration failed. Error: {}'.format(e))
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e), 'debug_log': webauthn_registration_response.getLog()})

    return jsonify(attestation_response)


@app.route('/view/assertion', methods=['POST'])
def view_assertion():
    challenge = session.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    user = Users.query.filter_by(credential_id=credential_id).first()
    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey,
        user.username,
        user.display_name,
        user.icon_url,
        user.credential_id,
        user.pub_key,
        user.sign_count,
        user.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        allow_credentials=None,
        uv_required=False)  # User Verification

    try:
        webauthn_assertion = webauthn_assertion_response.view()
    except Exception as e:
        app.logger.debug('Assertion failed. Error: {}'.format(e))
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e), 'debug_log': webauthn_assertion_response.getLog()})

    return jsonify(webauthn_assertion)


@app.route('/options', methods=['GET'])
def get_options():

    try:
        options = webauthn.WebAuthnOptions()
        options.load()
        options_dict = options.get()
    except Exception as e:
        app.logger.debug('Options failed. Error: {}'.format(e))
        return jsonify({'fail': 'Options failed. Error: {}'.format(e)})

    return jsonify(options_dict)


@app.route('/options', methods=['POST'])
def set_options():
    
    conveyancePreference = request.form.get('conveyancePreference')
    userVerification = request.form.get('userVerification')
    requireResidentKey = request.form.get('requireResidentKey')
    authenticatorAttachment = request.form.get('authenticatorAttachment')
    attestationAllowCredentials = request.form.get('attestationAllowCredentials')
    attestationExcludeCredentials = request.form.get('attestationExcludeCredentials')
    attestationExtensions = request.form.get('attestationExtensions')
    assertionAllowCredentials = request.form.get('assertionAllowCredentials')
    assertionExtensions = request.form.get('assertionExtensions')

    try:
        options = webauthn.WebAuthnOptions()
        options.load()

        if conveyancePreference in webauthn.WebAuthnOptions.SUPPORTED_CONVEYANCE_PREFARENCE:
            options.conveyancePreference = conveyancePreference
        else:
            return jsonify({'fail': 'Option Selection Error (conveyancePreference).'})
        if userVerification in webauthn.WebAuthnOptions.SUPPORTED_AUTHENTICATIONSELECTION_USERVERIFICATION:
            options.userVerification = userVerification
        else:
            return jsonify({'fail': 'Option Selection Error (userVerification).'})
        if requireResidentKey in webauthn.WebAuthnOptions.SUPPORTED_REQUIRE_REDIDENTKEY:
            options.requireResidentKey = requireResidentKey
        else:
            return jsonify({'fail': 'Option Selection Error (requireResidentKey).'})
        if authenticatorAttachment in webauthn.WebAuthnOptions.SUPPORTED_AUTHENTICATIONSELECTION_ATTACHIMENT or authenticatorAttachment == '':
            options.authenticatorAttachment = authenticatorAttachment
        else:
            return jsonify({'fail': 'Option Selection Error (authenticatorAttachment).'})
        if set(attestationAllowCredentials.split(' ')).issubset(webauthn.WebAuthnOptions.SUPPORTED_TRANSPORTS) or attestationAllowCredentials == '':
            options.attestationAllowCredentials = attestationAllowCredentials.split(' ')
        else:
            return jsonify({'fail': 'Option Selection Error (attestationAllowCredentials).'})
        if set(attestationExcludeCredentials.split(' ')).issubset(webauthn.WebAuthnOptions.SUPPORTED_TRANSPORTS) or attestationExcludeCredentials == '':
            options.attestationExcludeCredentials = attestationExcludeCredentials.split(' ')
        else:
            return jsonify({'fail': 'Option Selection Error (attestationExcludeCredentials).'})
        if attestationExtensions != '':
            tmp_dict = {}
            for lineitem in attestationExtensions.splitlines():
                item = [x.strip() for x in lineitem.split('=')]
                if len(item) == 2:
                    tmp_dict[item[0]] = item[1]
            if len(tmp_dict) > 0:
                options.attestationExtensions = tmp_dict
            else:
                return jsonify({'fail': 'Option Format Error (assertionExtensions).'})
        if set(assertionAllowCredentials.split(' ')).issubset(webauthn.WebAuthnOptions.SUPPORTED_TRANSPORTS) or assertionAllowCredentials == '':
            options.assertionAllowCredentials = assertionAllowCredentials.split(' ')
        else:
            return jsonify({'fail': 'Option Selection Error (assertionAllowCredentials).'})
        if assertionExtensions != '':
            tmp_dict = {}
            for lineitem in assertionExtensions.splitlines():
                item = [x.strip() for x in lineitem.split('=')]
                if len(item) == 2:
                    tmp_dict[item[0]] = item[1]
            if len(tmp_dict) > 0:
                options.attestationExtensions = tmp_dict
            else:
                return jsonify({'fail': 'Option Format Error (assertionExtensions).'})

        options.save()

    except Exception as e:
        app.logger.debug('Options failed. Error: {}'.format(e))
        return jsonify({'fail': 'Options failed. Error: {}'.format(e)})
    
    return jsonify({'success': 'Options successfully saved.'})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(PORT, 10), debug=True)
