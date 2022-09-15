"""Contains all functions for the purpose of logging in and out to Robinhood."""
import getpass
import os
import pickle
import random

from robin_stocks.robinhood.helper import *
from robin_stocks.robinhood.urls import *

EXPIRY_TIME = 86400
CLIENT_ID = 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS'

def generate_device_token():
    """This function will generate a token used when loggin on.

    :returns: A string representing the token.

    """
    rands = []
    for i in range(0, 16):
        r = random.random()
        rand = 4294967296.0 * r
        rands.append((int(rand) >> ((3 & i) << 3)) & 255)

    hexa = []
    for i in range(0, 256):
        hexa.append(str(hex(i+256)).lstrip("0x").rstrip("L")[1:])

    id = ""
    for i in range(0, 16):
        id += hexa[rands[i]]

        if (i == 3) or (i == 5) or (i == 7) or (i == 9):
            id += "-"

    return(id)


def respond_to_challenge(challenge_id, sms_code):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = challenge_url(challenge_id)
    payload = {
        'response': sms_code
    }
    return(request_post(url, payload))


def refresh_access_token(refresh_token, device_token=None):
    """This function will refresh the access token with a refresh token.

    :param refresh_token: The refresh token to use.
    :returns:  The response from requests.

    """
    if not device_token:
        device_token = generate_device_token()
    url = login_url()
    relogin_payload = {
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "device_token": device_token,
        "refresh_token": refresh_token,
        "scope": "web_limited",
    }
    pop_session_header('Authorization')
    try:
        data = request_post(url, relogin_payload)
    except HTTPError:
        raise AuthenticationError("Failed to refresh token")

    update_session(
        'Authorization', '{0} {1}'.format(data.get('token_type'), data.get('access_token')))
    return data


def login(username=None, password=None, access_token=None, expiresIn=EXPIRY_TIME, scope='internal', by_sms=True, mfa_code=None, challenge_id=None, device_token=None):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. By default, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins.

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param access_token: The access token to attempt to log in with.
    :type access_token: Optional[str]
    :param expiresIn: The time until your login session expires. This is in seconds.
    :type expiresIn: Optional[int]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param by_sms: Specifies whether to send an email(False) or an sms(True)
    :type by_sms: Optional[boolean]
    :param mfa_code: MFA token if enabled.
    :type mfa_code: Optional[str]
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    if not device_token:
        device_token = generate_device_token()
    # Challenge type is used if not logging in with two-factor authentication.
    if by_sms:
        challenge_type = "sms"
    else:
        challenge_type = "email"

    url = login_url()
    payload = {
        'client_id': CLIENT_ID,
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'challenge_type': challenge_type,
        'device_token': device_token
    }

    if mfa_code:
        if challenge_id:
            res = respond_to_challenge(challenge_id, mfa_code)
            update_session(
                'X-ROBINHOOD-CHALLENGE-RESPONSE-ID', challenge_id)
            if 'challenge' in res:
                raise Exception("Unable to log in with provided credentials")
            import time
            time.sleep(2)
        else:
            payload['mfa_code'] = mfa_code

    if access_token and access_token.token:
        try:
            token = access_token.token
            token_type = access_token.meta.get("token_type")
            # Set login status to True in order to try and get account info.
            set_login_state(True)
            update_session(
                'Authorization', '{0} {1}'.format(token_type, token))
            # Try to load account profile to check that authorization token is still valid.
            res = request_get(
                positions_url(), 'pagination', {'nonzero': 'true'}, jsonify_data=False)
            # Raises exception is response code is not 200.
            res.raise_for_status()
            return({'access_token': token, 'token_type': token_type,
                    'expires_in': expiresIn, 'scope': scope, 'detail': 'logged in using authentication in'})
        except Exception as ex:
            print(
                "ERROR: There was an issue using access token. Authentication may be expired - logging in normally.", file=get_output())
            set_login_state(False)
            update_session('Authorization', None)
    data = request_post(url, payload)
    # Handle case where mfa or challenge is required.
    if data:
        if 'mfa_required' in data:
            return "MFA_REQUIRED"
            mfa_token = input("Please type in the MFA code: ")
            payload['mfa_code'] = mfa_token
            res = request_post(url, payload, jsonify_data=False)
            while (res.status_code != 200):
                mfa_token = input(
                    "That MFA code was not correct. Please type in another MFA code: ")
                payload['mfa_code'] = mfa_token
                res = request_post(url, payload, jsonify_data=False)
            data = res.json()
        elif 'challenge' in data:
            return {"CHALLENGE_ID": data['challenge']['id']}
            #return "CHALLENGE_REQUIRED"
            challenge_id = data['challenge']['id']
            sms_code = input('Enter Robinhood code for validation: ')
            res = respond_to_challenge(challenge_id, sms_code)
            while 'challenge' in res and res['challenge']['remaining_attempts'] > 0:
                sms_code = input('That code was not correct. {0} tries remaining. Please type in another code: '.format(
                    res['challenge']['remaining_attempts']))
                res = respond_to_challenge(challenge_id, sms_code)
            update_session(
                'X-ROBINHOOD-CHALLENGE-RESPONSE-ID', challenge_id)
            data = request_post(url, payload)
        # Update Session data with authorization or raise exception with the information present in data.
        if 'access_token' in data:
            token = '{0} {1}'.format(data['token_type'], data['access_token'])
            update_session('Authorization', token)
            set_login_state(True)
            data['detail'] = "logged in with brand new authentication code."

        else:
            raise Exception(data['detail'])
    else:
        raise Exception('Error: Trouble connecting to robinhood API. Check internet connection.')
    return(data)


@login_required
def logout():
    """Removes authorization from the session header.

    :returns: None

    """
    set_login_state(False)
    update_session('Authorization', None)
