from flask_oauthlib.client import OAuth, OAuthException
import json, requests

def microsoft_client(config, app):
    return OAuth(app).remote_app(
        'microsoft',
        consumer_key=config['client_id'],
        consumer_secret=config['client_secret'],
        request_token_params={'scope': _scopes(config) },
        base_url='http://microsoft_ignores_this_value',  # We won't need this
        request_token_url=None,
        access_token_method='POST',
        access_token_url=_token_url(config),
        authorize_url=_authorize_url(config)
    )

def keys(config):
    return json.loads(requests.get(_keys_url(config)).text)

def _keys_url(config):
    return _core_url(config) + '/discovery/keys'

def _core_url(config):
    return 'https://login.microsoftonline.com/tfp/' + config['tenant_id'] +'/' + config['policy_name']

def _scopes(config):
    return 'openid ' + config['client_id']

def _token_url(config):
    return _core_url(config) + '/oauth2/v2.0/token'

def _authorize_url(config):
    return _core_url(config) + '/oauth2/v2.0/authorize'
