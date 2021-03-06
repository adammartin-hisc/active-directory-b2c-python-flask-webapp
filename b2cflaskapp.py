from flask import Flask, redirect, url_for, session, request, render_template
from jose import jws
import json, requests, uuid, yaml
from microsoft_client import microsoft_client, keys
from security.user_operations import get_user

with open("config/config.yml", 'r') as ymlfile:
    config = yaml.load(ymlfile)

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'

# This sample loads the keys on boot, but for production
# the keys should be refreshed either periodically or on
# jws.verify fail to be able to handle a key rollover
keys = keys(config)
microsoft = microsoft_client(config, app)

@app.route('/')
def index():
    return render_template('hello.html')

@app.route('/login', methods = ['POST', 'GET'])
def login():
    if 'microsoft_token' in session:
        return redirect(url_for('me'))

    return _authenticate(session, microsoft)

@app.route('/logout', methods = ['POST', 'GET'])
def logout():
    session.pop('microsoft_token', None)
    session.pop('claims', None)
    session.pop('state', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    _verify_state(session, request)
    response = microsoft.authorized_response()

    if response is None:
        return _access_denied_message(response)

    _store_results(session, response)
    return redirect(url_for('me'))

@app.route('/me')
def me():
    token = session['microsoft_token'][0]
    claims = session['claims']
    email = claims['emails'][0]

    return render_template('me.html', me=str(claims), user_identity=get_user(email, config))

# If library is having trouble with refresh, uncomment below and implement refresh handler
# see https://github.com/lepture/flask-oauthlib/issues/160 for instructions on how to do this
# Implements refresh token logic
# @app.route('/refresh', methods=['POST'])
# def refresh():

@microsoft.tokengetter
def get_microsoft_oauth_token():
    return session.get('microsoft_token')

if __name__ == '__main__':
    app.run()

def _authenticate(session, microsoft_client):
    session['state'] = uuid.uuid4()
    return microsoft_client.authorize(callback=url_for('authorized', _external=True), state=session['state'])

def _access_denied_message(request):
    return "Access Denied: Reason=%s\nError=%s" % (response.get('error'), request.get('error_description'))

def _verify_state(session, request):
    if str(session['state']) != str(request.args['state']):
        raise Exception('State has been tampered with, end authentication')

def _store_results(session, response):
    print("Response: " + str(response))
    # Okay to store this in a local variable, encrypt if it's going to client
    # machine or database. Treat as a password.
    access_token = response['access_token']
    session['microsoft_token'] = (access_token, '')
    session['claims'] = json.loads(jws.verify(access_token, keys, algorithms=['RS256']))
