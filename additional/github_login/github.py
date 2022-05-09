from flask import Flask, url_for, request, redirect, render_template, session
import os, json
from flask_dance.contrib.github import make_github_blueprint, github



app = Flask(__name__)
app.config["SECRET_KEY"]= "githubflaskappsecretkey"

github_blueprint = make_github_blueprint(client_id='a240e7ae9b1f7f6b8d6f',
                                         client_secret='2e8d282e2a621a971f21b716cf566786b2a779af')

app.register_blueprint(github_blueprint, url_prefix='/github_login')

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 


@app.route('/')
def home():
    return redirect(url_for('github.login'))


@app.route('/github_login')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))

    account_info = github.get('/user')

    if account_info:
        account_info_json = account_info.json()
        session['github'] = account_info_json['login']
        print(session['github'])
        return render_template('home.html')

    return '<h1>Request failed!</h1>'


@app.route('/github_logout')
def github_logout():
    session.pop('github')
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)