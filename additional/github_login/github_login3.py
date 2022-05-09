# Github login

oauth = OAuth(app143)

app143.config['GITHUB_CLIENT_ID'] = "190d9903df1402441a93"
app143.config['GITHUB_CLIENT_SECRET'] = "fae13a0ed7b17ff7f926ec68cfe3892b6f7d132b"

github = oauth.register (
  name = 'github',
    client_id = app143.config["GITHUB_CLIENT_ID"],
    client_secret = app143.config["GITHUB_CLIENT_SECRET"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)


@app143.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)


@app143.route('/login/github/authorize')
def github_authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user').json()
    print(f"\n{resp}\n")
    return render_template('check3.html')


@app143.route('/github_logout')
def github_logout():
    session.clear()
    return redirect("/")
