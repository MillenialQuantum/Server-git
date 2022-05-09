from crypt import methods
from flask import Flask, render_template, request, json, session, make_response
from flask import redirect, url_for, flash, send_from_directory, abort
from flaskext.mysql import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid, os, pathlib, requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests as req
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.github import make_github_blueprint, github
from flask_oauth import Oauth


app143 = Flask(__name__)
app143.secret_key = 'teodortoreadorflaskspacesapp'

# MySQL configurations
mysql = MySQL()
app143.config['MYSQL_DATABASE_USER'] = 'root'
app143.config['MYSQL_DATABASE_PASSWORD'] = 'tDeF2ghNj9ClH7S0VVdYhRc5cvgSbQtS'
app143.config['MYSQL_DATABASE_DB'] = 'user'
app143.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app143)




#Маршруты сайта
@app143.route("/")
def index():
    return render_template('index.html')


@app143.route('/signup')
def signup():
    return render_template('signup.html')


@app143.route('/signup2',methods=['POST'])
def signUp():
    try:
        # read the posted values from the UI
        _name = request.form['inputName']
        _email = request.form['inputEmail']
        _password = request.form['inputPassword']
 
        # validate the received values
        # if _name and _email and _password:
            # return json.dumps({'html':'<span>All fields good !!</span>'})
        # else:
            # return json.dumps({'html':'<span>Enter the required fields</span>'})
            
        conn = mysql.connect()
        cursor = conn.cursor()
        _hashed_password = generate_password_hash(_password)
        cursor.callproc('sp_createUser',(_name,_email,_hashed_password))
        data = cursor.fetchall()

        if len(data) == 0:
            conn.commit()
            return redirect('/userHome')
            #Не знаю, что это
            #return json.dumps({'message':'User created successfully !'})
        else:
            return json.dumps({'error':str(data[0])})
    
    except Exception as e:
        return json.dumps({'error':str(e)})
        #А что это, тоже не знаю
        #return traceback.format_exc()
    finally:
        cursor.close()
        conn.close()


@app143.route('/signin')
def showSignin():
    if session.get('user'):
        return redirect('/userHome')
    elif session.get('name'):
        return redirect('/userHome')
    if session.get('github'):
        return redirect('/userHome')
    else:
        return render_template('signin.html')


@app143.route('/validateLogin',methods=['POST'])
def validateLogin():
    try:
        _username = request.form['inputEmail']
        _password = request.form['inputPassword']
	
	    # connect to mysql
        con = mysql.connect()
        cursor = con.cursor()
        cursor.callproc('sp_validateLogin',(_username,))
        data = cursor.fetchall()
 
        if len(data) > 0:
            if check_password_hash(str(data[0][3]), _password):
                session['user'] = data[0][0]
                return redirect('/userHome')
            else:
                return render_template('error.html',error = 'Неверный логин или пароль')
        else:
            return render_template('error.html',error = 'Неверный логин или пароль')
  
    except Exception as e:
        return render_template('error.html',error = str(e))


@app143.route('/userHome')
def userHome():
    if session.get('github'):
        return render_template('check3.html')
    elif session.get('user'):
        return render_template('check.html')
    elif session.get('name'):
        return render_template('check2.html')
    else:
        return render_template('error.html',error = 'Вы вне аккаунта')


@app143.route('/title')
def newtitle():
    return render_template('title.html')


@app143.route('/addtitle', methods=['POST'])
def addtitle():
    try:
        # Если внутренняя регистрация
        if session.get('user'):
            _title = request.form['inputTitle']
            _text = request.form['inputText']
            _user = session.get('user')
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_addtitle',(_title,_text,_user))
            data = cursor.fetchall()
 
            if len(data) == 0:
                conn.commit()
                return redirect('/upload')
            else:
                return render_template('error.html',error = 'Мало текста для поста')

        elif session.get('name'):
            _title = request.form['inputTitle']
            _text = request.form['inputText']
            _user = session.get('name')

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_google',(_title,_text,_user))
            data = cursor.fetchall()
 
            if len(data) == 0:
                conn.commit()
                return redirect('/upload')
            else:
                return render_template('error.html',error = 'Мало текста для поста')

        # Google login         
        elif session.get('name'):
            _title = request.form['inputTitle']
            _text = request.form['inputText']
            _user = session.get('name')
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_addtitle',(_title,_text,_user))
            data = cursor.fetchall()
 
            if len(data) == 0:
                conn.commit()
                return redirect('/userHome')
            else:
                return render_template('error.html',error = 'Мало текста для поста')
        else:
            return render_template('error.html',error = 'Вы вне аккаунта')
    except Exception as e:
        return render_template('error.html',error = str(e))
    finally:
        cursor.close()
        conn.close()


@app143.route('/gettitle')
def gettitle():
    try:
        if session.get('user'):
            _user = session.get('user')
            _limit = 2
            _total_records = 0


            con = mysql.connect()
            cursor = con.cursor()
            cursor.callproc('sp_GetTitleByUser',(_user,))
            titles = cursor.fetchall()
 
            titles_dict = []
            for title in titles:
                wish_dict = {
                        'Id': title[0],
                        'Title': title[1],
                        'Text': title[2]}
                titles_dict.append(wish_dict)
 
            return json.dumps(titles_dict)
        else:
            return render_template('error.html', error = 'Вы вне аккаунта')
    except Exception as e:
        return render_template('error.html', error = str(e))


@app143.route('/gettitles')
def gettitles():
    try:
        con = mysql.connect()
        cursor = con.cursor()
        cursor.callproc('sp_GetTitles')
        titles = cursor.fetchall()
 
        titles_dict = []
        for title in titles:
            wish_dict = {
                    'Id': title[0],
                    'Title': title[1],
                    'Text': title[2]}
            titles_dict.append(wish_dict)
 
        return json.dumps(titles_dict)
    except Exception as e:
        return render_template('error.html', error = str(e))


@app143.route('/getTitleById',methods=['POST'])
def getTitleById():
    try:
        if session.get('user'):
 
            _id = request.form['id']
            _user = session.get('user')
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetTitleById',(_id,_user))
            result = cursor.fetchall()
 
            wish = []
            wish.append({'Id':result[0][0],'Title':result[0][1],'Text':result[0][2]})
 
            return json.dumps(wish)
        else:
            return render_template('error.html', error = 'Вы вне аккаунта')
    except Exception as e:
        return render_template('error.html',error = str(e))


@app143.route('/updateTitle', methods=['POST'])
def updateTitle():
    try:
        if session.get('user'):
            _user = session.get('user')
            _title = request.form['title']
            _text = request.form['text']
            _title_id = request.form['id']
 
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_updateTitle',(_title,_text,_title_id,_user))
            data = cursor.fetchall()
 
            if len(data) == 0:
                conn.commit()
                return json.dumps({'status':'OK'})
            else:
                return json.dumps({'status':'ERROR'})
    except Exception as e:
        return json.dumps({'status':'Вы вне аккаунта'})
    finally:
        cursor.close()
        conn.close()


@app143.route('/deleteTitle',methods=['POST'])
def deleteTitle():
    try:
        if session.get('user'):
            _id = request.form['id']
            _user = session.get('user')
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_deleteTitle',(_id,_user))
            result = cursor.fetchall()
 
            if len(result) == 0:
                conn.commit()
                return json.dumps({'status':'OK'})
            else:
                return json.dumps({'status':'An Error occured'})
        else:
            return render_template('error.html',error = 'Вы вне аккаунта')
    except Exception as e:
        return json.dumps({'status':str(e)})
    finally:
        cursor.close()
        conn.close()

@app143.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


@app143.route('/posts')
def posts():
    return render_template('read.html')




# Загрузка файлов

app143.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app143.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

basedir = os.path.abspath(os.path.dirname(__file__))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
     
 
@app143.route('/upload')
def home():
    return render_template('upload.html')
 
@app143.route('/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No image selected for uploading')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(basedir, app143.config['UPLOAD_FOLDER'], filename))
        #print('upload_image filename: ' + filename)
        flash('Image successfully uploaded and displayed below')
        return render_template('upload.html', filename=filename)
    else:
        flash('Allowed image types are - pdf, png, jpg, jpeg, gif')
        return redirect(request.url)
 
@app143.route('/display/<filename>')
def display_image(filename):
    #print('display_image filename: ' + filename)
    return redirect(url_for('static', filename='uploads/' + filename), code=301)




# Google Login

GOOGLE_CLIENT_ID = "492287753148-708sfc6b20mtrprleumnolq51l87enhi.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'google_secret.json') #set the path to where the .json file you got Google console is

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #this is to set our environment to https because OAuth 2.0 only supports https environments

flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 class that stores all the information on how we want to authorize our users
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="http://propro.ds20-hel1-hz.deespaces.us/callback"  #and the redirect URI is the point where the user will end up after the authorization
)


def login_is_required(function):  #a function to check if the user is authorized or not
    def wrapper(*args, **kwargs):
        if "google_id" not in session:  #authorization required
            return abort(401)
        else:
            return function()

    return wrapper

@app143.route("/google_login")  #the page where the user can login
def login():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)


@app143.route("/callback")  #this is the page that will handle the callback process meaning process after the authorization
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  #state does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = req.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")  #defing the results to show on the page
    session["name"] = id_info.get("name")
    return redirect("/protected_area")  #the final page where the authorized users will end up


@app143.route("/protected_area")  #the page where only the authorized users can go to
@login_is_required
def protected_area():
    return render_template("check2.html")


@app143.route("/google_logout")  #the logout page and function
def google_logout():
    session.clear()
    return redirect("/")




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
    session['github'] = github.get('user').json()
    return render_template('check3.html')


@app143.route('/github_logout')
def github_logout():
    session.clear()
    return redirect("/")




# Facebook login




#Приложение работает

if __name__ == "__main__":
    app143.run(host="0.0.0.0", debug=True)
