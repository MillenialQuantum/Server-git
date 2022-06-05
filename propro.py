from crypt import methods
from unicodedata import name
from flask import Flask, render_template, request, json, session, Response
import time
from flask import redirect, url_for, flash, abort
from flaskext.mysql import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, pathlib, requests, datetime
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests as req
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
import pymongo

app143 = Flask(__name__)
app143.secret_key = 'teodortoreadorflaskspacesapp'

# MySQL configurations
mysql = MySQL()
app143.config['MYSQL_DATABASE_USER'] = 'root'
app143.config['MYSQL_DATABASE_PASSWORD'] = 'tDeF2ghNj9ClH7S0VVdYhRc5cvgSbQtS'
app143.config['MYSQL_DATABASE_DB'] = 'user'
app143.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app143)


#Mongodb configurations
client = pymongo.MongoClient('mongodb://127.0.0.1:27017')
db = client.auth
coll = db.users


# Регистрация, кабинеты и прочее
@app143.route("/")
def index():
    return render_template('index.html')


@app143.route('/signup')
def signup():
    return render_template('signup.html')


@app143.route('/signup2',methods=['POST'])
def signUp():
    try:
        new = {
            "_first_name" : request.form['inputFirst_name'],
            "_last_name" : request.form['inputLast_name'],
            "_email" : request.form['inputEmail'],
            "_password" : generate_password_hash(request.form['inputPassword']),
            "_created" : str(time.time()).split('.')[0],
            "_location" : request.form['inputLocation']
        }
     
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.callproc('sp_createUser',(new["_first_name"], new["_last_name"], new["_email"], new["_password"], new["_created"], new["_location"]))
        data = cursor.fetchall()

        if len(data) == 0:
            conn.commit()
            _object = "user"
            _object_name = new["_email"]
            _event = "added"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            return redirect('/userHome')
        else:
            return json.dumps({'error':str(data[0])})
    
    except Exception as e:
        return json.dumps({'error':str(e)})
    finally:
        cursor.close()
        conn.close()


@app143.route('/signin')
def showSignin():
    if session.get('user') or session.get('google') or session.get('github') or session.get('facebook'):
        return redirect('/userHome')
    else:
        return render_template('signin.html')


@app143.route('/validateLogin',methods=['POST'])
def validateLogin():
    try:
        _username = request.form['inputEmail']
        _password = request.form['inputPassword']
	
	    # connect to mysql
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.callproc('sp_validateLogin',(_username,))
        data = cursor.fetchall()
 
        if len(data) > 0:
            if check_password_hash(str(data[0][4]), _password):
                session['user'] = data[0][0]
                _object = "user"
                _object_name = data[0][3]
                _event = "logged in"
                _time = str(time.time()).split('.')[0]
                cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
                event = cursor.fetchall()
                conn.commit()
                return redirect('/userHome')
            else:
                return render_template('error.html',error = 'Неверный логин или пароль')
        else:
            return render_template('error.html',error = 'Пользователя не существует')
  
    except Exception as e:
        return render_template('error.html',error = str(e))

    finally:
        cursor.close()
        conn.close()


@app143.route('/userHome')
def userHome():
    if session.get('github') or session.get('facebook') or session.get('google'):
        return render_template('check2.html')
    elif session.get('user'):
        conn = mysql.connect()
        cursor = conn.cursor()
        _user = str(session['user'])
        cursor.callproc('sp_get_info',(_user,))
        data = cursor.fetchall()
        new = {
            "_first_name" : data[0][1] or None,
            "_last_name" : data[0][2] or None,
            "_email" : data[0][3] or None,
            "_password" : data[0][4] or None,
            "_google" : data[0][5] or None,
            "_github" : data[0][10] or None,
            "_avatar" : data[0][4] or None,
        }
        name = data[0][1] + ' ' + data[0][2]
        if data[0][7]:
            filename = '/uploads/' + data[0][7]
            return render_template('check.html', name=name, filename=filename, google=new['_google'], github=new['_github'])
        else:
            return render_template('check.html', name=name, google=new['_google'], github=new['_github'])
    else:
        return render_template('error.html',error = 'Вы вне аккаунта')


@app143.route('/profile_image')
def profile_image():
    return render_template('profileimage.html')

@app143.route('/profile_image', methods=['POST'])
def upload2():
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
        conn = mysql.connect()
        cursor = conn.cursor()
        _file = filename
        _user = str(session['user'])
        cursor.callproc('sp_add_avatar',(_user, _file))
        cursor.fetchall()
        conn.commit()
        return redirect('/userHome')
    else:
        flash('Allowed image types are - pdf, png, jpg, jpeg, gif')
        return redirect(request.url)

@app143.route('/logout')
def logout():
    if session.get('user'):
        conn = mysql.connect()
        cursor = conn.cursor()
        _user = str(session['user'])
        cursor.callproc('sp_get_info',(_user,))
        data = cursor.fetchall()
        _object = "user"
        _object_name = data[0][3]
        _event = "logged out"
        _time = str(time.time()).split('.')[0]
        cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
        event = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        session.clear()
        return redirect('/')
    else:
        return redirect('/')




# Все, что касается написания текстов
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
            _created = str(time.time()).split('.')[0]
 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_add_title',(_title,_text,_user,_created))
            data = cursor.fetchall()
 
            if len(data) == 0:
                conn.commit()
                _object = "title"
                _object_name = _title
                _event = "added"
                _time = str(time.time()).split('.')[0]
                cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
                event = cursor.fetchall()
                conn.commit()
                return redirect('/upload')
            else:
                return render_template('error.html',error = 'Мало текста для поста')
    except Exception as e:
        return str(e)
    finally:
        cursor.close()
        conn.close()


@app143.route('/gettitle')
def gettitle():
    try:
        if session.get('user'):
            _user = session.get('user')

            con = mysql.connect()
            cursor = con.cursor()
            cursor.callproc('sp_GetTitleByUser',(_user))
            titles = cursor.fetchall()
 
            titles_dict = []
            for title in titles:
                wish_dict = {
                        'Id': title[0],
                        'Title': title[1],
                        'Text': title[2],
                        'Author': title[3],
                        'Image': title[4],
                        'Created': datetime.datetime.fromtimestamp(int(title[5])) or "null"}
                titles_dict.append(wish_dict)
 
            return json.dumps(titles_dict)
        else:
            return render_template('error.html', error = 'Вы вне аккаунта')
    except Exception as e:
        return render_template('error.html', error = str(e))


@app143.route('/posts')
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
                    'Text': title[2],
                    'Author': title[3],
                    'Image': title[4],
                    'Created': datetime.datetime.fromtimestamp(int(title[5])) or "null"}
            titles_dict.append(wish_dict)
    
        return render_template('new.html', posts=titles_dict)
    except Exception as e:
        return render_template('error.html', error = str(e))
    finally:
        cursor.close()
        con.close()


@app143.route('/post/<id>')
def show_post(id):
    try:
        _id = id
        con = mysql.connect()
        cursor = con.cursor()
        cursor.callproc('sp_GetTitle',(_id,))
        title = cursor.fetchall()
        yo = {
                'Id': title[0][0],
                'Title': title[0][1],
                'Text': title[0][2],
                'Author': title[0][3],
                'Created': datetime.datetime.fromtimestamp(int(title[0][5])) or "null"}
        _user = str(yo['Author'])
        cursor.callproc('sp_get_info',(_user,))
        data = cursor.fetchall()
        name = data[0][1] + ' ' + data[0][2]
        if title[0][4]:
            yo['Image'] = '/uploads/' + title[0][4]
            return render_template('read_title.html', post=yo, filename=yo['Image'], name=name)
        else:
            return render_template('read_title.html', post=yo, name=name)

    except Exception as e:
        return render_template('error.html', error = str(e))
    finally:
        cursor.close()
        con.close()


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







# Загрузка файлов

app143.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app143.config['MAX_CONTENT_LENGTH'] = 32 * 2048 * 2048
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
    try:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(basedir, app143.config['UPLOAD_FOLDER'], filename))
            conn = mysql.connect()
            cursor = conn.cursor()
            _image = filename
            cursor.callproc('sp_addImage',(_image,))
            cursor.fetchall()
            conn.commit()
            return redirect('/userHome')
        else:
            flash('Allowed image types are - pdf, png, jpg, jpeg, gif')
            return redirect(request.url)
    except Exception as e:
        return json.dumps({'status':str(e)})
    finally:
        cursor.close()
        conn.close()


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
    session["google"] = id_info.get("name")
    
    try:
        new = {
            "_nickname" : id_info.get("given_name") + " " + id_info.get("family_name") or "null",
            "_first_name" : session["google"].split()[0],
            "_last_name" : session["google"].split()[1].title(),
            "_created" : str(time.time()).split('.')[0],
            "_location" : id_info.get("location") or "null",
            "_status" : "active",
            "_birthday" : id_info.get("birthday") or "null",
            "_auth_provider" : "google",
            "_auth_provider_user_id" : session["google_id"],
            "_email" : id_info.get("email"),
            "_gender" : id_info.get("gender") or "null",
            "_avatar" : id_info.get("picture") or "null"
        }

        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.callproc('sp_add_auth_provider',
            (new["_nickname"], new["_first_name"], 
            new["_last_name"], new["_created"], 
            new["_location"], new["_status"], 
            new["_birthday"], new["_auth_provider"], 
            new["_auth_provider_user_id"], new["_email"], 
            new["_gender"], new["_avatar"])
        )  
        data = cursor.fetchall()

        if len(data) == 0:
            conn.commit()
            _object = "google_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "added"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            _object = "google_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "logged in"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            return redirect('/userHome')
        else:
            _object = "google_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "logged in"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            return redirect('/userHome') 
    
    except Exception as e:
        return json.dumps({'error':str(e)})
    finally:
        cursor.close()
        conn.close()
    

    
@app143.route("/protected_area")  #the page where only the authorized users can go to
@login_is_required
def protected_area():
    return render_template('check2.html')


@app143.route("/social_logout")  #the logout page and function
def google_logout():
    conn = mysql.connect()
    cursor = conn.cursor()
    if session.get('google'):
        _user = session['google_id']
    elif session.get('github'):
        _user = session['github_id']
    cursor.callproc('sp_social_info',(_user,))
    data = cursor.fetchall()
    _object = "google_user"
    _object_name = data[0][10]
    _event = "logged out"
    _time = str(time.time()).split('.')[0]
    cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
    event = cursor.fetchall()
    conn.commit()
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
    session['github_id'] = session['github']["id"]

    try:
        new = {
            "_nickname" : session['github']["login"] or "null",
            "_first_name" : session['github'].get("name") or "null",
            "_last_name" : session['github'].get("name") or "null",
            "_created" : str(time.time()).split('.')[0],
            "_location" : session['github']["location"] or "null",
            "_status" : "active",
            "_birthday" : session['github'].get("birthday") or "null",
            "_auth_provider" : "github",
            "_auth_provider_user_id" : str(session['github']["id"]),
            "_email" : session['github'].get("email") or "null",
            "_gender" : session['github'].get("gender") or "null",
            "_avatar" : session['github'].get("avatar_url") or "null"
        }

        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.callproc('sp_add_auth_provider',
            (new["_nickname"], new["_first_name"], 
            new["_last_name"], new["_created"], 
            new["_location"], new["_status"], 
            new["_birthday"], new["_auth_provider"], 
            new["_auth_provider_user_id"], new["_email"], 
            new["_gender"], new["_avatar"])
        )  
        data = cursor.fetchall()

        if len(data) == 0:
            conn.commit()
            _object = "github_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "added"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            _object = "github_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "logged in"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            return redirect('/userHome')
        else:
            _object = "github_user"
            _object_name = new["_auth_provider_user_id"]
            _event = "logged in"
            _time = str(time.time()).split('.')[0]
            cursor.callproc('sp_add_event',(_object, _object_name, _event, _time))
            event = cursor.fetchall()
            conn.commit()
            return redirect('/userHome')
    
    except Exception as e:
        return json.dumps({'error':str(e)})
    finally:
        cursor.close()
        conn.close()

# На всякий случай(выход осуществляется через маршрут social_logout)
#@app143.route('/github_logout')
#def github_logout():
    #session.clear()
    #return redirect("/")




# Facebook login


app143.config["FACEBOOK_OAUTH_CLIENT_ID"] = '563843535081424'
app143.config["FACEBOOK_OAUTH_CLIENT_SECRET"] = '036cb4b29f9a8ab38637befb640c3bb0'


facebook_blueprint = make_facebook_blueprint(client_id=app143.config["FACEBOOK_OAUTH_CLIENT_ID"],
                                            client_secret=app143.config["FACEBOOK_OAUTH_CLIENT_SECRET"])                                   

app143.register_blueprint(facebook_blueprint, url_prefix="/login")


@app143.route('/facebook_login')
def facebook_login():
    return redirect(url_for("facebook.login"))


@app143.route('/login/facebook/authorized')
def facebook_authorized():
    account_info = facebook.get('/user').json()
    session['facebook'] = account_info['login']
    
    return account_info


@app143.route('/facebook_logout')
def facebook_logout():
    session.clear()
    return redirect('/')


# Для проверки
@app143.route('/banger')
def banger():
    data = db.users.find()
    return data

#Приложение работает

if __name__ == "__main__":
    app143.run(host="0.0.0.0", debug=True)
