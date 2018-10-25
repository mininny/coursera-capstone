from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, Flask, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from passlib.hash import sha256_crypt
import os
import functools
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SubmitField
from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
import mysql.connector
import sqlite3
from sqlalchemy import create_engine
import tempfile
import zipfile
from time import gmtime, strftime

app = Flask(__name__)
# app.secret_key = str(uuid.uuid4())
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_DB'] = 'cryptoApp'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# app.config['MYSQL_PASSWORD'] = '123456'
app.secret_key = "verysecret"
PATH = os.path.join(tempfile.gettempdir(), 'init.db')
# engine = create_engine("sqlite:////data/test.db")

# flask_sqlalchemy.sqlalchemy.create_engine("sqlite:///data/database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+PATH
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
# sql = mysql.connector.connect(
#     host ="localhost",
#     user = "root",
#     passwd = "1234",
#     database = "cryptoApp"
# )
@login_manager.user_loader
def load_user(username):
    return User.query.filter_by(username = username).first()

class User(db.Model):
    __tablename__ = "users"
    username = db.Column(db.String(80), unique=True, primary_key=True)
    password = db.Column(db.String(120), unique=True)
    def __init__(self, username, password):
        self.username = username
        self.password = password
    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.username)
        
class Chat(db.Model):
    __tablename__ = "chats"
    sender = db.Column(db.String(80))#, nullable=False)
    chat = db.Column(db.String(120))#, nullable=False)
    receiver = db.Column(db.String(80))#, nullable=False)
    time = db.Column(db.String(30), primary_key=True)
    def __init__(self, sender, receiver, chat):
        self.sender = sender
        self.receiver = receiver
        self.chat = chat
        self.time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        print("Sending chat from %s to %s", (sender, receiver))
#     def __init__(self, sender, chat, receiver):
#         self.sender = sender
#         self.chat = chat
#         self.receiver = receiver

db.create_all()
def initDB():
    db.init_app(app)
    db.app = app
    db.create_all()


# initDB()
app.debug = True
print("INITIZLIAED")
encrypt = Fernet(Fernet.generate_key())
# db.Query.addcolumn()


@app.route('/')
def index():
    return render_template('/index.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = UserForm(request.form)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']#form.password.data
        usernameSalt = str(uuid.uuid4())
        print(username)
        results = db.engine.execute("SELECT * FROM users WHERE username='{0}'".format(username))
        for result in results:
            # Get stored hash
            print(result)
            data = result
            password_candidate = data['password']
            user = User.query.filter_by(username=form.username.data).first()
            # Compare Passwords
            if password_candidate == password:
                # Passed
                session['logged_in'] = True
                session['username'] = username
                login_user(user)
                flash('You are now logged in', 'success')
                print("Logged In'")
                return redirect(url_for('inbox'))
            else:
                error = 'Invalid login'
                print("Wrong password")
                return render_template('login.html', error=error)
            # Close connection
        error = 'Username not found'
        print("Username not found while logging in")
        return render_template('login.html', error=error)
        # encryptedUsernameSalt = encrypt.encrypt(usernameSalt)
        # passwordHash = Bcrypt.generate_password_hash(usernameSalt+"#"+form.password)
        # flash("Loggin In")
        
        # login_user(user)
        # return redirect(url_for("inbox"))
        # return render_template("/register.html")
    return render_template('/login.html', form=form)

@app.route("/logout")
def logout():
    if session["logged_in"]:
        session.clear()
        flash("Logged out of service", 'success')
        return redirect(url_for('login'))
    else:
        flash("Already logged out", 'failure')
        return redirect(url_for('login'))

@app.route('/inbox', methods=('GET','POST'))
def inbox():
    form = chatForm(request.form)
    if request.method=='GET':
        if current_user.is_authenticated:
            user = current_user.get_id()
            chatList = Chat.query.filter_by(receiver = user).all()
        return render_template('/inbox.html', form=form, chatList = chatList)
    if request.method=='POST':
        if current_user.is_authenticated:
            user = current_user.get_id()
            chatList = Chat.query.filter_by(receiver = user).all()
        return render_template('/inbox.html', form=form)
    return render_template('/inbox.html')

@app.route('/outbox', methods=('GET', 'POST'))
def outbox():
    form = chatForm(request.form)
    if request.method == "POST":
        if current_user.is_authenticated:
            receiver = form.receiver.data
            chat = form.chat.data
            newChat = Chat(current_user.get_id(), receiver, chat)
            db.session.add(newChat)
            db.session.commit()
            return redirect(url_for("inbox"))
    return render_template("/outbox.html")


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        usernameSalt = str(uuid.uuid4())
        # encryptedUsernameSalt = encrypt.encrypt(usernameSalt)
        # passwordHash = Bcrypt.generate_password_hash(usernameSalt+"#"+form.password)
        newUser = User(username, password)
        # db.engine.execute("INSERT INTO users(username, password) VALUES('{0}','{1}')".format(username, password))
        db.session.add(newUser)
        db.session.commit()

        # sql.commit()
        # cur.close()
        flash("LMAO")

        return redirect(url_for("login"))
        # if not username:
        #     error = 'Username is required.'
        # elif not password:
        #     error = 'Password is required.'
        # elif db.execute(
        #     'SELECT id FROM user WHERE username = ?', (username,)
        # ).fetchone() is not None:
        #     error = 'User {} is already registered.'.format(username)

        # if error is None:
        #     db.execute(
        #         'INSERT INTO user (username, password) VALUES (?, ?)',
        #         (username, generate_password_hash(password))
        #     )
        #     db.commit()
        #     return redirect(url_for('auth.login'))
    return render_template('/register.html', form=form)

@app.route("/dbdump", methods=["GET"])
def dbdump():
    if request.method == "GET":
        # get DB dump in memory
        conn = sqlite3.connect(PATH)
        dump_data = '\n'.join(conn.iterdump())
        conn.close()
        # zip the dump data into a file
        dumpfile = str(uuid.uuid4())+".dump.zip"
        zfile = zipfile.ZipFile(dumpfile, mode="w", compression=zipfile.ZIP_DEFLATED)
        zfile.writestr("dump.sql", dump_data)
        zfile.close()
        return send_file(dumpfile, as_attachment=True)
    # handle other request methods
    else:
        error = "Method not allowed"
        return render_template("index.html", error = error)

class UserForm(Form):
    username = StringField('UserName', [validators.Length(min=1, max=50)])
    password = PasswordField('Password', [validators.Length(min=3, max=50)])
    submit = SubmitField("user")
class chatForm(Form):
    receiver = StringField('receiver', [validators.Length(min=1, max=50)])
    chat = TextAreaField("chat", [validators.Length(min=1, max=200)])
    submit = SubmitField("chat")

