from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, Flask
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

app = Flask(__name__)
# app.secret_key = str(uuid.uuid4())
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_DB'] = 'cryptoApp'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# app.config['MYSQL_PASSWORD'] = '123456'

PATH = "data/database.sqlite"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+PATH
db = SQLAlchemy(app)
# sql = mysql.connector.connect(
#     host ="localhost",
#     user = "root",
#     passwd = "1234",
#     database = "cryptoApp"
# )

class User(db.Model):
    __tablename__ = "users"
    uesrname = db.Column(db.String(80), unique=True, primary_key=True)
    password = db.Column(db.String(120), unique=True)
    def __init__(self, username, password):
        self.uesrname = username
        self.password = password
class Chat(db.Model):
    __tablename__ = "chats"
    sender = db.Column(db.String(80), unique=True, primary_key=True)#, nullable=False)
    chat = db.Column(db.String(120))#, nullable=False)
    receiver = db.Column(db.String(80))#, nullable=False)

    def __init__(self, sender, chat, receiver):
        self.sender = sender
        self.chat = chat
        self.receiver = receiver

# db.create_all()

encrypt = Fernet(Fernet.generate_key())
# db.Query.addcolumn()

loginManager = LoginManager()
loginManager.init_app(app)

@app.route('/')
def index():
    return render_template('/index.html')


@app.route('/login')
def login():
    form = UserForm(request.form)
    if request.method == 'POST':

        username = form.username.data
        password = form.password.data
        # db = get_db()
        error = None
        usernameSalt = str(uuid.uuid4())
        encryptedUsernameSalt = encrypt.encrypt(usernameSalt)

        passwordHash = Bcrypt.generate_password_hash(usernameSalt+"#"+form.password)
        # cur = sql.cursor()
        # cur = 
        # cur.execute("INSERT INTO users(username, password, usernameSalt, encryptedUsernameSalt, passwordHash) VALUES(%s, %s, %s, %s, %s)", (username, password, usernameSalt, encryptedUsernameSalt, passwordHash))

        # sql.commit()
        # cur.close()
        flash("LMAO")

        return render_template("/register.html")
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


    return render_template('/login.html', form=form)

@app.route('/inbox')
def inbox():
    return render_template('/inbox.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        # db = get_db()
        error = None
        usernameSalt = str(uuid.uuid4())
        encryptedUsernameSalt = encrypt.encrypt(usernameSalt)

        passwordHash = Bcrypt.generate_password_hash(usernameSalt+"#"+form.password)
        # cur = sql.cursor()
        # cur = 
        # cur.execute("INSERT INTO users(username, password, usernameSalt, encryptedUsernameSalt, passwordHash) VALUES(%s, %s, %s, %s, %s)", (username, password, usernameSalt, encryptedUsernameSalt, passwordHash))

        # sql.commit()
        # cur.close()
        flash("LMAO")

        return render_template("/register.html")
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

class UserForm(Form):
    username = StringField('UserName', [validators.Length(min=1, max=50)])
    password = PasswordField('Password', [validators.Length(min=3, max=50)])
    submit = SubmitField("user")
class chatForm(Form):
    username = StringField('UserName', [validators.Length(min=1, max=50)])
    chat = TextAreaField("chat", [validators.Length(min=1, max=200)])
    submit = SubmitField("chat")