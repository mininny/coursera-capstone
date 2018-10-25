from flask import (
    flash, redirect, render_template, request, session, url_for, Flask, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
import os
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SubmitField
from cryptography.fernet import Fernet
import uuid
import sqlite3
from sqlalchemy import create_engine
import tempfile
import zipfile
from time import gmtime, strftime
import base64
app = Flask(__name__)

app.secret_key = "verysecret"
PATH = os.path.join(tempfile.gettempdir(), 'testestesbase.db')

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+PATH
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(username):
    return User.query.filter_by(username = username).first()

class User(db.Model):
    __tablename__ = "users"
    username = db.Column(db.String(80), unique=True, primary_key=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)
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
    sender = db.Column(db.String(256))
    chat = db.Column(db.String(256))
    receiver = db.Column(db.String(80))
    time = db.Column(db.String(30), primary_key=True)
    def __init__(self, sender, receiver, chat):
        self.sender = sender
        self.receiver = receiver
        self.chat = chat
        self.time = strftime("%Y-%m-%d %H:%M:%S", gmtime())

db.create_all()



app.debug = True
print("INITIZLIAED")
encrypt = Fernet(b'CC9R5uGZBs8obPmSnPnIipZek-Rfox2lzDm-8zCSTgE=')

@app.route('/')
def index():
    return render_template('/index.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = UserForm(request.form)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        usernameSalt = str(uuid.uuid4())
        results = db.engine.execute("SELECT * FROM users WHERE username='{0}'".format(username))
        for result in results:
            data = result
            password_candidate = data['password']
            if sha256_crypt.verify(password, password_candidate):
                user = User.query.filter_by(username=form.username.data).first()
                login_user(user)
                flash('Successfully logged in', 'success')
                return redirect(url_for('inbox'))
            else:
                flash("Wrong Password", "error")
                return render_template('login.html', form=form)
        flash("No matching username", "error")
        return render_template('login.html', form=form)
    return render_template('/login.html', form=form)

@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("Logging out of service", 'success')
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/inbox', methods=('GET', 'POST'))
def inbox():
    form = chatForm(request.form)
    if request.method=='GET':
        if current_user.is_authenticated:
            user = current_user.get_id()
            chatList = Chat.query.filter_by(receiver = user).all()
            decryptedChatList = []
            for chat in chatList:
                print(str(chat.sender))
                decodedSender = encrypt.decrypt(bytes(str(chat.sender), 'utf-8')[2:-1]).decode('utf-8')
                print(decodedSender)
                decodedChat = encrypt.decrypt(bytes(str(chat.chat), 'utf-8')[2:-1]).decode('utf-8')
                decryptedChat = Chat(decodedSender, str(chat.receiver), decodedChat)
                decryptedChatList.append(decryptedChat)
            return render_template('/inbox.html', form=form, chatList = decryptedChatList)
        else:
            logout()
            flash("Not authenticated. Logging out", "error")
            return redirect(url_for("login"))
    if request.method=='POST':
        if current_user.is_authenticated:
            return render_template('/inbox.html', form=form)
        else:
            logout()
            return render_template('/login.html')
    return render_template('/inbox.html')        

@app.route('/outbox', methods=('GET','POST'))
def outbox():
    form = chatForm(request.form)
    if request.method == "POST":
        if current_user.is_authenticated:
            if form.receiver.data and form.chat.data:
                receiver = form.receiver.data
                chat = encrypt.encrypt(bytes(str(form.chat.data), 'utf-8'))
                newChat = Chat(encrypt.encrypt(bytes(str(current_user.get_id()), 'utf-8')), receiver, chat)
                db.session.add(newChat)
                db.session.commit()
                flash("Successfully sent message", "success")
                return redirect(url_for("inbox"))
            else:
                flash("receiver of chat doesn't exist", "error")
                return redirect(url_for('outbox'))
        else:
            flash("Not Authenticated!", "error")
            logout()
            return render_template("/outbox.html")
    if request.method == "GET":
        if current_user.is_authenticated:
            return render_template("/outbox.html", form=form)
        else:
            flash("Not Authenticated!", "error")
            logout()
            return redirect(url_for("login"))
    return render_template("/outbox.html")


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        if not User.query.filter_by(username=form.username.data).first():
            username = form.username.data
            password = sha256_crypt.encrypt(str(form.password.data))
            newUser = User(username, password)
            db.session.add(newUser)
            db.session.commit()
            flash("Successfully Registered", "success")
            return redirect(url_for("login"))
        else:
            flash("Same Username already exists!", "error")
            return render_template('/register.html', form=form)
    return render_template('/register.html', form=form)

@app.route("/dbdump", methods=["GET"])
def dbdump():
    if request.method == "GET":
        conn = sqlite3.connect(PATH)
        dumpData = '\n'.join(conn.iterdump())
        conn.close()
        dumpFile = str(uuid.uuid4())+".dump.zip"
        zipFile = zipfile.ZipFile(dumpFile, mode="w", compression=zipfile.ZIP_DEFLATED)
        zipFile.writestr("dump.sql", dumpData)
        zipFile.close()
        return send_file(dumpFile, as_attachment=True)
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

