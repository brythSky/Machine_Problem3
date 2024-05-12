import secrets
import sqlite3

from flask import Flask, request, redirect, render_template
from flask_wtf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config['SECRET_KEY'] = b'0bf64056cc0ecaf65653bf72fbfe4ee5'
csrf = CSRFProtect(app)
con = sqlite3.connect("app.db", check_same_thread=False)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    cur = con.cursor()
    form = LoginForm()
    if form.validate_on_submit():
        # Modified for SQL injections
        res = cur.execute("SELECT id FROM users WHERE username = ? AND password = ?",
                        (form.username.data, form.password.data))
        user = res.fetchone()
        if user:
            token = secrets.token_hex()
            cur.execute("INSERT INTO sessions (user, token) VALUES (?, ?)",
                        (user[0], token))
            con.commit()
            response = redirect("/home")
            response.set_cookie("session_token", token)
            return response
        else:
            return render_template("login.html", form=form, error="Invalid username and/or password!")
    return render_template("login.html", form=form)

@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          + "users.id = sessions.user WHERE sessions.token = '"
                          + request.cookies.get("session_token") + "';")
        user = res.fetchone()
        if user:
            res = cur.execute("SELECT message FROM posts WHERE user = " + str(user[0]) + ";")
            posts = res.fetchall()
            return render_template("home.html", username=user[1], posts=posts)

    return redirect("/login")


@app.route("/posts", methods=["POST"])
def posts():
    form = PostForm()
    # Checks for CSRF Token
    if form.validate_on_submit():  
        cur = con.cursor()
        session_token = request.cookies.get("session_token")
        if session_token:
            # Parameterized SQL to avoid SQL injection
            res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                              "users.id = sessions.user WHERE sessions.token = ?", (session_token,))
            user = res.fetchone()
            if user:
                # Modified for XSS attacks
                message = request.form["message"].replace("<", "&leftt;").replace(">", "&rightt;")
                cur.execute("INSERT INTO posts (message, user) VALUES (?, ?)", (message, user[0]))
                con.commit()
                return redirect("/home")

        return redirect("/login")
    return "Invalid submission", 400 



@app.route("/logout", methods=["GET"])
def logout():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          + "users.id = sessions.user WHERE sessions.token = '"
                          + request.cookies.get("session_token") + "'")
        user = res.fetchone()
        if user:
            cur.execute("DELETE FROM sessions WHERE user = " + str(user[0]) + ";")
            con.commit()

    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)

    return response
