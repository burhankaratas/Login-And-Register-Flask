from flask import Flask,render_template,flash,redirect,url_for,session,logging,request,g
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators, SubmitField
from passlib.hash import sha256_crypt 
from functools import wraps
import hashlib


app = Flask(__name__)
app.secret_key= "isdfgrhsri"


app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "loginregister"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)


@app.route("/")
def index():
    if session["logged_in"] == True:
        return render_template("index.html")
    
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "GET":
        return render_template("register.html", form=form)

    elif request.method == "POST" and form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        passwordAgain = form.passwordAgain.data

        if password == passwordAgain:
            cursor = mysql.connection.cursor()

            sorgu = "SELECT * FROM users WHERE username = %s"
            query = cursor.execute(sorgu, (username,))

            if query > 0:
                flash("Böyle bir kullanıcı zaten kayıtlı. Lütfen başka bir isim deneyiniz.", "danger")
                return redirect(url_for("register"))
            
            else:
                hashed_password = sha256_crypt.encrypt(password)

                sorgu2 = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
                cursor.execute(sorgu2, (username, email, hashed_password))
                mysql.connection.commit() 

                cursor.close()

                flash("Kayıt işleminiz gerçekleştirilmiştir. Hesabınıza erişmek için lütfen giriş yapınız.", "success")
                return redirect(url_for("login"))
        else:
            flash("Şifreleriniz uyuşmuyor lütfen tekrar deneyiniz.", "danger")
            return redirect(url_for("register"))


@app.route("/login", methods = ["GET", "POST"])
def login():
    form = LoginForm(request.form)
    
    if request.method == "GET":
        return render_template("login.html", form = form)
    
    elif request.method == "POST":
        username = form.username.data
        password = form.password.data


        cursor = mysql.connection.cursor()

        sorgu = "SELECT * FROM users WHERE username = %s"
        query = cursor.execute(sorgu, (username,))

        if query > 0:
            data = cursor.fetchone()
            
            if sha256_crypt.verify(password, data["password"]):
                session["logged_in"] = True
                session["username"] = username

                flash("Başarıyla giriş yaptınız. Anasayfaya yönlendiriliyorsunuz...", "success")
                return redirect(url_for("index"))

            else:
                flash("Girilen şifre yanlış. Lütfen tekrar deneyiniz.", "danger")
                return redirect(url_for("login"))

        else:
            flash("Böyle bir kullanıcı bulunamadı. Lütfen tekrar deneyiniz.", "danger")
            return redirect(url_for("login"))


class RegisterForm(Form):
    username = StringField(validators=[validators.InputRequired()])
    email = StringField(validators=[validators.InputRequired()])
    password = PasswordField(validators=[validators.InputRequired()])
    passwordAgain = PasswordField(validators=[validators.InputRequired()])

class LoginForm(Form):
    username = StringField(validators=[validators.InputRequired()])
    password = PasswordField(validators=[validators.InputRequired()])

if __name__ == "__main__":
    app.run(debug= True)