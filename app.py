from flask import Flask, render_template, request, redirect, url_for, session
import ibm_db
import bcrypt
conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=ea286ace-86c7-4d5b-8580-3fbfa46b1c66.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=31505;SECURITY=SSL;SSLServiceCertificate=DigiCertGlobalRootCA.crt;UID=lpr87378;PWD=z1LR9MwJzLBYvmD4", '', '')
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
print(conn)


@app.route("/", methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(email,password)
        if not email or not password:
            return render_template('login.html', error='Please fill all the fields')
        query = "SELECT * FROM USERS WHERE email=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        print(isUser, password)

        if not isUser:
            return render_template('login.html', error='Invalid Credentials')

        isPasswordMatch = bcrypt.checkpw(password.encode('utf-8'), isUser['PWD'].encode('utf-8'))

        if not isPasswordMatch:
            return render_template('login.html', error='Incorrect password')
        return render_template('home.html')

    return render_template("Login.html")


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        firstName = request.form['firstName']
        password1 = request.form['password1']
        password2 = request.form['password2']
        print(password1, password2)
        if not email or not firstName or not password1 or not password2:
            return render_template('signup.html', error='Please fill all fields')
        hash = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
        print(hash)
        query = "SELECT * FROM Users WHERE email=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        if isUser:
            return render_template('login.html', msg="You are already a member, please login using your details")
        if not isUser:
            insert_sql = "INSERT INTO Users VALUES (?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, email)
            ibm_db.bind_param(prep_stmt, 2, firstName)
            ibm_db.bind_param(prep_stmt, 3, hash)
            ibm_db.execute(prep_stmt)
            return render_template('login.html',msg="Successfully registered", success="Succesfully registered now you can login")
        else:
            return render_template('signup.html', error='Invalid Credentials')

    return render_template("signup.html")


if __name__ == "__main__":
    app.run(debug=True)
