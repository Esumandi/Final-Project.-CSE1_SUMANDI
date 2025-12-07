from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Pentagon0211'
app.config['MYSQL_DB'] = 'CS_ELECT'

mysql = MySQL(app)

@app.route('/')
def home():
    return 'Hello World!'

@app.route("/testdb")
def testdb():
    cur = mysql.connection.cursor()
    cur.execute("SELECT DATABASE()")
    data = cur.fetchone()
    return str(data)

if __name__ == '__main__':
    app.run(debug=True)
