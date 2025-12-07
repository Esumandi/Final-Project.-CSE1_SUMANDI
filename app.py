from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)


@app.route('/')
def home():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run(debug=True)

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Pentagon0211'
app.config['MYSQL_DB'] = 'CS_ELECT'

mysql = MySQL(app)