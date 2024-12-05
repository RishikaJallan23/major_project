from flask import Flask, render_template, request, redirect, url_for
# import os.path
import os
from prediction import predict_res
from datetime import datetime
import pandas as pd
import numpy as np
import yagmail
import mysql.connector


app = Flask(__name__)
app.secret_key = "intrusionn"

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Rishika123',
    'database': 'intrusion',
}

conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    gender ENUM('Male', 'Female') NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    city VARCHAR(255),
    country VARCHAR(255)
)
''')


@app.route("/index")
def index():
    return render_template("index.html")


# Your Flask route for prediction
@app.route('/predict', methods=['POST', 'GET'])
def predict():
    try:
        if request.method == 'POST':
            file = request.files['file_path']
            file_path = 'upload/' + file.filename
            print("file_path : ", file_path)
            file.save(file_path)
            prediction_data = predict_res(file_path)

            if prediction_data[0] in ['DDOS', 'Password', 'Scanning']:
                try:
                    user = yagmail.SMTP(
                        user='samming2508@gmail.com', password='uecbbelurwbrqtgw')
                    user.send(to='1bi20cs153@bit-bangalore.edu.in', subject=' ALERT !!!',
                              contents=f" {prediction_data[0]}  intrusion has been found.")
                    print("Email sent successfully")
                except Exception as e:
                    print(e)

            return render_template('index.html', lb=prediction_data[0], ip=prediction_data[1])
        return render_template("index.html")
    except Exception as e:
        return render_template('index.html', u=e)


def read_excel():
    try:
        # Read CSV file
        df = pd.read_csv('LOG.csv')
        # Check if the dataframe is empty
        if df.empty:
            print("LOG.csv is empty.")
            return ['IP Address', 'Found Attack'], []
        
        # Reverse the rows for display
        cols = list(df.columns)
        values = df.iloc[::-1].values.tolist()  # Convert to a list of lists
        return cols, values
    except FileNotFoundError:
        print("LOG.csv file not found.")
        return ['IP Address', 'Found Attack'], []
    except Exception as e:
        print("Error reading LOG.csv:", e)
        return ['IP Address', 'Found Attack'], []


@app.route("/blocked_ip", methods=['GET', 'POST'])
def blocked_ip():
    data = read_excel()
    cols = data[0]
    values = data[1]
    title = "List of Blocked Clients"
    return render_template("result1.html", title=title, cols=cols, values=values)


@app.route("/clear_data", methods=['GET', 'POST'])
def clear_data():
    df = pd.read_csv("LOG.csv")
    df.drop(df.index, inplace=True)
    df.to_csv("LOG.csv", index=False)

    # Redirect to the 'blocked_ip' route
    return redirect(url_for('blocked_ip'))


@app.route('/register', methods=['POST', 'GET'])
def register():
    try:
        if request.method == 'POST':
            # Fetch form data
            userDetails = request.form
            name = userDetails['name']
            email = userDetails['Email']
            password = userDetails['Password']
            last_name = userDetails['Last_name']
            sex = userDetails['gender']
            city = userDetails['city']
            country = userDetails['country']

            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()

            cur.execute("INSERT INTO users(name, last_name, gender, email, password, city, country) VALUES(%s, %s, %s, %s, %s, %s, %s)",
                        (name, last_name, sex, email, password, city, country))

            conn.commit()

            cur.close()
            conn.close()

            if sex == 'Male':
                msg = "Hello Mr. {} !! You can login Here !!!".format(name)
            else:
                msg = "Hello Ms. {} !! You can login Here !!!".format(name)
            return render_template('login.html', msg=msg, email=email)

        return render_template('register.html')
    except Exception as e:
        return render_template('register.html', msg=e)


@app.route('/')
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        # Execute query to check if the user exists
        cur.execute(
            "SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            return redirect(url_for('index'))
        else:
            msg = 'Invalid Login Details. Please Try Again.'
            return render_template('login.html', msg=msg, email=email)
    return render_template('login.html')


@app.route('/password', methods=['POST', 'GET'])
def password():
    if request.method == 'POST':
        current_pass = request.form['current']
        new_pass = request.form['new']
        verify_pass = request.form['verify']
        email = request.form['email']

        # Connect to MySQL
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Execute query to fetch user data
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # Check if the current password matches
            if user[5] == current_pass:
                # Check if the new password matches the verified password
                if new_pass == verify_pass:
                    # Update the password in the database
                    cursor.execute(
                        "UPDATE users SET password = %s WHERE email = %s", (new_pass, email))
                    conn.commit()
                    cursor.close()
                    conn.close()
                    msg = 'Password changed successfully'
                    return render_template('password.html', msg=msg)
                else:
                    cursor.close()
                    conn.close()
                    msg = 'Re-entered password does not match'
                    return render_template('password.html', msg=msg)
            else:
                cursor.close()
                conn.close()
                msg = 'Incorrect current password'
                return render_template('password.html', msg=msg)
        else:
            cursor.close()
            conn.close()
            msg = 'User not found'
            return render_template('password.html', msg=msg)

    return render_template('password.html')


@app.route("/logout")
def logout():
    return render_template("login.html")


if __name__ == '__main__':
    app.run(port=5015, debug=True, threaded=False)
