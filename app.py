from flask import Flask, render_template, request, session, redirect, url_for
import sqlite3
import os
import bcrypt
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori, association_rules


app = Flask(__name__)
app.secret_key = os.urandom(15)

# Database connection
conn = sqlite3.connect('database.db')
conn.execute('CREATE TABLE IF NOT EXISTS users (firstname TEXT, lastname TEXT, username TEXT, email TEXT, address TEXT, ssname TEXT, purpose TEXT, password TEXT)')
conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()

        print("User tuple:", user)
        print("User tuple length:", len(user))
        #print(user[3])

        if user is not None:
            stored_username = user[2]
            stored_password = user[7]
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['username'] = stored_username
                return redirect(url_for('main'))
            else:
                error = 'Invalid password.'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found.'
            return render_template('login.html', error=error)

    return render_template('login.html')

# added signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        email = request.form['email']
        address = request.form['address']
        ssname = request.form['ssname']     #ss stands for supermarket/school
        purpose = request.form['purpose']

        password = request.form['password']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create the users table if it doesn't exist
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT,
            lastname TEXT,
            username TEXT
            email TEXT,
            address TEXT,
            ssname TEXT,
            purpose TEXT,
            password TEXT
            
        )''')
        conn.commit()

        # Check if the username already exists
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cur.fetchone()

        if existing_user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('signup.html', error=error)
        else:
            # Insert the new user into the database
            cur.execute('INSERT INTO users (firstname, lastname, username, email, address, ssname, purpose, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (firstname, lastname, username, email, address, ssname, purpose, hashed_password))
            conn.commit()
            conn.close()

            # Redirect the user to the login page after successful signup
            return redirect(url_for('login'))

    return render_template('signup.html')



# main page route
@app.route('/main')
def main():
    if 'username' in session:
        username = session['username']

        conn = sqlite3.connect('database.db')
        cur = conn.cursor()

        # Fetch quiz history for the logged-in user
        #cur.execute('SELECT score FROM quiz_history WHERE username = ?', (username,))
        #quiz_history = cur.fetchall()

        #conn.close()
        if request.method == 'POST':
            transactions = request.form['transactions']
            items = request.form['items']
            min_support =0.01
            min_confidence = 0.5
            
            # Split transactions and items into lists
            transactions = transactions.split('\n')
            items = items.split(',')
            
            # Call the Apriori algorithm function
            association_rules = apriori_algorithm(transactions, items, min_support, min_confidence)
            return render_template('main.html', username=username, association_rules=association_rules)

        return render_template('main.html')
    else:
        return redirect(url_for('login'))
    
    """

    if request.method == 'POST':
        transactions = request.form['transactions']
        items = request.form['items']
        min_support =0.01
        min_confidence = 0.5
        
        # Split transactions and items into lists
        transactions = transactions.split('\n')
        items = items.split(',')
        
        # Call the Apriori algorithm function
        association_rules = apriori_algorithm(transactions, items, min_support, min_confidence)
        
        return render_template('index.html', association_rules=association_rules)
    
    return render_template('index.html')
    """

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

