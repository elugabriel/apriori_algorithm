from flask import Flask, render_template, request, session, redirect, url_for
import sqlite3
import os
import pandas as pd
import bcrypt
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori, association_rules

app = Flask(__name__)
app.secret_key = os.urandom(15)

# Database connection
conn = sqlite3.connect('database.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT,
    lastname TEXT,
    username TEXT,
    email TEXT,
    address TEXT,
    ssname TEXT,
    purpose TEXT,
    password TEXT
)''')
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

        if user is not None:
            stored_username = user[2]
            stored_password = user[7]  # Index 8 corresponds to the 'password' field

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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        email = request.form['email']
        address = request.form['address']
        ssname = request.form['ssname']
        purpose = request.form['purpose']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        cur = conn.cursor()

        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cur.fetchone()

        if existing_user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('signup.html', error=error)
        else:
            cur.execute('INSERT INTO users (firstname, lastname, username, email, address, ssname, purpose, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (firstname, lastname, username, email, address, ssname, purpose, hashed_password))
            conn.commit()
            conn.close()

            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/main', methods=['GET', 'POST'])
def main():
    if 'username' in session:
        username = session['username']

        if request.method == 'POST':
            transactions = request.form['transactions']
            items = request.form['items']
            min_support = float(request.form['min_support'])
            min_confidence = float(request.form['min_confidence'])

            # Convert transactions to list of lists
            transactions = [t.strip().split(',') for t in transactions.split('\n') if t.strip()]
            
            # Convert items to list
            items = [item.strip() for item in items.split(',')]

            # Print the values for debugging
            print("Transactions:", transactions)
            print("Items:", items)
            print("Min Support:", min_support)
            print("Min Confidence:", min_confidence)

            # Convert transactions to binary encoded format
            te = TransactionEncoder()
            te_ary = te.fit(transactions).transform(transactions)
            df = pd.DataFrame(te_ary, columns=te.columns_)

            print("Transaction Data:")
            print(df)

            # Apply Apriori algorithm
            frequent_itemsets = apriori(df, min_support=min_support, use_colnames=True)
            rules = association_rules(frequent_itemsets, min_threshold=min_confidence)

            # Convert association rules to list of strings
            generated_rules = []
            for _, rule in rules.iterrows():
                antecedents = ", ".join(list(rule['antecedents']))
                consequents = ", ".join(list(rule['consequents']))
                generated_rules.append(f"{antecedents} -> {consequents}")

            print("Generated Rules:")
            print(generated_rules)

            return render_template('main.html', username=username, association_rules=generated_rules)

        return render_template('main.html', username=username)
    else:
        return redirect(url_for('login'))
    

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=8000)
