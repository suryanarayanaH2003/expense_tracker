from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
import random
import smtplib
import ssl
from email.message import EmailMessage
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# MongoDB setup
try:
    client = MongoClient("mongodb://127.0.0.1:27017/", serverSelectionTimeoutMS=5000)
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    print("❌ Failed to connect to MongoDB:", e)

db = client['user_db']
users = db['users']
otps = db['otps']
expenses_collection = db['expenses']

# Email configuration
EMAIL_SENDER = 'harinik3326@gmail.com'
EMAIL_PASSWORD = 'lxrp xltw tteu dkwf'  # Use app password for Gmail

# OTP Email sender
def send_otp(email, otp):
    subject = 'Your OTP Verification Code'
    body = f'Your OTP is: {otp}'

    em = EmailMessage()
    em['From'] = EMAIL_SENDER
    em['To'] = email
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(em)
        print(f"✅ OTP email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send email to {email}: {e}")
        flash("Failed to send OTP. Please try again later.")

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        number = request.form['number']
        email = request.form['email']
        password = request.form['password']

        if users.find_one({'email': email}):
            flash("Email already exists.")
            return redirect(url_for('signup'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.")
            return redirect(url_for('signup'))

        if not re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', password):
            flash("Password must contain a capital letter, a number, and be 8+ characters.")
            return redirect(url_for('signup'))

        session['temp_user'] = {
            'username': username,
            'number': number,
            'email': email,
            'password': bcrypt.generate_password_hash(password).decode('utf-8')
        }

        otp = str(random.randint(100000, 999999))
        print(f"Generated OTP for {email}: {otp}")
        otps.update_one({'email': email}, {'$set': {'otp': otp}}, upsert=True)
        send_otp(email, otp)

        flash('OTP sent to your email.')
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        email = session['temp_user']['email']
        record = otps.find_one({'email': email})

        if record and record['otp'] == entered_otp:
            users.insert_one(session['temp_user'])
            otps.delete_one({'email': email})
            session.pop('temp_user', None)
            flash("Account created successfully. Please log in.")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Try again.")
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.find_one({'username': username})
        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            session['user_id'] = str(user['_id'])  # ✅ Needed for dashboard
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        if user:
            otp = str(random.randint(100000, 999999))
            otps.update_one({'email': email}, {'$set': {'otp': otp}}, upsert=True)
            print(f"Generated OTP for reset: {otp}")
            send_otp(email, otp)
            session['reset_email'] = email
            flash("OTP sent to your email.")
            return redirect(url_for('reset_password'))
        else:
            flash("Email not registered.")
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['new_password']
        email = session.get('reset_email')

        record = otps.find_one({'email': email})

        if record and record['otp'] == entered_otp:
            if not re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', new_password):
                flash("Password must contain a capital letter, a number, and be 8+ characters.")
                return redirect(url_for('reset_password'))

            hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
            users.update_one({'email': email}, {'$set': {'password': hashed_pw}})
            otps.delete_one({'email': email})
            session.pop('reset_email', None)
            flash("Password reset successful.")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP.")
            return redirect(url_for('reset_password'))
    return render_template('reset_password.html')

@app.route('/welcome')
def welcome():
    if 'username' in session:
        return render_template('welcome.html', username=session['username'])
    else:
        flash("Please log in first.")
        return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        trans_type = request.form['type']
        date = datetime.now()

        expenses_collection.insert_one({
            'user_id': ObjectId(user_id),
            'description': description,
            'amount': amount,
            'type': trans_type,
            'date': date
        })
        return redirect(url_for('dashboard'))

    expenses = list(expenses_collection.find({'user_id': ObjectId(user_id)}).sort('date', -1))
    print('demo',expenses)

    total_income = sum(x['amount'] for x in expenses if x.get('type') == 'income')
    total_expense = sum(x['amount'] for x in expenses if x.get('type') == 'expense')
    balance = total_income - total_expense

    return render_template(
        'dashboard.html',
        expenses=expenses,
        total_income=total_income,
        total_expense=total_expense,
        balance=balance,
        username=user.get('username'),
        email=user.get('email'),
        phone=user.get('phone')
    )
from bson import ObjectId
from collections import defaultdict


@app.route('/overview')
def overview():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user_object_id = ObjectId(user_id)
    transactions = list(expenses_collection.find({'user_id': user_object_id}))

    # Initialize tracking variables
    income_total = 0
    expenses_total = 0
    expenses_by_category = defaultdict(float)
    monthly_data = defaultdict(lambda: {'income': 0, 'expense': 0})

    # Process transactions
    for txn in transactions:
        amount = float(txn.get('amount', 0))
        txn_type = txn.get('type')
        date = txn.get('date')
        month_key = date.strftime('%Y-%m')  # Format: '2025-05'

        # Update monthly totals
        if txn_type == 'income':
            income_total += amount
            monthly_data[month_key]['income'] += amount
        elif txn_type == 'expense':
            expenses_total += amount
            monthly_data[month_key]['expense'] += amount
            category = txn.get('description', 'Other')
            expenses_by_category[category] += amount

    # Calculate expense percentage
    expense_percentage = round((expenses_total / income_total * 100) if income_total > 0 else 0, 2)

    # Prepare monthly trend data (last 6 months)
    sorted_months = sorted(monthly_data.keys())[-6:]  # Get last 6 months
    monthly_labels = [datetime.strptime(m, '%Y-%m').strftime('%b %Y') for m in sorted_months]
    monthly_income = [monthly_data[m]['income'] for m in sorted_months]
    monthly_expenses = [monthly_data[m]['expense'] for m in sorted_months]

    # Prepare pie chart data
    labels = ['Income'] + list(expenses_by_category.keys())
    data = [income_total] + list(expenses_by_category.values())

    return render_template(
        'overview.html', 
        labels=labels, 
        data=data,
        total_income=income_total,
        total_expenses=expenses_total,
        expense_percentage=expense_percentage,
        monthly_labels=monthly_labels,
        monthly_income=monthly_income,
        monthly_expenses=monthly_expenses
    )

@app.route('/get_transaction/<transaction_id>')
def get_transaction(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    transaction = expenses_collection.find_one({'_id': ObjectId(transaction_id)})
    return {
        'description': transaction['description'],
        'amount': transaction['amount'],
        'type': transaction['type']
    }

@app.route('/update_transaction/<transaction_id>', methods=['POST'])
def update_transaction(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    description = request.form['description']
    amount = float(request.form['amount'])
    trans_type = request.form['type']
    
    expenses_collection.update_one(
        {'_id': ObjectId(transaction_id)},
        {'$set': {
            'description': description,
            'amount': amount,
            'type': trans_type
        }}
    )
    return redirect(url_for('dashboard'))

@app.route('/delete_transaction/<transaction_id>', methods=['DELETE'])
def delete_transaction(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    expenses_collection.delete_one({'_id': ObjectId(transaction_id)})
    return '', 204

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'})

    user_id = session['user_id']
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')

    update_data = {
        'username': username,
        'email': email,
        'phone': phone
    }

    # If password is provided, update it
    if password:
        update_data['password'] = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        session['username'] = username  # Update session username
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)

