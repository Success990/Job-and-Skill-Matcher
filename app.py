from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import sqlite3

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Change this to a secure key in production
app.permanent_session_lifetime = timedelta(days=30)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone_number TEXT,
            job_interest TEXT,
            qualification TEXT,
            firm_description TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Route to choose signup type
@app.route('/choose_signup')
def choose_signup():
    return render_template('choose_signup.html')  # Offers links to /signup/job_seeker and /signup/employer

# Job Seeker Signup Route
@app.route('/signup/job_seeker', methods=['GET', 'POST'])
def signup_job_seeker():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        job_interest = request.form['job_interest']
        qualification = request.form['qualification']
        
        # Enforce email in lowercase
        if email != email.lower():
            flash("Invalid email: Email must be in all lowercase. Please re-enter your email in lowercase.", "error")
            return redirect(url_for('signup_job_seeker'))
        
        # Check password requirements
        if len(password) < 8 or not any(char.isdigit() for char in password):
            flash("Password must be at least 8 characters long and contain at least one number.", "error")
            return redirect(url_for('signup_job_seeker'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_type, full_name, email, password, phone_number, job_interest, qualification)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ("job_seeker", full_name, email, hashed_password, phone_number, job_interest, qualification))
            conn.commit()
            conn.close()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login_job_seeker'))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use a different email.", "error")
            return redirect(url_for('signup_job_seeker'))
        
    return render_template('signup_job_seeker.html')

# Employer Signup Route
@app.route('/signup/employer', methods=['GET', 'POST'])
def signup_employer():
    if request.method == 'POST':
        firm_name = request.form['firm_name']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        firm_description = request.form['firm_description']
        
        # Enforce email in lowercase
        if email != email.lower():
            flash("Invalid email: Email must be in all lowercase. Please re-enter your email in lowercase.", "error")
            return redirect(url_for('signup_employer'))
        
        # Check password requirements
        if len(password) < 8 or not any(char.isdigit() for char in password):
            flash("Password must be at least 8 characters long and contain at least one number.", "error")
            return redirect(url_for('signup_employer'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_type, full_name, email, password, phone_number, firm_description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ("employer", firm_name, email, hashed_password, phone_number, firm_description))
            conn.commit()
            conn.close()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login_employer'))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use a different email.", "error")
            return redirect(url_for('signup_employer'))
        
    return render_template('signup_employer.html')

# Route to choose login type
@app.route('/choose_login')
def choose_login():
    return render_template('choose_login.html')  # Offers links to /login/job_seeker and /login/employer

# Job Seeker Login Route
@app.route('/login/job_seeker', methods=['GET', 'POST'])
def login_job_seeker():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND user_type = ?", (email, "job_seeker"))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"], password):
            session['user_email'] = user["email"]
            session.permanent = True
            return redirect(url_for('dashboard'))
        flash("Invalid email or password.", "error")
        return redirect(url_for('login_job_seeker'))
    return render_template('login_job_seeker.html')

# Employer Login Route
@app.route('/login/employer', methods=['GET', 'POST'])
def login_employer():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND user_type = ?", (email, "employer"))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"], password):
            session['user_email'] = user["email"]
            session.permanent = True
            return redirect(url_for('dashboard'))
        flash("Invalid email or password.", "error")
        return redirect(url_for('login_employer'))
    return render_template('login_employer.html')

# Dashboard route for both user types
@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('choose_login'))
    email = session['user_email']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    # Pass an empty activities list if no activities are tracked yet
    return render_template('dashboard.html', user=user, activities=[])

# Edit Profile route (changes based on user type)
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_email' not in session:
        return redirect(url_for('choose_login'))
    email = session['user_email']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if request.method == 'POST':
        if user['user_type'] == 'job_seeker':
            full_name = request.form.get('full_name')
            phone_number = request.form.get('phone_number')
            job_interest = request.form.get('job_interest')
            qualification = request.form.get('qualification')
            cursor.execute("UPDATE users SET full_name = ?, phone_number = ?, job_interest = ?, qualification = ? WHERE email = ?",
                           (full_name, phone_number, job_interest, qualification, email))
        else:  # employer
            firm_name = request.form.get('firm_name')
            phone_number = request.form.get('phone_number')
            firm_description = request.form.get('firm_description')
            cursor.execute("UPDATE users SET full_name = ?, phone_number = ?, firm_description = ? WHERE email = ?",
                           (firm_name, phone_number, firm_description, email))
        conn.commit()
        conn.close()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('edit_profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)
