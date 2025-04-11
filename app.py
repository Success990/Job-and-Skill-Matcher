from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import sqlite3

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Change this in production
app.permanent_session_lifetime = timedelta(days=30)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect("users.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
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
    
    # Create vacancies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vacancies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_email TEXT NOT NULL,
            firm_name TEXT NOT NULL,
            firm_description TEXT NOT NULL,
            vacancy TEXT NOT NULL,
            ideal_jobseeker TEXT DEFAULT NULL,
            FOREIGN KEY (employer_email) REFERENCES users (email)
        )
    ''')
    
    # Create applications table (added `status` column)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_seeker_email TEXT NOT NULL,
            job_seeker_name TEXT NOT NULL,
            qualification TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            vacancy_id INTEGER NOT NULL,
            employer_email TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (job_seeker_email) REFERENCES users (email),
            FOREIGN KEY (vacancy_id) REFERENCES vacancies (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# ------------------ Routes ------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/choose_signup')
def choose_signup():
    return render_template('choose_signup.html')

@app.route('/choose_login')
def choose_login():
    return render_template('choose_login.html')

# ------------------ Signup ------------------

@app.route('/signup/job_seeker', methods=['GET', 'POST'])
def signup_job_seeker():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email'].lower()
        password = request.form['password']
        phone_number = request.form['phone_number']
        job_interest = request.form['job_interest']
        qualification = request.form['qualification']

        if len(password) < 8 or not any(char.isdigit() for char in password):
            flash("Password must be at least 8 characters long and include a number.", "danger")
            return redirect(url_for('signup_job_seeker'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (user_type, full_name, email, password, phone_number, job_interest, qualification) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         ('job_seeker', full_name, email, hashed_password, phone_number, job_interest, qualification))
            conn.commit()
            flash("Signup successful! You can now log in.", "success")
            return redirect(url_for('login_job_seeker'))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use a different email.", "danger")
        finally:
            conn.close()

    return render_template('signup_job_seeker.html')

@app.route('/signup/employer', methods=['GET', 'POST'])
def signup_employer():
    if request.method == 'POST':
        firm_name = request.form['firm_name']
        email = request.form['email'].lower()
        password = request.form['password']
        phone_number = request.form['phone_number']
        firm_description = request.form['firm_description']
        
        if len(password) < 8 or not any(char.isdigit() for char in password):
            flash("Password must be at least 8 characters long and contain at least one number.", "error")
            return redirect(url_for('signup_employer'))
        
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_type, full_name, email, password, phone_number, firm_description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ("employer", firm_name, email, hashed_password, phone_number, firm_description))
            conn.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login_employer'))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use a different email.", "error")
            return redirect(url_for('signup_employer'))
        finally:
            conn.close()
    
    return render_template('signup_employer.html')


# ------------------ Login ------------------

@app.route('/login/job_seeker', methods=['GET', 'POST'])
def login_job_seeker():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ? AND user_type = 'job_seeker'", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = email
            session['user_type'] = 'job_seeker'
            return redirect(url_for('job_seeker_dashboard'))
        else:
            flash("Invalid email or password", "error")
            return redirect(url_for('login_job_seeker'))
    return render_template('login_job_seeker.html')


@app.route('/login/employer', methods=['GET', 'POST'])
def login_employer():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ? AND user_type = 'employer'", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = email
            session['user_type'] = 'employer'
            return redirect(url_for('employer_dashboard'))
        else:
            flash("Invalid email or password", "danger")

    return render_template('login_employer.html')

# ------------------ Dashboards ------------------
@app.route('/job_seeker/dashboard')
def job_seeker_dashboard():
    if 'user' in session and session.get('user_type') == 'job_seeker':
        email = session['user']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Retrieve job seeker details
        cursor.execute("SELECT * FROM users WHERE email = ? AND user_type = 'job_seeker'", (email,))
        user = cursor.fetchone()
        
        # Exclude vacancies the job seeker has already responded to or deleted
        cursor.execute('''
            SELECT v.* 
            FROM vacancies v
            WHERE v.id NOT IN (
                SELECT vacancy_id 
                FROM applications 
                WHERE job_seeker_email = ?
            )
        ''', (email,))
        vacancies = cursor.fetchall()
        
        conn.close()
        return render_template('job_seeker_dashboard.html', user=user, vacancies=vacancies)
    return redirect(url_for('login_job_seeker'))


@app.route('/employer/dashboard')
def employer_dashboard():
    # Check if a user is logged in and is an employer
    if 'user' in session and session.get('user_type') == 'employer':
        email = session['user']
        conn = get_db_connection()
        cursor = conn.cursor()
        # Retrieve the employer's record
        cursor.execute("SELECT * FROM users WHERE email = ? AND user_type = ?", (email, "employer"))
        user = cursor.fetchone()
        if not user:
            conn.close()
            # If no user record is found, redirect to login
            return redirect(url_for('login_employer'))
        # Fetch vacancies posted by this employer
        cursor.execute("SELECT * FROM vacancies WHERE employer_email = ?", (email,))
        vacancies = cursor.fetchall()
        # Fetch applications for vacancies posted by this employer
        cursor.execute("SELECT * FROM applications WHERE employer_email = ?", (email,))
        applications = cursor.fetchall()
        conn.close()
        return render_template('employer_dashboard.html', user=user, vacancies=vacancies, applications=applications)
    else:
        # If the session doesn't have the employer info, redirect to the employer login page
        return redirect(url_for('login_employer'))

@app.route('/post_job', methods=['GET', 'POST'])
def post_job():
    # Ensure user is logged in
    if 'user' not in session:
        return redirect(url_for('choose_login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Retrieve employer details based on session email
    cursor.execute("SELECT * FROM users WHERE email = ?", (session['user'],))
    user = cursor.fetchone()
    
    # Only employers should post jobs
    if user['user_type'] != 'employer':
        flash("Only employers can post jobs.", "error")
        conn.close()
        return redirect(url_for('employer_dashboard'))
    
    if request.method == 'POST':
        vacancy = request.form.get('vacancy')
        ideal_jobseeker = request.form.get('ideal_jobseeker', '')
        
        if not vacancy:
            flash("Vacancy field is required.", "error")
            conn.close()
            return redirect(url_for('post_job'))
        
        # Insert the job vacancy into the database
        cursor.execute('''
            INSERT INTO vacancies (employer_email, firm_name, firm_description, vacancy, ideal_jobseeker)
            VALUES (?, ?, ?, ?, ?)
        ''', (user['email'], user['full_name'], user['firm_description'], vacancy, ideal_jobseeker))
        conn.commit()
        flash("Job posted successfully!", "success")
        conn.close()
        return redirect(url_for('employer_dashboard'))
    
    conn.close()
    return render_template('post_job.html')

# ------------------ Application Route for Job Seekers ------------------
@app.route('/apply/<int:vacancy_id>', methods=['POST'])
def apply(vacancy_id):
    if 'user' not in session or session.get('user_type') != 'job_seeker':
        return redirect(url_for('choose_login'))

    action = request.form.get('action')  # 'apply' or 'delete'
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get job seeker info
    cursor.execute("SELECT * FROM users WHERE email = ? AND user_type = 'job_seeker'", (session['user'],))
    job_seeker = cursor.fetchone()

    if action == "delete":
        # Record deletion for this user only
        cursor.execute('''
            INSERT INTO deleted_vacancies (job_seeker_email, vacancy_id) VALUES (?, ?)
        ''', (job_seeker['email'], vacancy_id))
        conn.commit()
        conn.close()
        flash("Vacancy removed from your list.", "info")
        return redirect(url_for('job_seeker_dashboard'))

    # If applying
    cursor.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,))
    vacancy = cursor.fetchone()

    if not vacancy:
        flash("Job vacancy not found.", "error")
        conn.close()
        return redirect(url_for('job_seeker_dashboard'))

    cursor.execute('''
        INSERT INTO applications (
            job_seeker_email, job_seeker_name, qualification, phone_number, vacancy_id, employer_email, status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'applied')
    ''', (
        job_seeker['email'], job_seeker['full_name'], job_seeker['qualification'],
        job_seeker['phone_number'], vacancy_id, vacancy['employer_email']
    ))

    conn.commit()
    conn.close()
    flash("You have successfully applied for the job!", "success")
    return redirect(url_for('job_seeker_dashboard'))



@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' not in session:
        return redirect(url_for('choose_login'))
    email = session['user']
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
            cursor.execute(
                "UPDATE users SET full_name = ?, phone_number = ?, job_interest = ?, qualification = ? WHERE email = ?",
                (full_name, phone_number, job_interest, qualification, email)
            )
        else:  # employer
            firm_name = request.form.get('firm_name')
            phone_number = request.form.get('phone_number')
            firm_description = request.form.get('firm_description')
            cursor.execute(
                "UPDATE users SET full_name = ?, phone_number = ?, firm_description = ? WHERE email = ?",
                (firm_name, phone_number, firm_description, email)
            )
        conn.commit()
        conn.close()
        flash("Profile updated successfully!", "success")
        # Redirect based on user type
        if user['user_type'] == 'job_seeker':
            return redirect(url_for('job_seeker_dashboard'))
        else:
            return redirect(url_for('employer_dashboard'))
    conn.close()
    return render_template('edit_profile.html', user=user)
   
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    # Ensure the user is logged in
    if 'user' not in session:
        return redirect(url_for('choose_login'))
    
    email = session['user']
    
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()
        # Optionally, delete related records in vacancies or applications if needed
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        
        # Clear the session after deletion
        session.pop('user', None)
        session.pop('user_type', None)
        flash("Your account has been deleted.", "success")
        return redirect(url_for('home'))
    
    # Render a confirmation page for account deletion
    return render_template('delete_account_confirm.html')


# ------------------ Logout ------------------

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_type', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('home'))

# ------------------ Run App ------------------

if __name__ == '__main__':
    app.run(debug=True)
