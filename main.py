from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Change this to a secure key in production

# Set the session lifetime to 30 days
app.permanent_session_lifetime = timedelta(days=30)

# In-memory storage for users (for now; later, use a real database)
users = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_type = request.form.get('user_type')
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        
        # Ensure password meets requirements
        if len(password) < 8 or not any(char.isdigit() for char in password):
            return "Password must be at least 8 characters long and contain at least one number."

        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Save the user (this is an in-memory store; replace with a database later)
        users[email] = {
            'full_name': full_name,
            'email': email,
            'password': hashed_password,
            'phone_number': phone_number,
            'user_type': user_type
        }
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.get(email)
        if user and check_password_hash(user['password'], password):
            session['user_email'] = email  # Store user in session
            session.permanent = True       # Mark session as permanent (remembers user for 30 days)
            return redirect(url_for('dashboard'))
        return "Invalid login. Please try again."
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    user = users.get(session['user_email'])
    return render_template('dashboard.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    # Redirect to login if user isn't logged in
    if 'user_email' not in session:
        return redirect(url_for('login'))
    
    user = users.get(session['user_email'])
    
    if request.method == 'POST':
        # Get new profile data from the form
        full_name = request.form.get('full_name')
        phone_number = request.form.get('phone_number')
        
        # Update the in-memory user record if new data is provided
        if full_name:
            user['full_name'] = full_name
        if phone_number:
            user['phone_number'] = phone_number
        
        # Redirect back to the dashboard after updating
        return redirect(url_for('dashboard'))
    
    # Render the edit profile form with the current user data
    return render_template('edit_profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)
