from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, auth
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Better secret key generation


# SQLite Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///abhishek.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)    

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    
    
    
 #test it
 
 # First, update your Flask app (add these to your existing code)

# Password Vault Model
class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Note: In production, encrypt this
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('password_entries', lazy=True))

# Password Vault Routes
@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        passwords = PasswordEntry.query.filter_by(user_id=session['user_id']).order_by(PasswordEntry.updated_at.desc()).all()
        return jsonify({
            'success': True,
            'passwords': [{
                'id': p.id,
                'website': p.website,
                'username': p.username,
                'password': p.password,
                'created_at': p.created_at.isoformat(),
                'updated_at': p.updated_at.isoformat()
            } for p in passwords]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/passwords', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not all(key in data for key in ['website', 'username', 'password']):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    try:
        new_entry = PasswordEntry(
            user_id=session['user_id'],
            website=data['website'],
            username=data['username'],
            password=data['password']
        )
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({'success': True, 'id': new_entry.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
def update_password(password_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not all(key in data for key in ['website', 'username', 'password']):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    try:
        entry = PasswordEntry.query.filter_by(id=password_id, user_id=session['user_id']).first()
        if not entry:
            return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
        entry.website = data['website']
        entry.username = data['username']
        entry.password = data['password']
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        entry = PasswordEntry.query.filter_by(id=password_id, user_id=session['user_id']).first()
        if not entry:
            return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
        db.session.delete(entry)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
 
 #end   
    
    
    

# Initialize Firebase (with error handling)
try:
    cred = credentials.Certificate('serviceAccountKey.json')
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Firebase initialization failed: {str(e)}")
    # Handle this appropriately for your use case

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'user_id' in session:  # Consistent session check
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/psd')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('home'))
    
    return render_template('psd.html', 
                         user_name=f"{user.first_name} {user.last_name}",
                         user_email=user.email)







@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    try:
        # Verify token with error handling
        decoded_token = auth.verify_id_token(
            data['token'],
            clock_skew_seconds=60
        )
        email = decoded_token.get('email')
        name = decoded_token.get('name', '').split()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found in token'}), 401

        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                first_name=name[0] if name else 'New',
                last_name=name[1] if len(name) > 1 else 'User',
                email=email,
                password=generate_password_hash(os.urandom(16).hex())
            )
            db.session.add(user)
            db.session.commit()

        # Set session
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = f"{user.first_name} {user.last_name}"

        return jsonify({
            'success': True,
            'redirect': url_for('dashboard'),
            'user': {
                'name': session['user_name'],
                'email': session['user_email']
            }
        })

    except auth.ExpiredIdTokenError:
        return jsonify({'success': False, 'error': 'Token expired'}), 401
    except auth.InvalidIdTokenError:
        return jsonify({'success': False, 'error': 'Invalid token'}), 401
    except Exception as e:
        app.logger.error(f"Auth error: {str(e)}")
        return jsonify({'success': False, 'error': 'Authentication failed'}), 500



@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({'success': True})
    response.set_cookie('session', '', expires=0)
    return response
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate request data
    if not data:
        return jsonify({
            'success': False, 
            'message': 'No data received',
            'error_type': 'empty_request'
        }), 400
        
    # Extract fields with proper defaults
    first_name = data.get('firstName', '').strip()
    last_name = data.get('lastName', '').strip()
    email = data.get('email', '').strip().lower()  # Normalize email
    password = data.get('password', '').strip()
    confirm_password = data.get('confirmPassword', '').strip()

    # Validation with specific error messages
    if not all([first_name, last_name, email, password, confirm_password]):
        return jsonify({
            'success': False,
            'message': 'All fields are required!',
            'error_type': 'missing_fields'
        }), 400

    if len(password) < 8:
        return jsonify({
            'success': False,
            'message': 'Password must be at least 8 characters',
            'error_type': 'invalid_password'
        }), 400

    if password != confirm_password:
        return jsonify({
            'success': False,
            'message': 'Passwords do not match!',
            'error_type': 'password_mismatch'
        }), 400

    if not '@' in email or '.' not in email.split('@')[-1]:
        return jsonify({
            'success': False,
            'message': 'Invalid email format',
            'error_type': 'invalid_email'
        }), 400

    # Check for existing user
    if User.query.filter_by(email=email).first():
        return jsonify({
            'success': False,
            'message': 'Email already exists!',
            'error_type': 'email_exists'
        }), 409

    try:
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        # Return success with user data
        return jsonify({
            'success': True, 
            'message': 'Registration successful! You can now login.',
            'user': {
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Registration error: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Registration failed due to server error',
            'error_type': 'server_error'
        }), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'message': 'No data received'}), 400
        
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = f"{user.first_name} {user.last_name}"
        return jsonify({
            'success': True, 
            'redirect': url_for('dashboard'),
            'user': {
                'name': session['user_name'],
                'email': session['user_email']
            }
        })
    else:
        return jsonify({
            'success': False, 
            'message': 'Invalid email or password!'
        }), 401
        
        
        
# delete account st
        
        
     
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    try:
        user = User.query.get(session['user_id'])
        if user:
            PasswordEntry.query.filter_by(user_id=user.id).delete()
            db.session.delete(user)
            db.session.commit()
            session.clear()
            return jsonify({'success': True, 'message': 'Account deleted'})
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
        

#delete account end




# password_change section st


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    user = User.query.get(session['user_id'])
    if not user or not check_password_hash(user.password, old_password):
        return jsonify({'success': False, 'message': 'Old password incorrect'}), 400

    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'New password must be at least 8 characters'}), 400

    user.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Password changed successfully'})


# password_change section end 

@app.route('/api/update_name', methods=['PUT'])
def update_name():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    data = request.get_json()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()

    if not first_name:
        return jsonify({'success': False, 'error': 'First name is required'}), 400

    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        user.first_name = first_name
        user.last_name = last_name
        db.session.commit()
        # Update session name
        session['user_name'] = f"{user.first_name} {user.last_name}"
        return jsonify({'success': True, 'message': 'Name updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)