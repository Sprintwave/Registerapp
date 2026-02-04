import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

DATABASE = 'care_register.db'

def get_db():
    """Get database connection - supports both SQLite (local) and PostgreSQL (Render)"""
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Production: PostgreSQL on Render
        import psycopg2
        from psycopg2.extras import RealDictCursor
        import urllib.parse
        
        # Parse the URL
        url_parts = urllib.parse.urlparse(database_url)
        conn = psycopg2.connect(
            host=url_parts.hostname,
            port=url_parts.port,
            database=url_parts.path[1:],
            user=url_parts.username,
            password=url_parts.password,
            sslmode='require',
            cursor_factory=RealDictCursor
        )
        return conn
    else:
        # Development: SQLite
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    """Initialize database and create tables"""
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Create locations table
        if is_postgres:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS locations (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    address TEXT
                )
            ''')
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    address TEXT
                )
            ''')
        
        # Check if locations table needs to be populated
        cursor.execute('SELECT COUNT(*) FROM locations')
        location_count = cursor.fetchone()[0]
        if location_count == 0:
            locations = [
                ('Sunrise Care Center', '123 Oak Street, Downtown'),
                ('Meadowbrook Facility', '456 Pine Avenue, Westside'),
                ('Riverside Day Care', '789 River Road, Northbank'),
                ('Garden View Center', '321 Elm Drive, Southside'),
                ('Harmony House', '654 Maple Lane, Eastend')
            ]
            if is_postgres:
                cursor.executemany('INSERT INTO locations (name, address) VALUES (%s, %s)', locations)
            else:
                cursor.executemany('INSERT INTO locations (name, address) VALUES (?, ?)', locations)
        
        # Check if users table needs migration
        try:
            if is_postgres:
                cursor.execute('SELECT location_id FROM users LIMIT 1')
            else:
                conn.execute('SELECT location_id FROM users LIMIT 1')
            users_migrated = True
        except (sqlite3.OperationalError, Exception):
            users_migrated = False
        
        if not users_migrated:
            # Create new users table with location support
            if is_postgres:
                cursor.execute('ALTER TABLE users ADD COLUMN location_id INTEGER')
            else:
                conn.execute('ALTER TABLE users ADD COLUMN location_id INTEGER')
            
        # Create users table if it doesn't exist (fallback)
        if is_postgres:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'carer')),
                    location_id INTEGER,
                    FOREIGN KEY (location_id) REFERENCES locations (id)
                )
            ''')
        else:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'carer')),
                    location_id INTEGER,
                    FOREIGN KEY (location_id) REFERENCES locations (id)
                )
            ''')
        
        # Check if patients table needs migration
        try:
            if is_postgres:
                cursor.execute('SELECT location_id FROM patients LIMIT 1')
            else:
                conn.execute('SELECT location_id FROM patients LIMIT 1')
            patients_migrated = True
        except (sqlite3.OperationalError, Exception):
            patients_migrated = False
        
        if not patients_migrated:
            # Create new patients table with location and carer support
            if is_postgres:
                cursor.execute('ALTER TABLE patients ADD COLUMN location_id INTEGER')
                cursor.execute('ALTER TABLE patients ADD COLUMN primary_carer_id INTEGER')
            else:
                conn.execute('ALTER TABLE patients ADD COLUMN location_id INTEGER')
                conn.execute('ALTER TABLE patients ADD COLUMN primary_carer_id INTEGER')
            
            # Update existing patients with location assignments
            if is_postgres:
                existing_patients = cursor.execute('SELECT id, name FROM patients').fetchall()
            else:
                existing_patients = conn.execute('SELECT id, name FROM patients').fetchall()
            if existing_patients:
                # Assign first 3 patients to location 1, rest evenly distributed
                for i, patient in enumerate(existing_patients):
                    location_id = (i % 5) + 1  # Distribute across 5 locations
                    if is_postgres:
                        cursor.execute('UPDATE patients SET location_id = %s WHERE id = %s', 
                                     (location_id, patient['id']))
                    else:
                        conn.execute('UPDATE patients SET location_id = ? WHERE id = ?', 
                                   (location_id, patient['id']))
        
        # Create patients table if it doesn't exist (fallback)
        if is_postgres:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS patients (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    location_id INTEGER,
                    primary_carer_id INTEGER,
                    FOREIGN KEY (location_id) REFERENCES locations (id),
                    FOREIGN KEY (primary_carer_id) REFERENCES users (id)
                )
            ''')
        else:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS patients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    location_id INTEGER,
                    primary_carer_id INTEGER,
                    FOREIGN KEY (location_id) REFERENCES locations (id),
                    FOREIGN KEY (primary_carer_id) REFERENCES users (id)
                )
            ''')
        
        # Create events table
        if is_postgres:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    patient_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN ('ARRIVED', 'LEFT')),
                    left_with TEXT,
                    transport_mode TEXT,
                    notes TEXT,
                    ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_id) REFERENCES patients (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        else:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN ('ARRIVED', 'LEFT')),
                    left_with TEXT,
                    transport_mode TEXT,
                    notes TEXT,
                    ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_id) REFERENCES patients (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        
        # Seed admin user if not exists
        if is_postgres:
            admin_exists = cursor.execute('SELECT id FROM users WHERE username = %s', ('admin',)).fetchone()
            if not admin_exists:
                admin_hash = generate_password_hash('admin123')
                cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)',
                        ('admin', admin_hash, 'admin'))
        else:
            admin_exists = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
            if not admin_exists:
                admin_hash = generate_password_hash('admin123')
                conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                        ('admin', admin_hash, 'admin'))
        
        # Seed carer users if not exist
        new_carers = [
            'sarah_jones', 'mike_davis', 'emma_wilson', 'james_taylor', 'lisa_brown'
        ]
        
        for i, username in enumerate(new_carers):
            if is_postgres:
                carer_exists = cursor.execute('SELECT id FROM users WHERE username = %s', (username,)).fetchone()
                if not carer_exists:
                    password_hash = generate_password_hash('carer123')
                    location_id = i + 1
                    cursor.execute('INSERT INTO users (username, password_hash, role, location_id) VALUES (%s, %s, %s, %s)',
                               (username, password_hash, 'carer', location_id))
            else:
                carer_exists = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if not carer_exists:
                    password_hash = generate_password_hash('carer123')
                    location_id = i + 1
                    conn.execute('INSERT INTO users (username, password_hash, role, location_id) VALUES (?, ?, ?, ?)',
                               (username, password_hash, 'carer', location_id))
        
        # Update existing carer1 if exists
        if is_postgres:
            existing_carer = cursor.execute('SELECT id FROM users WHERE username = %s AND location_id IS NULL', ('carer1',)).fetchone()
            if existing_carer:
                cursor.execute('UPDATE users SET location_id = 1 WHERE username = %s', ('carer1',))
        else:
            existing_carer = conn.execute('SELECT id FROM users WHERE username = ? AND location_id IS NULL', ('carer1',)).fetchone()
            if existing_carer:
                conn.execute('UPDATE users SET location_id = 1 WHERE username = ?', ('carer1',))
        
        # Seed more patients if we have fewer than 30
        if is_postgres:
            current_patient_count = cursor.execute('SELECT COUNT(*) FROM patients').fetchone()[0]
        else:
            current_patient_count = conn.execute('SELECT COUNT(*) FROM patients').fetchone()[0]
        if current_patient_count < 30:
            # Get carer IDs for assignment
            if is_postgres:
                carers = cursor.execute('SELECT id, location_id FROM users WHERE role = %s AND location_id IS NOT NULL ORDER BY location_id', ('carer',)).fetchall()
            else:
                carers = conn.execute('SELECT id, location_id FROM users WHERE role = "carer" AND location_id IS NOT NULL ORDER BY location_id').fetchall()
            
            if carers:
                additional_patients = [
                    # Additional patients for each location
                    ('Elizabeth Davis', 1), ('William Wilson', 1), ('Jennifer Garcia', 1),
                    ('David Miller', 2), ('Susan Anderson', 2), ('Charles Thompson', 2),
                    ('Patricia Martinez', 2), ('Michael Rodriguez', 2), ('Linda Hernandez', 2),
                    ('Christopher Lopez', 3), ('Barbara Gonzalez', 3), ('Matthew Perez', 3),
                    ('Helen Sanchez', 3), ('Daniel Torres', 3), ('Sarah Flores', 3),
                    ('Anthony Rivera', 4), ('Nancy Cook', 4), ('Mark Bailey', 4),
                    ('Betty Reed', 4), ('Steven Cooper', 4), ('Dorothy Richardson', 4),
                    ('Paul Cox', 5), ('Sandra Howard', 5), ('Kenneth Ward', 5),
                    ('Donna Torres', 5), ('Joshua Peterson', 5), ('Carol Gray', 5)
                ]
                
                for name, location_id in additional_patients:
                    # Find carer for this location
                    carer = next((c for c in carers if c['location_id'] == location_id), None)
                    if carer:
                        # Check if patient already exists
                        if is_postgres:
                            existing = cursor.execute('SELECT id FROM patients WHERE name = %s', (name,)).fetchone()
                            if not existing:
                                cursor.execute('INSERT INTO patients (name, location_id, primary_carer_id) VALUES (%s, %s, %s)',
                                           (name, location_id, carer['id']))
                        else:
                            existing = conn.execute('SELECT id FROM patients WHERE name = ?', (name,)).fetchone()
                            if not existing:
                                conn.execute('INSERT INTO patients (name, location_id, primary_carer_id) VALUES (?, ?, ?)',
                                           (name, location_id, carer['id']))
        
        # Update existing patients without location assignments
        if is_postgres:
            unassigned_patients = cursor.execute('SELECT id FROM patients WHERE location_id IS NULL').fetchall()
            carers = cursor.execute('SELECT id, location_id FROM users WHERE role = %s AND location_id IS NOT NULL ORDER BY location_id', ('carer',)).fetchall()
        else:
            unassigned_patients = conn.execute('SELECT id FROM patients WHERE location_id IS NULL').fetchall()
            carers = conn.execute('SELECT id, location_id FROM users WHERE role = "carer" AND location_id IS NOT NULL ORDER BY location_id').fetchall()
        
        for i, patient in enumerate(unassigned_patients):
            if carers:
                carer = carers[i % len(carers)]
                if is_postgres:
                    cursor.execute('UPDATE patients SET location_id = %s, primary_carer_id = %s WHERE id = %s',
                               (carer['location_id'], carer['id'], patient['id']))
                else:
                    conn.execute('UPDATE patients SET location_id = ?, primary_carer_id = ? WHERE id = ?',
                               (carer['location_id'], carer['id'], patient['id']))
        
        conn.commit()

def require_login(f):
    """Decorator to require login"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_admin(f):
    """Decorator to require admin role"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_carer(f):
    """Decorator to require carer role"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'carer':
            flash('Carer access required', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/')
def index():
    """Redirect to appropriate page based on login status and role"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'admin':
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        database_url = os.environ.get('DATABASE_URL')
        is_postgres = database_url is not None
        
        with get_db() as conn:
            if is_postgres:
                cursor = conn.cursor()
                user = cursor.execute('SELECT * FROM users WHERE username = %s', (username,)).fetchone()
            else:
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                if user['role'] == 'admin':
                    return redirect(url_for('admin'))
                else:
                    return redirect(url_for('register'))
            else:
                flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@require_carer
def register():
    """Register page for carers to log patient events"""
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    if request.method == 'POST':
        patient_id = request.form['patient_id']
        event_type = request.form['event_type']
        left_with = request.form.get('left_with', '')
        transport_mode = request.form.get('transport_mode', '')
        notes = request.form.get('notes', '')
        
        with get_db() as conn:
            if is_postgres:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO events (patient_id, user_id, event_type, left_with, transport_mode, notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (patient_id, session['user_id'], event_type, left_with, transport_mode, notes))
            else:
                conn.execute('''
                    INSERT INTO events (patient_id, user_id, event_type, left_with, transport_mode, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (patient_id, session['user_id'], event_type, left_with, transport_mode, notes))
            conn.commit()
        
        flash('Event recorded successfully', 'success')
        return redirect(url_for('register'))
    
    # Get patients for this carer's location and recent events
    with get_db() as conn:
        # Get carer's location
        if is_postgres:
            cursor = conn.cursor()
            carer = cursor.execute('SELECT location_id FROM users WHERE id = %s', (session['user_id'],)).fetchone()
            
            # Get patients in same location
            patients = cursor.execute('''
                SELECT p.*, l.name as location_name
                FROM patients p
                JOIN locations l ON p.location_id = l.id
                WHERE p.location_id = %s
                ORDER BY p.name
            ''', (carer['location_id'],)).fetchall()
            
            recent_events = cursor.execute('''
                SELECT e.*, p.name as patient_name
                FROM events e
                JOIN patients p ON e.patient_id = p.id
                WHERE e.user_id = %s
                ORDER BY e.ts_utc DESC
                LIMIT 20
            ''', (session['user_id'],)).fetchall()
        else:
            carer = conn.execute('SELECT location_id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            
            # Get patients in same location
            patients = conn.execute('''
                SELECT p.*, l.name as location_name
                FROM patients p
                JOIN locations l ON p.location_id = l.id
                WHERE p.location_id = ?
                ORDER BY p.name
            ''', (carer['location_id'],)).fetchall()
            
            recent_events = conn.execute('''
                SELECT e.*, p.name as patient_name
                FROM events e
                JOIN patients p ON e.patient_id = p.id
                WHERE e.user_id = ?
                ORDER BY e.ts_utc DESC
                LIMIT 20
            ''', (session['user_id'],)).fetchall()
    
    return render_template('register.html', patients=patients, recent_events=recent_events)

@app.route('/admin')
@require_admin
def admin():
    """Admin dashboard"""
    date_filter = request.args.get('date_filter', 'today')
    patient_search = request.args.get('patient_search', '')
    location_filter = request.args.get('location_filter', '')
    
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    # Calculate date range
    if date_filter == 'today':
        start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    elif date_filter == 'week':
        start_date = datetime.now() - timedelta(days=7)
    else:  # all
        start_date = datetime.min
    
    with get_db() as conn:
        if is_postgres:
            cursor = conn.cursor()
            # Get all locations for filter
            locations = cursor.execute('SELECT * FROM locations ORDER BY name').fetchall()
        else:
            # Get all locations for filter
            locations = conn.execute('SELECT * FROM locations ORDER BY name').fetchall()
        
        # Get currently on site patients by location
        currently_on_site_query = '''
            WITH latest_events AS (
                SELECT patient_id, MAX(ts_utc) as latest_ts
                FROM events
                GROUP BY patient_id
            )
            SELECT p.name as patient_name, p.id as patient_id, e.event_type, e.ts_utc,
                   l.name as location_name, l.id as location_id,
                   u.username as primary_carer
            FROM latest_events le
            JOIN events e ON le.patient_id = e.patient_id AND le.latest_ts = e.ts_utc
            JOIN patients p ON e.patient_id = p.id
            JOIN locations l ON p.location_id = l.id
            JOIN users u ON p.primary_carer_id = u.id
            WHERE e.event_type = 'ARRIVED'
        '''
        
        if location_filter:
            if is_postgres:
                currently_on_site_query += ' AND l.id = %s'
                currently_on_site_raw = cursor.execute(currently_on_site_query + ' ORDER BY l.name, p.name', (location_filter,)).fetchall()
            else:
                currently_on_site_query += ' AND l.id = ?'
                currently_on_site_raw = conn.execute(currently_on_site_query + ' ORDER BY l.name, p.name', (location_filter,)).fetchall()
        else:
            if is_postgres:
                currently_on_site_raw = cursor.execute(currently_on_site_query + ' ORDER BY l.name, p.name').fetchall()
            else:
                currently_on_site_raw = conn.execute(currently_on_site_query + ' ORDER BY l.name, p.name').fetchall()
        
        # Convert Row objects to dictionaries for JSON serialization
        currently_on_site = []
        for row in currently_on_site_raw:
            currently_on_site.append({
                'patient_name': row['patient_name'],
                'patient_id': row['patient_id'],
                'event_type': row['event_type'],
                'ts_utc': row['ts_utc'],
                'location_name': row['location_name'],
                'location_id': row['location_id'],
                'primary_carer': row['primary_carer']
            })
        
        # Get location statistics
        location_stats_query = '''
            WITH latest_events AS (
                SELECT patient_id, MAX(ts_utc) as latest_ts
                FROM events
                GROUP BY patient_id
            ),
            current_status AS (
                SELECT p.location_id, 
                       COUNT(*) as total_patients,
                       SUM(CASE WHEN e.event_type = 'ARRIVED' THEN 1 ELSE 0 END) as patients_on_site
                FROM latest_events le
                JOIN events e ON le.patient_id = e.patient_id AND le.latest_ts = e.ts_utc
                JOIN patients p ON e.patient_id = p.id
                GROUP BY p.location_id
            )
            SELECT l.id, l.name, l.address,
                   COALESCE(cs.total_patients, 0) as total_patients,
                   COALESCE(cs.patients_on_site, 0) as patients_on_site,
                   (SELECT COUNT(*) FROM patients WHERE location_id = l.id) as registered_patients
            FROM locations l
            LEFT JOIN current_status cs ON l.id = cs.location_id
            ORDER BY l.name
        '''
        
        if is_postgres:
            location_stats = cursor.execute(location_stats_query).fetchall()
        else:
            location_stats = conn.execute(location_stats_query).fetchall()
        
        # Get recent events with filters
        query = '''
            SELECT e.*, p.name as patient_name, u.username as carer_name,
                   l.name as location_name
            FROM events e
            JOIN patients p ON e.patient_id = p.id
            JOIN users u ON e.user_id = u.id
            JOIN locations l ON p.location_id = l.id
            WHERE e.ts_utc >= %s
        ''' if is_postgres else '''
            SELECT e.*, p.name as patient_name, u.username as carer_name,
                   l.name as location_name
            FROM events e
            JOIN patients p ON e.patient_id = p.id
            JOIN users u ON e.user_id = u.id
            JOIN locations l ON p.location_id = l.id
            WHERE e.ts_utc >= ?
        '''
        params = [start_date.isoformat()]
        
        if patient_search:
            if is_postgres:
                query += ' AND p.name LIKE %s'
            else:
                query += ' AND p.name LIKE ?'
            params.append(f'%{patient_search}%')
            
        if location_filter:
            if is_postgres:
                query += ' AND l.id = %s'
            else:
                query += ' AND l.id = ?'
            params.append(location_filter)
        
        query += ' ORDER BY e.ts_utc DESC LIMIT 200'
        
        if is_postgres:
            recent_events = cursor.execute(query, params).fetchall()
        else:
            recent_events = conn.execute(query, params).fetchall()
        
        # Get daily activity stats for chart
        daily_stats_query = '''
            SELECT DATE(ts_utc) as date,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN event_type = 'ARRIVED' THEN 1 ELSE 0 END) as arrivals,
                   SUM(CASE WHEN event_type = 'LEFT' THEN 1 ELSE 0 END) as departures
            FROM events
            WHERE ts_utc >= %s
            GROUP BY DATE(ts_utc)
            ORDER BY date DESC
            LIMIT 7
        ''' if is_postgres else '''
            SELECT DATE(ts_utc) as date,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN event_type = 'ARRIVED' THEN 1 ELSE 0 END) as arrivals,
                   SUM(CASE WHEN event_type = 'LEFT' THEN 1 ELSE 0 END) as departures
            FROM events
            WHERE ts_utc >= ?
            GROUP BY DATE(ts_utc)
            ORDER BY date DESC
            LIMIT 7
        '''
        
        if is_postgres:
            daily_stats = cursor.execute(daily_stats_query, (start_date.isoformat(),)).fetchall()
        else:
            daily_stats = conn.execute(daily_stats_query, (start_date.isoformat(),)).fetchall()
    
    return render_template('admin.html', 
                         currently_on_site=currently_on_site,
                         recent_events=recent_events,
                         locations=locations,
                         location_stats=location_stats,
                         daily_stats=daily_stats,
                         date_filter=date_filter,
                         patient_search=patient_search,
                         location_filter=location_filter)

@app.route('/admin/export.csv')
@require_admin
def export_csv():
    """Export events as CSV"""
    date_filter = request.args.get('date_filter', 'today')
    patient_search = request.args.get('patient_search', '')
    location_filter = request.args.get('location_filter', '')
    
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    # Calculate date range
    if date_filter == 'today':
        start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    elif date_filter == 'week':
        start_date = datetime.now() - timedelta(days=7)
    else:  # all
        start_date = datetime.min
    
    with get_db() as conn:
        query = '''
            SELECT e.ts_utc, p.name as patient_name, e.event_type, 
                   e.left_with, e.transport_mode, e.notes, u.username as carer_name,
                   l.name as location_name
            FROM events e
            JOIN patients p ON e.patient_id = p.id
            JOIN users u ON e.user_id = u.id
            JOIN locations l ON p.location_id = l.id
            WHERE e.ts_utc >= %s
        ''' if is_postgres else '''
            SELECT e.ts_utc, p.name as patient_name, e.event_type, 
                   e.left_with, e.transport_mode, e.notes, u.username as carer_name,
                   l.name as location_name
            FROM events e
            JOIN patients p ON e.patient_id = p.id
            JOIN users u ON e.user_id = u.id
            JOIN locations l ON p.location_id = l.id
            WHERE e.ts_utc >= ?
        '''
        params = [start_date.isoformat()]
        
        if patient_search:
            if is_postgres:
                query += ' AND p.name LIKE %s'
            else:
                query += ' AND p.name LIKE ?'
            params.append(f'%{patient_search}%')
            
        if location_filter:
            if is_postgres:
                query += ' AND l.id = %s'
            else:
                query += ' AND l.id = ?'
            params.append(location_filter)
        
        query += ' ORDER BY e.ts_utc DESC'
        
        if is_postgres:
            cursor = conn.cursor()
            events = cursor.execute(query, params).fetchall()
        else:
            events = conn.execute(query, params).fetchall()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Patient', 'Location', 'Event Type', 'Left With', 'Transport', 'Notes', 'Carer'])
    
    for event in events:
        writer.writerow([
            event['ts_utc'],
            event['patient_name'],
            event['location_name'],
            event['event_type'],
            event['left_with'] or '',
            event['transport_mode'] or '',
            event['notes'] or '',
            event['carer_name']
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=care_register_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

# API endpoints for management functionality
@app.route('/api/location/<int:location_id>/patients')
@require_admin
def get_location_patients(location_id):
    """Get all patients for a specific location"""
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    with get_db() as conn:
        if is_postgres:
            cursor = conn.cursor()
            patients = cursor.execute('''
                SELECT p.id, p.name, u.username as primary_carer_username
                FROM patients p
                JOIN users u ON p.primary_carer_id = u.id
                WHERE p.location_id = %s
                ORDER BY p.name
            ''', (location_id,)).fetchall()
        else:
            patients = conn.execute('''
                SELECT p.id, p.name, u.username as primary_carer_username
                FROM patients p
                JOIN users u ON p.primary_carer_id = u.id
                WHERE p.location_id = ?
                ORDER BY p.name
            ''', (location_id,)).fetchall()
        
        # Convert to list of dicts for JSON
        result = []
        for patient in patients:
            result.append({
                'id': patient['id'],
                'name': patient['name'],
                'primary_carer_username': patient['primary_carer_username']
            })
        
        return jsonify(result)

@app.route('/api/users')
@require_admin
def get_users():
    """Get all users and locations for management"""
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    with get_db() as conn:
        if is_postgres:
            cursor = conn.cursor()
            users = cursor.execute('''
                SELECT u.id, u.username, u.role, u.location_id, l.name as location_name
                FROM users u
                LEFT JOIN locations l ON u.location_id = l.id
                ORDER BY u.role, u.username
            ''').fetchall()
            
            locations = cursor.execute('SELECT id, name FROM locations ORDER BY name').fetchall()
        else:
            users = conn.execute('''
                SELECT u.id, u.username, u.role, u.location_id, l.name as location_name
                FROM users u
                LEFT JOIN locations l ON u.location_id = l.id
                ORDER BY u.role, u.username
            ''').fetchall()
            
            locations = conn.execute('SELECT id, name FROM locations ORDER BY name').fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'location_id': user['location_id'],
                'location_name': user['location_name']
            })
            
        locations_list = []
        for location in locations:
            locations_list.append({
                'id': location['id'],
                'name': location['name']
            })
        
        return jsonify({
            'users': users_list,
            'locations': locations_list
        })

@app.route('/api/user/update-location', methods=['POST'])
@require_admin
def update_user_location():
    """Update user's location assignment"""
    data = request.get_json()
    user_id = data.get('user_id')
    location_id = data.get('location_id')
    
    if not user_id or not location_id:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    with get_db() as conn:
        if is_postgres:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET location_id = %s WHERE id = %s', (location_id, user_id))
        else:
            conn.execute('UPDATE users SET location_id = ? WHERE id = ?', (location_id, user_id))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/api/location/add', methods=['POST'])
@require_admin
def add_location():
    """Add a new location"""
    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    
    if not name or not address:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    database_url = os.environ.get('DATABASE_URL')
    is_postgres = database_url is not None
    
    with get_db() as conn:
        if is_postgres:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO locations (name, address) VALUES (%s, %s)', (name, address))
        else:
            conn.execute('INSERT INTO locations (name, address) VALUES (?, ?)', (name, address))
        conn.commit()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    init_db()
    # Use environment variable for port (Render assigns this)
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
