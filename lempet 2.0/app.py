from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Конфігурація бази даних
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///work_tracking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Модель користувача
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')  # 'user' або 'admin'
    work_sessions = db.relationship('WorkSession', backref='user', lazy=True)

# Модель робочих сесій
class WorkSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)

# Декоратор для перевірки адміністратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':  # Перевіряємо роль
            flash('У вас немає доступу до цієї сторінки.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Паролі не співпадають!', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
            flash('Користувач із такою електронною поштою або іменем уже існує!', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Реєстрація успішна! Увійдіть, щоб продовжити.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Ви успішно увійшли!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Невірний логін або пароль.', 'error')

    return render_template('login.html')

@app.route('/work', methods=['GET', 'POST'])
def work():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть, щоб отримати доступ до цієї сторінки.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        action = request.form.get('action')

        if action == 'start':
            existing_session = WorkSession.query.filter_by(user_id=user_id, end_time=None).first()
            if existing_session:
                flash('Ви вже на роботі!', 'error')
            else:
                new_session = WorkSession(user_id=user_id, start_time=datetime.now())
                db.session.add(new_session)
                db.session.commit()
                flash('Сесія почалася!', 'success')

        elif action == 'stop':
            active_session = WorkSession.query.filter_by(user_id=user_id, end_time=None).first()
            if active_session:
                active_session.end_time = datetime.now()
                db.session.commit()
                flash('Сесія завершена!', 'success')
            else:
                flash('Немає активної сесії для завершення!', 'error')

    return render_template('work.html')

@app.route('/users')
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/user/<int:user_id>/sessions', methods=['GET', 'POST'])
def user_sessions(user_id):
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть, щоб отримати доступ до цієї сторінки.', 'error')
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    filter_date = None
    filtered_sessions = user.work_sessions

    if request.method == 'POST':
        date_str = request.form.get('filter_date')
        if date_str:
            try:
                filter_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                filtered_sessions = [
                    session for session in user.work_sessions
                    if (session.start_time and session.start_time.date() == filter_date) or
                       (session.end_time and session.end_time.date() == filter_date)
                ]
            except ValueError:
                flash('Невірний формат дати. Використовуйте формат YYYY-MM-DD.', 'error')

    return render_template('user_sessions.html', user=user, sessions=filtered_sessions, filter_date=filter_date)

@app.route('/logout')
def logout():
    session.clear()
    flash('Ви успішно вийшли із системи.', 'success')
    return redirect(url_for('home'))




@app.route('/add_admin_once')
def add_admin_once():
    existing_admin = User.query.filter_by(role='admin').first()
    if existing_admin:
        return "Адміністратор вже існує."

    admin = User(
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('adminpassword', method='pbkdf2:sha256'),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    return "Адміністратор успішно доданий!"




# Ініціалізація бази даних
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
