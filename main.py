from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key' # Нужен для сессий и безопасности
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- НАСТРОЙКА LOGIN MANAGER ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Если не авторизован, перенаправит сюда

# --- МОДЕЛИ БАЗЫ ДАННЫХ (Пункт 02) ---
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(200), nullable=True)
    text = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))

# --- МАРШРУТЫ (Пункт 03) ---

@app.route('/')
def home():
    # Если пользователь уже вошел, отправляем на главную (index)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Проверка на существующего пользователя
        user = Users.query.filter_by(username=username).first()
        if user:
            flash('Такой пользователь уже существует', 'error')
            return redirect(url_for('register'))
        
        # Хэшируем пароль и сохраняем
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Регистрация успешна! Войдите.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = Users.query.filter_by(username=username).first()
        
        # Проверка пароля
        if user and check_password_hash(user.password, password):
            login_user(user) # Авторизуем
            return redirect(url_for('index')) # Переход на главную
        else:
            flash('Неверный логин или пароль', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- ОСНОВНАЯ ЧАСТЬ САЙТА (Пункт 04: защита) ---

@app.route('/index')
@login_required
def index():
    # Достаем все карточки из БД
    cards = Card.query.all()
    return render_template('index.html', cards=cards)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        subtitle = request.form.get('subtitle')
        text = request.form.get('text')
        
        if title and text:
            new_card = Card(title=title, subtitle=subtitle, text=text)
            db.session.add(new_card)
            db.session.commit()
            return redirect(url_for('index'))
            
    return render_template('create.html')

@app.route('/card/<int:id>')
@login_required
def card(id):
    # Ищем карточку по ID
    card_item = db.session.get(Card, id)
    if card_item:
        return render_template('card.html', card=card_item)
    return "Карточка не найдена", 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Создаем таблицы при запуске
    app.run(debug=True)