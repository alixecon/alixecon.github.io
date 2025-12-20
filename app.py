from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import yfinance as yf
import pandas as pd
from ta.momentum import RSIIndicator
from ta.trend import SMAIndicator
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use env var in production
# Allow an environment DATABASE_URL (e.g. from Render/Heroku) with fallback to sqlite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

# Trading Agent Class (Simplified from before)
class DayTradingAgent:
    def __init__(self):
        self.symbols = ['AAPL', 'GOOGL', 'TSLA', 'NVDA', 'MSFT']  # Sample stocks
        self.picks = []

    def get_ai_picks(self):
        self.picks = []
        for symbol in self.symbols:
            try:
                data = yf.download(symbol, period='1d', interval='1m')
                if data.empty:
                    continue
                close = data['Close']  # pandas Series
                # Need enough data points for indicators
                if len(close) < 15:
                    continue

                rsi = RSIIndicator(close, window=14).rsi()  # Series with possible NaNs at start
                sma_short = SMAIndicator(close, window=5).sma_indicator()
                sma_long = SMAIndicator(close, window=10).sma_indicator()

                # Ensure we have valid latest values
                if rsi.isna().all():
                    continue
                rsi_last = rsi.dropna().iloc[-1]

                if rsi_last < 30 and close.iloc[-1] > close.iloc[-2] and sma_short.iloc[-1] > sma_long.iloc[-1]:
                    self.picks.append({
                        'symbol': symbol,
                        'action': 'BUY',
                        'reason': f'AI Signal: RSI {rsi_last:.2f} < 30, rising price, MA crossover',
                        'price': float(close.iloc[-1])
                    })
            except Exception:
                # Skip on any error (network, yfinance, indicator calculation, etc.)
                pass
        return self.picks[:5]  # Top 5 picks

agent = DayTradingAgent()

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Choose another.', 'danger')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    picks = agent.get_ai_picks()
    return render_template('dashboard.html', picks=picks, username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create DB tables
    app.run(debug=True)
