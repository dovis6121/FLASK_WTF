from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

app = Flask(__name__)
app.secret_key = 'secret_key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Change the database URI as per your needs
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

bcrypt = Bcrypt(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Flask-WTF Form Classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                          validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', 
                            validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username',
                          validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password',
                            validators=[DataRequired()])
    submit = SubmitField('Log In')

@app.route('/')
def home():
    if current_user.is_authenticated:
        username = current_user.username  # Fixed: Show actual username
    else:
        username = None
    return render_template('index.html', username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password before storing
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('home'))  # Fixed: Redirect to home instead of register
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Fixed: Actually log out the user
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
