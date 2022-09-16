from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, EmailField, PasswordField, TextAreaField, DateField, \
    TimeField
from wtforms.validators import InputRequired
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
import os
from flask_gravatar import Gravatar

HASH = 'pbkdf2:sha256'
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(uri,'sqlite:///userdata.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return UserData.query.get(user_id)


# table
class UserData(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    Email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    activities = db.relationship('Activity', backref='owner_id')

class Activity(db.Model):
    __tablename__ = "Task"
    id = db.Column(db.Integer, primary_key=True)
    Task = db.Column(db.String(300), nullable=False)
    collaborator_name = db.Column(db.String(120), nullable=True)
    collaborator_task = db.Column(db.String(300), nullable=True)
    timeline = db.Column(db.String(), nullable=False)
    due_time = db.Column(db.String(), nullable=False)
    user_data_id = db.Column(db.Integer, db.ForeignKey('users.id'))


db.create_all()


# forms
class UserSchedule(FlaskForm):
    company_name = StringField(label='Company name', validators=None)
    task = StringField(label='Task', validators=[InputRequired()])
    contributors = IntegerField(label='Number of contributors', validators=[InputRequired()])
    # when posted if the contributors are above 1 we generate another form for the user to describe the activites of the
    # contributors.
    contributors_name = StringField(label='please enter contributors name')
    description = TextAreaField(label='Enter work description', validators=[InputRequired()])
    contributors_task = TextAreaField(label="contributors work description", validators=[InputRequired()])
    start_date = DateField(label='Start date', validators=[InputRequired()])
    stop_date = DateField(label='Stop date', validators=[InputRequired()])
    due_time = TimeField(label="Due time", validators=[InputRequired()])
    submit = SubmitField(label="Submit", validators=[InputRequired()])


class LoginUser(FlaskForm):
    email = EmailField(label="Email Address", validators=[InputRequired()])
    password = PasswordField(label="Password", validators=[InputRequired()])
    submit = SubmitField(label='Login')


class RegisterUser(FlaskForm):
    name = StringField(label='Name', validators=[InputRequired()])
    email = EmailField(label='Email Address', validators=[InputRequired()])
    password = PasswordField(label='Password', validators=[InputRequired()])
    Reconfirm = PasswordField(label='Reconfirm password', validators=[InputRequired()])
    submit = SubmitField(label="Submit", validators=[InputRequired()])


@app.route("/register", methods=['POST', 'GET'])
def registration():
    forms = RegisterUser()
    if request.method == 'GET':
        return render_template('register.html', form=forms)
    elif request.method == 'POST':
        new_pass = generate_password_hash(password=forms.password.data, method=HASH, salt_length=8)
        new_user = UserData(
            name=forms.name.data,
            Email=forms.email.data,
            password=new_pass,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))


@app.route("/", methods=['POST', 'GET'])
def Homepage():
    if request.method == 'GET':
        return render_template('index.html')


@app.route("/login", methods=['POST', 'GET'])
def login():
    forms = LoginUser()
    if request.method == 'GET':
        return render_template("login.html", form=forms)
    elif request.method == "POST":
        user = UserData.query.filter_by(Email=forms.email.data).first()
        passwords = forms.password.data
        if not user:
            flash("This email doesnt exist, please go to the register tab.", 'error')
            return  redirect(url_for('login'))
        elif not check_password_hash(pwhash=user.password, password=passwords):
            flash(message="Password incorrect, Please try again", category='error')
            print('wrong password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('schedule', user=current_user))


@app.route("/addschedule", methods=['POST', 'GET'])
@login_required
def schedule():
    forms = UserSchedule()
    if request.method == 'GET':
        return render_template('scheduler.html', form=forms)
    elif request.method == 'POST':
        time_1 = forms.due_time.data
        due_time = str(time_1)
        new = Activity(
            Task=forms.description.data,
            collaborator_name=forms.contributors_name.data,
            collaborator_task=forms.contributors_task.data,
            timeline=f"{forms.start_date.data} till {forms.stop_date.data}",
            due_time=due_time,
            user_data_id=current_user.id
        )
        db.session.add(new)
        db.session.commit()
        return redirect(url_for('task'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('Homepage'))

@app.route("/tasks")
@login_required
def task():
    user = Activity.query.filter_by(user_data_id=current_user.id).all()
    return render_template('display.html', tasks=user)


if __name__ == '__main__':
    app.run(debug=True)
