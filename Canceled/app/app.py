import os
import hashlib
from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
from flask_pymongo import PyMongo
from flask_mongoengine import MongoEngine
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, DateField, HiddenField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_login import LoginManager, current_user,login_required , login_user, logout_user,UserMixin
import datetime
application = Flask(__name__)
application.config['SECRET_KEY'] = 'you-will-never-guess'
application.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb+srv://canceled-app:5i0ZOoLVUwJejfiN@canceled-f4rau.mongodb.net/canceled_db?retryWrites=true&w=majority',
    'connect': False,
}
db = MongoEngine(application)
login_manager = LoginManager(application)
class User(UserMixin, db.Document):
    meta = {'collection': 'users'}
    name = db.StringField()
    email = db.EmailField()
    password_hash = db.StringField()

class Requests(UserMixin, db.Document):
    meta = {'collection': 'requests'}
    requester_email = db.StringField()
    requestee_email = db.StringField()
    title = db.StringField()
    friend_name = db.StringField()
    time = db.StringField()
    date = db.DateTimeField()
    status = db.StringField()

class Friend(UserMixin, db.Document):
    meta = {'collection': 'friends'}
    email = db.StringField()
    friend_email = db.StringField()
    name = db.StringField()
    friend_name = db.StringField()
    accept_status =  db.BooleanField()

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[DataRequired()])
    passwordComfirm = PasswordField('Comfirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

class RequestForm(FlaskForm):
    friend = SelectField(u'Friend', validators=[DataRequired()])
    title = StringField('Name of plan you would like to cancel', validators=[DataRequired()])
    date= DateField('Date of event',validators=[DataRequired()] )
    time = SelectField(u'Time of day', choices=[('Morning', 'Morning'), ('Midday', 'Midday'), ('Afternoon', 'Afternoon'), ('Evening', 'Evening'), ('Night', 'Night')], validators=[DataRequired()])
    submit = SubmitField('Create')

class DeleteRequestForm(FlaskForm):
    id = HiddenField( validators=[DataRequired()])
    close = SubmitField('X')

class AccountForm(FlaskForm):
    name = StringField('Full Name', validators=[])
    email = StringField('Email', validators=[Email(message='Invalid email')])
    curr_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[])
    new_passwordComfirm = PasswordField('Comfirm New Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Make Changes')

class FriendForm(FlaskForm):
    email = StringField("Friend's email")
    add = SubmitField('Add Friend')

class FriendsForm(FlaskForm):
    friend_name = HiddenField(validators=[DataRequired()])
    friend_email = HiddenField(validators=[DataRequired()])
    accept = SubmitField('Accept')
    deny = SubmitField('Deny')
    cancel = SubmitField('Cancel Request')
    remove = SubmitField('Remove')

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

@application.route('/')
def index():
    return render_template('home.html')

''' **** Login, Register, Logout - Routes *** '''
@application.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                hashpass = hashlib.sha256(str(form.password.data).encode())
                hashpass = str(hashpass.digest())
                if check_user['password_hash'] == hashpass:
                    login_user(check_user)
                    return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@application.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = hashlib.sha256(str(form.password.data).encode())
                hashpass = str(hashpass.digest())
                hey = User(name=form.name.data,email=form.email.data,password_hash=hashpass).save()
                login_user(hey)
                return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)
@application.route('/logout', methods = ['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@application.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    form =  RequestForm()
    close_form = DeleteRequestForm()
    if request.method == 'POST':
        if close_form.validate_on_submit():
            if close_form.close.data:
                Requests.objects(id=close_form.id.data).first().delete()
                return redirect(url_for('dashboard'))
    context = {
        'name': current_user.name,
        'requests' :Requests.objects(requester_email=current_user.email),
        'form': form,
        'close_form': close_form
    }
    context['form'].friend.choices = [(friend.friend_email, friend.friend_name) for friend in Friend.objects(email=current_user.email, accept_status=True ).order_by('friend_name')]
    if request.method == 'POST':
        if form.validate_on_submit():
            friend = Friend.objects(email=current_user.email, friend_email=form.friend.data,accept_status=True ).first()
            match = Requests.objects(requester_email=form.friend.data, requestee_email=current_user.email, date=form.date.data, time=form.time.data)
            if len(match) > 0:
                match.update(status="CANCELED")
                Requests(requester_email=current_user.email,requestee_email=form.friend.data,friend_name=friend.friend_name,title=form.title.data, date=form.date.data, time=form.time.data, status="CANCELED").save()
            else:
                Requests(requester_email=current_user.email,requestee_email=form.friend.data,friend_name=friend.friend_name,title=form.title.data, date=form.date.data, time=form.time.data, status="PENDING").save()
                return redirect(url_for('dashboard'))
    return render_template('dashboard.html', context=context)

@application.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = AccountForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            check_user = User.objects(email=current_user.email).first()
            if check_user:
                hashpass = hashlib.sha256(str(form.curr_password.data).encode())
                hashpass = str(hashpass.digest())
                if check_user['password_hash'] == hashpass:
                    if form.name.data  != '':
                        hashpass = hashlib.sha256(str(form.curr_password.data).encode())
                        hashpass = str(hashpass.digest())
                        User.objects(email=current_user.email).update(name=form.name.data)
                        check_user = User.objects(email=current_user.email).first()
                        logout_user()
                        if check_user:
                            if check_user['password_hash'] == hashpass:
                                login_user(check_user)
                    if form.email.data != '':
                        existing_user = User.objects(email=form.email.data).first()
                        if existing_user is None:
                            hashpass = hashlib.sha256(str(form.curr_password.data).encode())
                            hashpass = str(hashpass.digest())
                            User.objects(email=current_user.email).update(email=form.email.data)
                            check_user = User.objects(email=form.email.data).first()
                            logout_user()
                            if check_user:
                                if check_user['password_hash'] == hashpass:
                                    login_user(check_user)
                    if form.new_password.data  != '':
                        if form.new_passwordComfirm.data is not None:
                            if form.new_password.data == form.new_passwordComfirm.data:
                                hashpass = hashlib.sha256(str(form.new_password.data).encode())
                                hashpass = str(hashpass.digest())
                                User.objects(email=current_user.email).update(password_hash=hashpass)
                                check_user = User.objects(email=current_user.email).first()
                                logout_user()
                                if check_user:
                                    if check_user['password_hash'] == hashpass:
                                        login_user(check_user)
                    redirect(url_for('account'))
    return render_template('account.html', form=form)

@application.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    form_friends = FriendsForm()
    form_friend = FriendForm()
    if request.method == 'POST':
        if form_friend.validate_on_submit():
            if current_user.email != form_friend.email.data:
                usr = User.objects(email=form_friend.email.data).first()
                if usr is not None:
                    fr = Friend.objects(email=current_user.email, friend_email=form_friend.email.data).first()
                    if fr is None:
                        fr = Friend.objects(friend_email=current_user.email, email=form_friend.email.data).first()
                        if fr is None:
                            Friend(email=current_user.email, friend_email=usr.email,name=current_user.name,friend_name=usr.name, accept_status=False).save()
                            return redirect(url_for('friends'))
        if form_friends.validate_on_submit():
            if form_friends.accept.data:
                Friend.objects(email=form_friends.friend_email.data, friend_email=current_user.email,accept_status=False ).update(accept_status=True)
                Friend(email=current_user.email, friend_email=form_friends.friend_email.data,name=current_user.name,friend_name=form_friends.friend_name.data, accept_status=True).save()
                return redirect(url_for('friends'))
            if form_friends.deny.data:
                Friend.objects(email=form_friends.friend_email.data, friend_email=current_user.email,accept_status=False ).first().delete()
                return redirect(url_for('friends'))
            if form_friends.cancel.data:
                Friend.objects(friend_email=form_friends.friend_email.data, email=current_user.email,accept_status=False ).first().delete()
                return redirect(url_for('friends'))
            if form_friends.remove.data:
                Requests.objects(requester_email=current_user.email, requestee_email=form_friends.friend_email.data).delete()
                Requests.objects(requestee_email=current_user.email, requester_email=form_friends.friend_email.data).delete()
                Friend.objects(email=form_friends.friend_email.data, friend_email=current_user.email,accept_status=True ).first().delete()
                Friend.objects(friend_email=form_friends.friend_email.data, email=current_user.email,accept_status=True ).first().delete()
                return redirect(url_for('friends'))
    context = {
        'requests' :Friend.objects(friend_email=current_user.email),
        'friends' :Friend.objects(email=current_user.email),
        'form_friends' : form_friends,
        'form_friend' : form_friend
    }
    return render_template('friends.html', context=context)


if __name__ == "__main__":
    ENVIRONMENT_DEBUG = os.environ.get("APP_DEBUG", True)
    ENVIRONMENT_PORT = os.environ.get("APP_PORT", 5000)
    application.run(host='0.0.0.0', port=ENVIRONMENT_PORT, debug=ENVIRONMENT_DEBUG)
