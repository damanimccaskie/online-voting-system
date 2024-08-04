from datetime import datetime
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required

app = Flask(__name__) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting_system.db'
app.config["SECRET_KEY"] = "hello"
db = SQLAlchemy(app)
login = LoginManager(app)

@login.user_loader
def load_user(id):
    return User.query.get(id)




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    date_created = db.Column(db.Date, default=datetime.datetime.now)
    polls = db.relationship('Poll', backref='creator', lazy=True)
    votes = db.relationship('Vote', backref='voter', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    choices = db.relationship('Choice', backref='poll', lazy=True)
    votes = db.relationship('Vote', backref='poll', lazy=True)

class Choice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    text = db.Column(db.String(200), nullable=False)
    votes = db.relationship('Vote', backref='choice', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    choice_id = db.Column(db.Integer, db.ForeignKey('choice.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()

admin = Admin(app, index_view=AdminIndexView())
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Poll, db.session))
admin.add_view(ModelView(Choice, db.session))
admin.add_view(ModelView(Vote, db.session))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        if check_if_user_exists(username):
            return jsonify({'message': 'User already exists'}), 400
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('home')
    return render_template('register.html')

def check_if_user_exists(username):
    if User.filter_by(username=username).first():
            return True
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.filter_by(username=username).first()

        if check_password_hash(user.password, password):
            login_user(username)
            return redirect(url_for('home'))
        else:
            return jsonify({'message': 'Username and Password do not match'}), 400
    return render_template('login.html')


@app.route('/create_poll', methods=['GET', 'POST'])
def create_poll():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        choices = request.form['choices']
        creator_id = current_user.id

        new_poll = Poll(title=title, description=description, creator_id=creator_id)

        db.session.add(new_poll)
        db.session.commit()

        choices = choices.split(',')
        for choice in choices:
            new_choice = Choice(text=choice, poll_id=new_poll.poll_id)
            db.session.add(new_choice)
        db.session.commit()

        return jsonify({'message': 'Poll created successfully'}), 201
    return render_template('create_poll.html')


@app.route('/')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)