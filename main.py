from datetime import datetime as dt
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
    date_created = db.Column(db.Date, default=dt.now)
    polls = db.relationship('Poll', backref='creator', lazy=True)
    votes = db.relationship('Vote', backref='voter', lazy=True)

    # Flask-Login integration
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    # Optional: Add methods to set and check passwords
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
        return redirect('/')
    return render_template('register.html')

def check_if_user_exists(username):
    if not User.query.filter_by(username=username).first():
            return False
    return True

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
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

        if check_if_logged_in():
            new_poll = Poll(title=title, description=description, creator_id=creator_id)

            db.session.add(new_poll)
            db.session.commit()

            choices = choices.split(',')
            for choice in choices:
                new_choice = Choice(text=choice, poll_id=new_poll.id)
                db.session.add(new_choice)
            db.session.commit()

            return jsonify({'message': 'Poll created successfully'}), 201
        else:
            return jsonify({'message': 'Please login to create a poll'}), 200
    return render_template('create_poll.html')


@app.route('/poll/<int:poll_id>')
def poll(poll_id):
    
    poll = get_poll(poll_id)

    return render_template('poll.html', poll=poll)


def get_poll(poll_id):
    return Poll.query.get(poll_id)

def check_if_logged_in():
    if current_user.is_authenticated:
        return True
    return False


@app.route('/')
def home():
    logged_in  = check_if_logged_in()
    polls = get_all_polls()
    return render_template('home.html', logged_in=logged_in, polls=polls)


def get_all_polls():
    return Poll.query.all()

@app.route('/logout')
def logout():
    logout_user()  # Logout the current user
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(debug=True)