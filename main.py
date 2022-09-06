from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, URLField, BooleanField, SubmitField, RadioField, SelectField, validators, PasswordField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap, forms
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SECRET_KEY'] = 'jigar'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String(250))
    coffee_price = db.Column(db.String(250))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class AddUser(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginUser(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class AddCafe(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    map_url = URLField('Map Url', validators=[DataRequired()])
    img_url = URLField('Image Url', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    has_sockets = SelectField('Has Sockets', choices=['Yes', 'No'])
    has_toilet = SelectField('Has Toilet', choices=['Yes', 'No'])
    has_wifi = SelectField('Has Wifi', choices=['Yes', 'No'])
    can_take_calls = SelectField('Can Take Calls', choices=['Yes', 'No'])
    seats = StringField('Seats', validators=[DataRequired()])
    coffee_price = StringField('Coffee Price', validators=[DataRequired()])
    submit = SubmitField('Submit')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# main route
@app.route('/')
def index():
    return render_template('index.html')


# Register user
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = AddUser()
    if form.validate_on_submit():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            hashed_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=16)
            user = User(email=email.lower(), password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Registered Successfully')
            return render_template('index.html')
    return render_template('register.html', form=form)


# login
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        if request.method == 'POST':
            email = request.form['email'].lower()
            password = request.form['password']
            if User.query.filter_by(email=email).first() is not None:
                user = User.query.filter_by(email=email).first()
                hashed_password = user.password
                print(hashed_password)
                if check_password_hash(password=password, pwhash=hashed_password):
                    login_user(user)
                    flash('Logged in Successfully', category='success')
                    return render_template('index.html')
                else:
                    flash('Invalid password', category='error')
                    return render_template('login.html', form=form)
            else:
                flash('User not found')
                return render_template('register.html')
    return render_template('login.html', form=form)


# logout user
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html')


# cafe route
@app.route('/cafes')
def get_cafe():
    cafes = Cafe.query.all()
    return render_template('cafes.html', cafes=cafes)


# form
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_cafe():
    form = AddCafe()
    if form.validate_on_submit():
        if request.method == 'POST':
            name = request.form['name']
            map_url = request.form['map_url']
            img_url = request.form['img_url']
            location = request.form['location']
            if request.form['has_sockets'] == 'Yes':
                has_sockets = True
            else:
                has_sockets = False

            if request.form['has_toilet'] == "Yes":
                has_toilet = True
            else:
                has_toilet = False

            if request.form['has_wifi'] == "Yes":
                has_wifi = True
            else:
                has_wifi = False

            if request.form['can_take_calls'] == 'Yes':
                can_take_calls = True
            else:
                can_take_calls = False

            seats = request.form['seats']
            coffee_price = request.form['coffee_price']
            new_cafe = Cafe(name=name, map_url=map_url, img_url=img_url, location=location, has_sockets=has_sockets,
                            has_toilet=has_toilet, has_wifi=has_wifi, can_take_calls=can_take_calls, seats=seats,
                            coffee_price=coffee_price)
            db.session.add(new_cafe)
            db.session.commit()
            message = 'Cafe added successfully'
            return redirect(url_for('index'))
    return render_template('form.html', form=form)


@app.route('/edit/<int:cafe_id>', methods=['GET', 'POST'])
@login_required
def edit_cafe(cafe_id):
    print('button clicked')
    cafe = Cafe.query.filter_by(id=cafe_id).first()
    form = AddCafe()
    form.name.data = cafe.name
    form.map_url.data = cafe.map_url
    form.img_url.data = cafe.img_url
    form.location.data = cafe.location
    if cafe.has_sockets == 1:
        form.has_sockets.data = 'Yes'
    else:
        form.has_sockets.data = "No"
    if cafe.has_toilet == 1:
        form.has_toilet.data = 'Yes'
    else:
        form.has_toilet.data = "No"
    if cafe.has_wifi == 1:
        form.has_wifi.data = 'Yes'
    else:
        form.has_wifi.data = "No"
    if cafe.can_take_calls == 1:
        form.can_take_calls.data = 'Yes'
    else:
        form.can_take_calls.data = "No"
    form.seats.data = cafe.seats
    form.coffee_price.data = cafe.coffee_price
    if form.validate_on_submit():
        if request.method == 'POST':
            cafe.name = request.form['name']
            cafe.map_url = request.form['map_url']
            cafe.img_url = request.form['img_url']
            cafe.location = request.form['location']
            if request.form['has_sockets'] == 'Yes':
                cafe.has_sockets = True
            else:
                cafe.has_sockets = False

            if request.form['has_toilet'] == "Yes":
                cafe.has_toilet = True
            else:
                cafe.has_toilet = False

            if request.form['has_wifi'] == "Yes":
                cafe.has_wifi = True
            else:
                cafe.has_wifi = False

            if request.form['can_take_calls'] == 'Yes':
                cafe.can_take_calls = True
            else:
                cafe.can_take_calls = False
            cafe.seats = request.form['seats']
            cafe.coffee_price = request.form['coffee_price']
            db.session.commit()
            flash('Cafe info updated successfully')
            # message = 'Cafe info updated successfully'
            return redirect(url_for('get_cafe'))
    return render_template('form.html', form=form)


@app.route('/delete/<int:cafe_id>', methods=['GET', 'POST'])
@login_required
def delete(cafe_id):
    print('Cafe is getting deleted')
    cafe = Cafe.query.filter_by(id=cafe_id).first()
    db.session.delete(cafe)
    db.session.commit()
    flash('Cafe deleted successfully')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
