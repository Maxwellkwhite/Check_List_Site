from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, RadioField, SelectField, PasswordField
from wtforms.validators import DataRequired
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

SECRET_KEY = os.environ.get("SECRET_KEY")

app = Flask(__name__)
ckeditor = CKEditor(app)
Bootstrap5(app)
app.config['SECRET_KEY'] = "ABLJKJt23354FDJODJF123454523466JFDOSF3"

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass
db_path = os.path.abspath(os.path.join(os.path.dirname("Final_Projects/Check_List_Site/instance"), "tasks.db"))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class CreateTask(FlaskForm):
    task = StringField(validators=[DataRequired()], render_kw={'placeholder': 'New Task Here', 
                                                               'class':'focus_new'}, label='')

class EditTask(FlaskForm):
    task = StringField(validators=[DataRequired()], render_kw={'style': 'width: 50ch'})

# Create a form to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

# Create a form to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class InProgressTaskList(db.Model):
    __tablename__ = "in_progress_tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    task_name: Mapped[str] = mapped_column(String(250), unique=False, nullable=False)
    completed: Mapped[int] = mapped_column(Integer, nullable=True)
    color: Mapped[str] = mapped_column(String(250))
    project: Mapped[str] = mapped_column(String(250))
    # author = relationship("User", back_populates="tasks")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    # tasks = relationship("InProgressTaskList", back_populates="author")

with app.app_context():
    db.create_all()

@app.route('/', methods=["GET", "POST"])
def all_tasks():
    form = CreateTask()
    form2 = EditTask()
    result = db.session.execute(db.select(InProgressTaskList))
    tasks = result.scalars().all()
    if form.validate_on_submit():
        new_task = InProgressTaskList(
            user_id=current_user.id,
            task_name=form.task.data,
            completed=0,
            color='white',
            project='No Project')
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("all_tasks"))
    return render_template("index.html", form=form, tasks=tasks, form2=form2, current_user=current_user)

@app.route("/update/<int:id>", methods =["GET", "POST"])
def update(id):
    if request.method == "POST":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.completed += 1
            db.session.commit()
        return redirect(url_for('all_tasks'))


@app.route("/task_update/<int:id>", methods =["GET", "POST"])
def task_update(id):
    if request.method == "POST":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.task_name = request.form.get("task_name")
            db.session.commit()
        return redirect(url_for('all_tasks'))
    
@app.route("/project_update/<int:id>", methods =["GET", "POST"])
def project_update(id):
    if request.method == "POST":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.project = request.form.get("project_name")
            db.session.commit()
        return redirect(url_for('all_tasks'))

@app.route("/color/<int:id>", methods =['POST','GET'])
def color(id):
    result = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
    if result.color == "yellow":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.color = "white"
            db.session.commit()
        return redirect(url_for('all_tasks'))
    elif result.color == "white":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.color = "yellow"
            db.session.commit()
        return redirect(url_for('all_tasks'))
    
@app.route("/delete/<int:id>", methods =['POST','GET'])
def delete_post(id):
    if request.method == "POST":
        post_to_delete = db.get_or_404(InProgressTaskList, id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('all_tasks'))

@app.route("/completed")
def completed():
    result = db.session.execute(db.select(InProgressTaskList))
    tasks = result.scalars().all()
    return render_template("completed.html", tasks=tasks)

@app.route("/fulltasks")
def full_tasks():
    result = db.session.execute(db.select(InProgressTaskList))
    tasks = result.scalars().all()
    return render_template("copy_tasks.html", tasks=tasks)

@app.route("/demote/<int:id>", methods =['POST','GET'])
def demote(id):
    if request.method == "POST":
        with app.app_context():
            completed_update = db.session.execute(db.select(InProgressTaskList).where(InProgressTaskList.id == id)).scalar()
            completed_update.completed -= 1
            db.session.commit()
        return redirect(url_for('all_tasks'))
    
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("all_tasks"))
    return render_template("register.html", form=form, current_user=current_user)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('all_tasks'))

    return render_template("login.html", form=form, current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('all_tasks'))

if __name__ == "__main__":
    app.run(debug=False, port=5002)
