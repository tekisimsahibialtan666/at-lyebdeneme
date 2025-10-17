import os
import secrets
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect, FlaskForm
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import BooleanField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import Email, EqualTo, InputRequired, Length
from wtforms.fields import MultipleFileField


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'site.db'}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
    app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

    return app


app = create_app()
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship("Message", backref="author", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200))
    short_description = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    design_philosophy = db.Column(db.Text)
    materials = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    images = db.relationship("ProjectImage", backref="project", cascade="all, delete-orphan")


class ProjectImage(db.Model):
    __tablename__ = "project_images"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def allowed_file(filename: str) -> bool:
    allowed_extensions = {"png", "jpg", "jpeg", "gif", "webp"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


class RegistrationForm(FlaskForm):
    name = StringField("Full Name", validators=[InputRequired(), Length(max=120)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            InputRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
        ],
    )
    confirm = PasswordField(
        "Confirm Password",
        validators=[InputRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[InputRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class ProjectForm(FlaskForm):
    title = StringField("Project Title", validators=[InputRequired(), Length(max=200)])
    location = StringField("Location", validators=[Length(max=200)])
    short_description = StringField(
        "Short Description", validators=[InputRequired(), Length(max=255)]
    )
    description = TextAreaField("Project Overview", validators=[InputRequired()])
    design_philosophy = TextAreaField("Design Philosophy")
    materials = TextAreaField("Materials & Systems")
    images = MultipleFileField("Project Images")
    submit = SubmitField("Save Project")


class MessageForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=120)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    content = TextAreaField("Message", validators=[InputRequired(), Length(max=2000)])
    submit = SubmitField("Send Message")


@app.template_filter("nl2br")
def nl2br_filter(value: str) -> Markup:
    if not value:
        return Markup("")
    escaped = escape(value)
    return Markup("<br>".join(escaped.splitlines()))


@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated and current_user.is_admin:
        unread_count = Message.query.filter_by(is_read=False).count()
    return {
        "unread_count": unread_count,
        "current_year": datetime.utcnow().year,
    }


@app.route("/")
def index():
    projects = Project.query.order_by(Project.created_at.desc()).limit(6).all()
    return render_template("index.html", projects=projects)


@app.route("/portfolio")
def portfolio():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("portfolio.html", projects=projects)


@app.route("/portfolio/<int:project_id>")
def project_detail(project_id: int):
    project = Project.query.get_or_404(project_id)
    return render_template("project_detail.html", project=project)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
            user_id=current_user.id,
            name=form.name.data,
            email=form.email.data,
            content=form.content.data,
        )
        db.session.add(message)
        db.session.commit()
        flash("Your message has been sent. Our team will get back to you soon.", "success")
        return redirect(url_for("contact"))

    if current_user.is_authenticated and request.method == "GET":
        form.name.data = current_user.name
        form.email.data = current_user.email

    return render_template("contact.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data.lower()).first()
        if existing_user:
            flash("An account with that email already exists.", "danger")
        else:
            user = User(
                name=form.name.data,
                email=form.email.data.lower(),
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Welcome back!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


def admin_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def handle_project_images(project: Project, files):
    for file in files:
        if not file or file.filename == "":
            continue
        if not allowed_file(file.filename):
            flash(f"Unsupported file type: {file.filename}", "warning")
            continue
        filename = secure_filename(file.filename)
        unique_name = f"{secrets.token_hex(8)}_{filename}"
        filepath = UPLOAD_DIR / unique_name
        file.save(filepath)
        image = ProjectImage(filename=unique_name, project=project)
        db.session.add(image)


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    project_count = Project.query.count()
    message_count = Message.query.count()
    unread_messages = Message.query.filter_by(is_read=False).count()
    latest_messages = (
        Message.query.order_by(Message.created_at.desc()).limit(5).all()
    )
    return render_template(
        "admin/dashboard.html",
        project_count=project_count,
        message_count=message_count,
        unread_messages=unread_messages,
        latest_messages=latest_messages,
    )


@app.route("/admin/projects")
@login_required
@admin_required
def admin_projects():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("admin/projects.html", projects=projects)


@app.route("/admin/projects/new", methods=["GET", "POST"])
@login_required
@admin_required
def admin_create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            location=form.location.data,
            short_description=form.short_description.data,
            description=form.description.data,
            design_philosophy=form.design_philosophy.data,
            materials=form.materials.data,
        )
        db.session.add(project)
        handle_project_images(project, form.images.data)
        db.session.commit()
        flash("Project created successfully.", "success")
        return redirect(url_for("admin_projects"))
    return render_template("admin/project_form.html", form=form, title="New Project")


@app.route("/admin/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_project(project_id: int):
    project = Project.query.get_or_404(project_id)
    form = ProjectForm(obj=project)
    if form.validate_on_submit():
        project.title = form.title.data
        project.location = form.location.data
        project.short_description = form.short_description.data
        project.description = form.description.data
        project.design_philosophy = form.design_philosophy.data
        project.materials = form.materials.data

        delete_ids = request.form.getlist("delete_images")
        if delete_ids:
            for image_id in delete_ids:
                image = ProjectImage.query.get(int(image_id))
                if image and image.project_id == project.id:
                    image_path = UPLOAD_DIR / image.filename
                    if image_path.exists():
                        image_path.unlink()
                    db.session.delete(image)

        handle_project_images(project, form.images.data)
        db.session.commit()
        flash("Project updated successfully.", "success")
        return redirect(url_for("admin_projects"))
    return render_template(
        "admin/project_form.html",
        form=form,
        title=f"Edit {project.title}",
        project=project,
    )


@app.route("/admin/projects/<int:project_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_project(project_id: int):
    project = Project.query.get_or_404(project_id)
    for image in project.images:
        image_path = UPLOAD_DIR / image.filename
        if image_path.exists():
            image_path.unlink()
    db.session.delete(project)
    db.session.commit()
    flash("Project deleted.", "info")
    return redirect(url_for("admin_projects"))


@app.route("/admin/messages")
@login_required
@admin_required
def admin_messages():
    messages = Message.query.order_by(Message.created_at.desc()).all()
    return render_template("admin/messages.html", messages=messages)


@app.route("/admin/messages/<int:message_id>/read", methods=["POST"])
@login_required
@admin_required
def admin_mark_message(message_id: int):
    message = Message.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()
    flash("Message marked as read.", "success")
    return redirect(url_for("admin_messages"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename: str):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.cli.command("create-admin")
def create_admin():
    """Create or update the default admin account."""
    import getpass

    email = input("Admin email: ").strip().lower()
    name = input("Admin name: ").strip()
    password = getpass.getpass("Admin password: ")

    if not email or not password or not name:
        print("All fields are required.")
        return

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            user.name = name
            user.is_admin = True
            user.set_password(password)
            message = "Updated existing admin account."
        else:
            user = User(name=name, email=email, is_admin=True)
            user.set_password(password)
            db.session.add(user)
            message = "Created new admin account."
        db.session.commit()
        print(message)


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
