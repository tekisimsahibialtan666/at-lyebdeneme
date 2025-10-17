import os
import secrets
from datetime import datetime, timedelta
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
from sqlalchemy import or_
from flask_wtf import CSRFProtect, FlaskForm
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import (
    BooleanField,
    HiddenField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional
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
    is_active_account = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)

    messages = db.relationship("Message", backref="author", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self) -> bool:  # type: ignore[override]
        return self.is_active_account


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


class SiteContent(db.Model):
    __tablename__ = "site_content"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SiteSetting(db.Model):
    __tablename__ = "site_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Message(db.Model):
    __tablename__ = "messages"

    STATUS_NEW = "new"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_RESPONDED = "responded"
    STATUS_ARCHIVED = "archived"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(120), default="General Inquiry")
    tags = db.Column(db.String(255))
    status = db.Column(db.String(20), default=STATUS_NEW, index=True)
    admin_response = db.Column(db.Text)
    responded_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False, index=True)
    archived_at = db.Column(db.DateTime)

    def update_status(self, status: str) -> None:
        valid_statuses = {
            self.STATUS_NEW,
            self.STATUS_IN_PROGRESS,
            self.STATUS_RESPONDED,
            self.STATUS_ARCHIVED,
        }
        if status not in valid_statuses:
            raise ValueError("Invalid status")
        self.status = status
        if status == self.STATUS_RESPONDED and not self.responded_at:
            self.responded_at = datetime.utcnow()
        if status == self.STATUS_ARCHIVED:
            self.archived_at = datetime.utcnow()


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
    category = SelectField(
        "Topic",
        choices=[
            ("General Inquiry", "General Inquiry"),
            ("Project Consultation", "Project Consultation"),
            ("Collaboration", "Collaboration"),
            ("Press", "Press"),
        ],
    )
    content = TextAreaField("Message", validators=[InputRequired(), Length(max=2000)])
    submit = SubmitField("Send Message")


class MessageAdminForm(FlaskForm):
    status = SelectField(
        "Status",
        choices=[
            (Message.STATUS_NEW, "New"),
            (Message.STATUS_IN_PROGRESS, "In Progress"),
            (Message.STATUS_RESPONDED, "Responded"),
            (Message.STATUS_ARCHIVED, "Archived"),
        ],
    )
    category = StringField("Category", validators=[InputRequired(), Length(max=120)])
    tags = StringField(
        "Tags",
        description="Comma-separated keywords",
        validators=[Optional(), Length(max=255)],
    )
    admin_response = TextAreaField("Admin Response", validators=[Optional()])
    mark_read = BooleanField("Mark as read")
    submit = SubmitField("Update Message")
    message_id = HiddenField(validators=[InputRequired()])


class MessageFilterForm(FlaskForm):
    status = SelectField(
        "Status",
        choices=[
            ("", "All"),
            (Message.STATUS_NEW, "New"),
            (Message.STATUS_IN_PROGRESS, "In Progress"),
            (Message.STATUS_RESPONDED, "Responded"),
            (Message.STATUS_ARCHIVED, "Archived"),
        ],
        default="",
        validators=[Optional()],
    )
    category = SelectField("Category", choices=[], validators=[Optional()])
    search = StringField("Search", validators=[Optional(), Length(max=120)])
    start_date = StringField("Start Date", validators=[Optional()])
    end_date = StringField("End Date", validators=[Optional()])
    submit = SubmitField("Apply Filters")


class AboutContentForm(FlaskForm):
    headline = StringField("Headline", validators=[InputRequired(), Length(max=200)])
    body = TextAreaField("About Content", validators=[InputRequired()])
    phone = StringField("Phone", validators=[InputRequired(), Length(max=40)])
    address = TextAreaField("Address", validators=[InputRequired(), Length(max=255)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    instagram = StringField(
        "Instagram", validators=[InputRequired(), Length(max=120)], description="Handle without @"
    )
    submit = SubmitField("Save About Page")


class UserStatusForm(FlaskForm):
    user_id = HiddenField(validators=[InputRequired()])
    is_admin = BooleanField("Administrator")
    is_active_account = BooleanField("Active")
    submit = SubmitField("Update User")


@app.template_filter("nl2br")
def nl2br_filter(value: str) -> Markup:
    if not value:
        return Markup("")
    escaped = escape(value)
    return Markup("<br>".join(escaped.splitlines()))


def get_setting(key: str, default: str = "") -> str:
    setting = SiteSetting.query.filter_by(key=key).first()
    return setting.value if setting else default


def set_setting(key: str, value: str) -> SiteSetting:
    setting = SiteSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = SiteSetting(key=key, value=value)
        db.session.add(setting)
    return setting


def get_about_content() -> SiteContent:
    about = SiteContent.query.filter_by(slug="about").first()
    if not about:
        about = SiteContent(
            slug="about",
            title="Designing spaces that inspire",
            body=(
                "At Atölye B Mimarlık we craft environments that merge form, "
                "function, and emotion. Our interdisciplinary team researches "
                "context, materiality, and human experience to create tailored "
                "solutions for each client."
            ),
        )
        db.session.add(about)
        db.session.commit()
    return about


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated and current_user.is_admin:
        unread_count = Message.query.filter_by(is_read=False).count()
    return {
        "unread_count": unread_count,
        "current_year": datetime.utcnow().year,
        "contact_phone": get_setting("contact_phone", "0(312) 428 6283"),
        "contact_address": get_setting(
            "contact_address", "Kıbrıs Sokak 17/2 PK:06690 A.AYRANCI/ÇANKAYA/ANKARA"
        ),
        "contact_email": get_setting("contact_email", "info@atolyeb.com"),
        "contact_instagram": get_setting("contact_instagram", "atölyebmimarlık"),
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
    about_content = get_about_content()
    contact_info = {
        "phone": get_setting("contact_phone", "0(312) 428 6283"),
        "address": get_setting(
            "contact_address", "Kıbrıs Sokak 17/2 PK:06690 A.AYRANCI/ÇANKAYA/ANKARA"
        ),
        "email": get_setting("contact_email", "info@atolyeb.com"),
        "instagram": get_setting("contact_instagram", "atölyebmimarlık"),
    }
    return render_template(
        "about.html",
        about_content=about_content,
        contact_info=contact_info,
    )


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
            user_id=current_user.id,
            name=form.name.data,
            email=form.email.data,
            category=form.category.data,
            content=form.content.data,
        )
        db.session.add(message)
        db.session.commit()
        flash("Your message has been sent. Our team will get back to you soon.", "success")
        return redirect(url_for("contact"))

    if current_user.is_authenticated and request.method == "GET":
        form.name.data = current_user.name
        form.email.data = current_user.email
        form.category.data = "General Inquiry"

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
            user.last_login_at = datetime.utcnow()
            db.session.commit()
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
    status_counts = {
        Message.STATUS_NEW: Message.query.filter_by(status=Message.STATUS_NEW).count(),
        Message.STATUS_IN_PROGRESS: Message.query.filter_by(
            status=Message.STATUS_IN_PROGRESS
        ).count(),
        Message.STATUS_RESPONDED: Message.query.filter_by(
            status=Message.STATUS_RESPONDED
        ).count(),
        Message.STATUS_ARCHIVED: Message.query.filter_by(
            status=Message.STATUS_ARCHIVED
        ).count(),
    }
    latest_messages = (
        Message.query.order_by(Message.created_at.desc()).limit(5).all()
    )
    recent_users = (
        User.query.order_by(User.created_at.desc()).limit(5).all()
    )
    return render_template(
        "admin/dashboard.html",
        project_count=project_count,
        message_count=message_count,
        unread_messages=unread_messages,
        latest_messages=latest_messages,
        status_counts=status_counts,
        recent_users=recent_users,
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


@app.route("/admin/about", methods=["GET", "POST"])
@login_required
@admin_required
def admin_about():
    about = get_about_content()
    form = AboutContentForm()
    if form.validate_on_submit():
        about.title = form.headline.data
        about.body = form.body.data
        set_setting("contact_phone", form.phone.data)
        set_setting("contact_address", form.address.data)
        set_setting("contact_email", form.email.data)
        set_setting("contact_instagram", form.instagram.data)
        db.session.commit()
        flash("About page updated.", "success")
        return redirect(url_for("admin_about"))

    if request.method == "GET":
        form.headline.data = about.title
        form.body.data = about.body
        form.phone.data = get_setting("contact_phone", "0(312) 428 6283")
        form.address.data = get_setting(
            "contact_address", "Kıbrıs Sokak 17/2 PK:06690 A.AYRANCI/ÇANKAYA/ANKARA"
        )
        form.email.data = get_setting("contact_email", "info@atolyeb.com")
        form.instagram.data = get_setting("contact_instagram", "atölyebmimarlık")

    return render_template("admin/about.html", form=form, about=about)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_users():
    if request.method == "POST":
        form = UserStatusForm()
        if form.validate_on_submit():
            user = User.query.get_or_404(int(form.user_id.data))
            if user.id == current_user.id and not form.is_admin.data:
                flash("You cannot remove your own admin access.", "warning")
                return redirect(url_for("admin_users"))
            if user.id == current_user.id and not form.is_active_account.data:
                flash("You cannot deactivate your own account while logged in.", "warning")
                return redirect(url_for("admin_users"))
            user.is_admin = form.is_admin.data
            user.is_active_account = form.is_active_account.data
            db.session.commit()
            flash("User permissions updated.", "success")
        else:
            flash("Unable to update user.", "danger")
        return redirect(url_for("admin_users"))

    users = User.query.order_by(User.created_at.desc()).all()
    forms = {}
    for user in users:
        form = UserStatusForm()
        form.user_id.data = user.id
        form.is_admin.data = user.is_admin
        form.is_active_account.data = user.is_active_account
        forms[user.id] = form

    return render_template("admin/users.html", users=users, forms=forms)


@app.route("/admin/messages", methods=["GET", "POST"])
@login_required
@admin_required
def admin_messages():
    filter_form = MessageFilterForm(request.args, meta={"csrf": False})
    categories = [
        row[0]
        for row in db.session.query(Message.category)
        .filter(Message.category.isnot(None))
        .distinct()
        .order_by(Message.category.asc())
        .all()
    ]
    filter_form.category.choices = [("", "All Categories")] + [
        (category, category) for category in categories
    ]

    if request.method == "POST":
        admin_form = MessageAdminForm()
        if admin_form.validate_on_submit():
            message = Message.query.get_or_404(int(admin_form.message_id.data))
            message.update_status(admin_form.status.data)
            message.category = admin_form.category.data
            message.tags = admin_form.tags.data
            response_text = (admin_form.admin_response.data or "").strip()
            message.admin_response = response_text or None
            if response_text:
                if admin_form.status.data != Message.STATUS_ARCHIVED:
                    message.update_status(Message.STATUS_RESPONDED)
                if not message.responded_at:
                    message.responded_at = datetime.utcnow()
            if admin_form.mark_read.data:
                message.is_read = True
            elif message.status == Message.STATUS_NEW:
                message.is_read = False
            else:
                message.is_read = True
            db.session.commit()
            flash("Message updated.", "success")
        else:
            flash("Unable to update message. Please review the form inputs.", "danger")
        return redirect(url_for("admin_messages", **request.args))

    query = Message.query
    if filter_form.validate():
        if filter_form.status.data:
            query = query.filter_by(status=filter_form.status.data)
        if filter_form.category.data:
            query = query.filter_by(category=filter_form.category.data)
        if filter_form.search.data:
            search_term = f"%{filter_form.search.data.strip()}%"
            query = query.filter(
                or_(
                    Message.name.ilike(search_term),
                    Message.email.ilike(search_term),
                    Message.content.ilike(search_term),
                    Message.tags.ilike(search_term),
                )
            )
        start = parse_date(filter_form.start_date.data)
        if start:
            query = query.filter(Message.created_at >= start)
        end = parse_date(filter_form.end_date.data)
        if end:
            query = query.filter(Message.created_at < end + timedelta(days=1))

    messages = query.order_by(Message.created_at.desc()).all()
    message_forms = {}
    for message in messages:
        form = MessageAdminForm()
        form.message_id.data = message.id
        form.status.data = message.status
        form.category.data = message.category or "General Inquiry"
        form.tags.data = message.tags or ""
        form.admin_response.data = message.admin_response or ""
        form.mark_read.data = message.is_read
        message_forms[message.id] = form

    return render_template(
        "admin/messages.html",
        messages=messages,
        filter_form=filter_form,
        message_forms=message_forms,
    )


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
