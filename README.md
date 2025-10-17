# Atölye B Mimarlık Website

A modern, database-driven portfolio website for Atölye B Mimarlık featuring a sophisticated front-end experience, secure user authentication, project management, and an admin-only inbox for client messages.

## Features

- Responsive, animated marketing site with portfolio grid, hero interactions, and curated content pages.
- Portfolio management with drag-and-drop image uploads, multi-image galleries, and expandable project details.
- Secure registration and login backed by hashed passwords and persistent SQLite storage.
- Role-based admin panel to manage projects, review user messages, and track unread inquiries.
- CRM-style inbox with filters, tagging, status tracking, and admin response history for each message.
- Admin tools to edit the About page copy and contact details that surface throughout the site.
- User directory view with per-account activation toggles and admin privilege controls.
- Contact form available to authenticated users with message history stored for the admin.
- Modern UI with minimalist palette, smooth hover states, and mobile-friendly navigation.

## Getting Started

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment (optional)

Create a `.env` file to override defaults:

```
SECRET_KEY=change-me
DATABASE_URL=sqlite:///site.db
```

### 3. Initialize the database

The models are created automatically when the app starts, but you can pre-create the schema with:

```bash
flask --app app shell -c "from app import db; db.create_all()"
```

> **Upgrading from a previous schema?**
> The message and user tables now include additional columns. If you are running an older `site.db`, delete it before recreating the schema or migrate the tables manually to avoid `OperationalError` issues.

### 4. Create an admin user

```bash
flask --app app create-admin
```

Follow the prompts to define the admin email, name, and password. This account has access to all administrative routes.

### 5. Run the development server

```bash
flask --app app run --debug
```

Navigate to `http://127.0.0.1:5000/` to explore the site.

## Usage Notes

- Regular visitors can browse the public pages. Registering creates a standard user account that can submit contact messages.
- Only the admin role can manage projects and review messages. Accessing `/admin` routes without admin privileges returns HTTP 403.
- The admin inbox supports filtering by status, category, date range, or keyword and records staff responses for future reference.
- Update the studio biography and contact information from **Admin → Edit About Page**; the changes flow to the public About page, contact page, and footer.
- Manage user permissions from **Admin → User Management** to grant admin access or deactivate accounts.
- Uploaded project images are stored under `static/uploads`. The `.gitignore` keeps this folder out of version control while preserving the directory.
- To update or remove project images, edit the project in the admin panel and use the removal checkboxes or upload new assets via drag & drop.

## Tech Stack

- [Flask](https://flask.palletsprojects.com/) for routing and templating
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) for ORM support
- [Flask-Login](https://flask-login.readthedocs.io/) for session management
- [Flask-WTF](https://flask-wtf.readthedocs.io/) for secure forms and validation

## Security Considerations

- Passwords are hashed using Werkzeug’s recommended algorithms.
- Authentication checks gate both contact form submissions and admin panel access.
- Uploaded filenames are sanitized and randomized to mitigate collisions.
- Sensitive configuration values (secret key, database URL) can be provided via environment variables or a `.env` file.
