import os
import re
import secrets
import shutil
import sqlite3
import hashlib

import click
from datetime import UTC, datetime, timedelta
from functools import wraps
from hmac import compare_digest

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from dotenv import load_dotenv

from email_service import (
    EmailConfigurationError,
    EmailDeliveryError,
    send_admin_password_changed_email,
    send_admin_password_reset_email,
    send_contact_email,
)

load_dotenv()

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.environ.get(
    "TESTA_DATABASE_PATH",
    os.path.join(BASE_DIR, "testa_roofing.db"),
)

# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app.config["SECRET_KEY"] = os.environ.get(
    "TESTA_SECRET_KEY",
    "local-development-key-change-before-deployment",
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "TESTA_ENV",
    "development",
).lower() == "production"
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

PROJECT_UPLOAD_ROOT = os.path.join(
    BASE_DIR,
    "static",
    "uploads",
    "projects",
)
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
HOMEPAGE_HERO_UPLOAD_ROOT = os.path.join(
    BASE_DIR,
    "static",
    "uploads",
    "homepage_hero",
)
MAX_HOMEPAGE_HERO_SLIDES = 5
LEARNING_UPLOAD_ROOT = os.path.join(
    BASE_DIR,
    "static",
    "uploads",
    "learning_center",
)


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def ensure_database_schema():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Create admin_users first because several other tables reference it.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'editor',
            is_active INTEGER NOT NULL DEFAULT 1,
            email_verified INTEGER NOT NULL DEFAULT 1,
            last_login TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by INTEGER,
            FOREIGN KEY (created_by)
                REFERENCES admin_users (id)
                ON DELETE SET NULL,
            CHECK (role IN ('owner', 'administrator', 'editor'))
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_password_reset_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            normalized_email TEXT NOT NULL,
            ip_address TEXT,
            requested_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_password_reset_requests_email
        ON admin_password_reset_requests (
            normalized_email,
            requested_at
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_password_reset_requests_ip
        ON admin_password_reset_requests (
            ip_address,
            requested_at
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            invalidated_at TEXT,
            FOREIGN KEY (admin_user_id)
                REFERENCES admin_users (id)
                ON DELETE CASCADE
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_password_reset_tokens_user
        ON admin_password_reset_tokens (
            admin_user_id,
            created_at
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            project_type TEXT,
            location_city TEXT,
            location_state TEXT,
            roofing_system TEXT,
            manufacturer TEXT,
            panel_profile TEXT,
            color TEXT,
            scope TEXT,
            completion_date TEXT,
            short_description TEXT,
            full_description TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            is_featured INTEGER NOT NULL DEFAULT 0,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            published_at TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS project_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            alt_text TEXT,
            caption TEXT,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_cover INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (project_id)
                REFERENCES projects (id)
                ON DELETE CASCADE
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS homepage_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            hero_caption TEXT,
            updated_at TEXT NOT NULL,
            updated_by INTEGER,
            FOREIGN KEY (updated_by)
                REFERENCES admin_users (id)
                ON DELETE SET NULL
        )
        """
    )

    cursor.execute(
        """
        INSERT OR IGNORE INTO homepage_settings (
            id,
            hero_caption,
            updated_at
        )
        VALUES (1, '', ?)
        """,
        (datetime.now(UTC).isoformat(timespec="seconds"),),
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS homepage_hero_slides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            alt_text TEXT,
            caption TEXT,
            project_title TEXT,
            location TEXT,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            is_builtin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by INTEGER,
            updated_by INTEGER,
            FOREIGN KEY (created_by)
                REFERENCES admin_users (id)
                ON DELETE SET NULL,
            FOREIGN KEY (updated_by)
                REFERENCES admin_users (id)
                ON DELETE SET NULL
        )
        """
    )

    hero_slide_columns = {
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(homepage_hero_slides)"
        ).fetchall()
    }

    if "project_title" not in hero_slide_columns:
        cursor.execute(
            """
            ALTER TABLE homepage_hero_slides
            ADD COLUMN project_title TEXT
            """
        )

    if "location" not in hero_slide_columns:
        cursor.execute(
            """
            ALTER TABLE homepage_hero_slides
            ADD COLUMN location TEXT
            """
        )

    # Preserve existing captions while moving to separate fields.
    existing_slides = cursor.execute(
        """
        SELECT id, caption, project_title, location
        FROM homepage_hero_slides
        """
    ).fetchall()

    for existing_slide in existing_slides:
        if existing_slide["project_title"] or existing_slide["location"]:
            continue

        caption = (existing_slide["caption"] or "").strip()

        if not caption:
            continue

        parts = re.split(r"\s+[—–-]\s+", caption, maxsplit=1)
        project_title = parts[0].strip()
        location = parts[1].strip() if len(parts) == 2 else ""

        cursor.execute(
            """
            UPDATE homepage_hero_slides
            SET project_title = ?, location = ?
            WHERE id = ?
            """,
            (
                project_title,
                location,
                existing_slide["id"],
            ),
        )

    hero_slide_count = cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM homepage_hero_slides
        """
    ).fetchone()[0]

    if hero_slide_count == 0:
        existing_caption = cursor.execute(
            """
            SELECT hero_caption
            FROM homepage_settings
            WHERE id = 1
            """
        ).fetchone()

        initial_caption = existing_caption[0] if existing_caption else ""
        now = datetime.now(UTC).isoformat(timespec="seconds")

        cursor.execute(
            """
            INSERT INTO homepage_hero_slides (
                filename,
                alt_text,
                caption,
                display_order,
                is_active,
                is_builtin,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, 0, 1, 1, ?, ?)
            """,
            (
                "img/website_cover.jpg",
                "Completed roofing project by Testa Roofing",
                initial_caption,
                now,
                now,
            ),
        )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS site_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_name TEXT NOT NULL DEFAULT 'Testa Roofing',
            legal_name TEXT NOT NULL DEFAULT 'Absolute Roof Solutions',
            phone_display TEXT NOT NULL DEFAULT '(330) 726-6484',
            phone_link TEXT NOT NULL DEFAULT '+13307266484',
            public_email TEXT NOT NULL DEFAULT 'info@testaroofing.com',
            address_line_1 TEXT,
            address_line_2 TEXT,
            service_area_summary TEXT NOT NULL
                DEFAULT 'Northeast Ohio & Western Pennsylvania',
            facebook_url TEXT,
            instagram_url TEXT,
            linkedin_url TEXT,
            youtube_url TEXT,
            updated_at TEXT NOT NULL,
            updated_by INTEGER,
            FOREIGN KEY (updated_by)
                REFERENCES admin_users (id)
                ON DELETE SET NULL
        )
        """
    )

    cursor.execute(
        """
        INSERT OR IGNORE INTO site_settings (
            id,
            public_name,
            legal_name,
            phone_display,
            phone_link,
            public_email,
            service_area_summary,
            updated_at
        )
        VALUES (
            1,
            'Testa Roofing',
            'Absolute Roof Solutions',
            '(330) 726-6484',
            '+13307266484',
            'info@testaroofing.com',
            'Northeast Ohio & Western Pennsylvania',
            ?
        )
        """,
        (datetime.now(UTC).isoformat(timespec="seconds"),),
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER,
            action TEXT NOT NULL,
            category TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            description TEXT NOT NULL,
            metadata_json TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (admin_user_id)
                REFERENCES admin_users (id)
                ON DELETE SET NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at
        ON admin_audit_log (created_at DESC)
        """
    )

    connection.commit()
    connection.close()

# =========================================================
# ADMIN AUTHENTICATION
# =========================================================

VALID_ADMIN_ROLES = {"owner", "administrator", "editor"}


def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_email(value):
    return value.strip().lower()


def get_current_admin_user():
    admin_user_id = session.get("admin_user_id")

    if not admin_user_id:
        return None

    connection = get_db_connection()
    admin_user = connection.execute(
        """
        SELECT id, first_name, last_name, email, role, is_active
        FROM admin_users
        WHERE id = ?
        """,
        (admin_user_id,),
    ).fetchone()
    connection.close()

    return admin_user

ADMIN_PASSWORD_MIN_LENGTH = 16
PASSWORD_RESET_TOKEN_MINUTES = 15
PASSWORD_RESET_WINDOW_MINUTES = 30
PASSWORD_RESET_MAX_REQUESTS = 4


def validate_admin_password(password):
    if not password:
        return "A password is required."

    if len(password) < ADMIN_PASSWORD_MIN_LENGTH:
        return (
            f"Your password must contain at least "
            f"{ADMIN_PASSWORD_MIN_LENGTH} characters."
        )

    if len(password) > 128:
        return "Your password cannot exceed 128 characters."

    return None


def hash_password_reset_token(token):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def get_request_ip_address():
    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    ).strip()

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or ""


def password_reset_request_allowed(
    connection,
    normalized_email,
    ip_address,
):
    cutoff = (
        datetime.now(UTC)
        - timedelta(minutes=PASSWORD_RESET_WINDOW_MINUTES)
    ).isoformat(timespec="seconds")

    email_request_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM admin_password_reset_requests
        WHERE normalized_email = ?
          AND requested_at >= ?
        """,
        (
            normalized_email,
            cutoff,
        ),
    ).fetchone()[0]

    ip_request_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM admin_password_reset_requests
        WHERE ip_address = ?
          AND requested_at >= ?
        """,
        (
            ip_address,
            cutoff,
        ),
    ).fetchone()[0]

    return (
        email_request_count < PASSWORD_RESET_MAX_REQUESTS
        and ip_request_count < PASSWORD_RESET_MAX_REQUESTS
    )


def record_password_reset_request(
    connection,
    normalized_email,
    ip_address,
):
    connection.execute(
        """
        INSERT INTO admin_password_reset_requests (
            normalized_email,
            ip_address,
            requested_at
        )
        VALUES (?, ?, ?)
        """,
        (
            normalized_email,
            ip_address,
            current_timestamp(),
        ),
    )


def create_admin_password_reset_token(
    connection,
    admin_user_id,
):
    now = datetime.now(UTC)
    expires_at = now + timedelta(
        minutes=PASSWORD_RESET_TOKEN_MINUTES
    )

    # Only the newest reset link remains valid.
    connection.execute(
        """
        UPDATE admin_password_reset_tokens
        SET invalidated_at = ?
        WHERE admin_user_id = ?
          AND used_at IS NULL
          AND invalidated_at IS NULL
        """,
        (
            now.isoformat(timespec="seconds"),
            admin_user_id,
        ),
    )

    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_password_reset_token(raw_token)

    connection.execute(
        """
        INSERT INTO admin_password_reset_tokens (
            admin_user_id,
            token_hash,
            created_at,
            expires_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            admin_user_id,
            token_hash,
            now.isoformat(timespec="seconds"),
            expires_at.isoformat(timespec="seconds"),
        ),
    )

    return raw_token


def get_valid_admin_password_reset(
    connection,
    raw_token,
):
    if not raw_token:
        return None

    token_hash = hash_password_reset_token(raw_token)

    reset_record = connection.execute(
        """
        SELECT
            admin_password_reset_tokens.*,
            admin_users.email,
            admin_users.first_name,
            admin_users.last_name,
            admin_users.is_active
        FROM admin_password_reset_tokens
        JOIN admin_users
            ON admin_users.id =
               admin_password_reset_tokens.admin_user_id
        WHERE admin_password_reset_tokens.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if reset_record is None:
        return None

    if reset_record["used_at"] is not None:
        return None

    if reset_record["invalidated_at"] is not None:
        return None

    if not reset_record["is_active"]:
        return None

    expires_at = datetime.fromisoformat(
        reset_record["expires_at"]
    )

    if expires_at <= datetime.now(UTC):
        return None

    return reset_record

def write_audit_log(
    action,
    category,
    description,
    admin_user_id=None,
    entity_type=None,
    entity_id=None,
    metadata_json=None,
):
    if admin_user_id is None:
        admin_user_id = session.get("admin_user_id")

    connection = get_db_connection()
    connection.execute(
        """
        INSERT INTO admin_audit_log (
            admin_user_id,
            action,
            category,
            entity_type,
            entity_id,
            description,
            metadata_json,
            ip_address,
            user_agent,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            admin_user_id,
            action,
            category,
            entity_type,
            entity_id,
            description,
            metadata_json,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", "")[:500],
            current_timestamp(),
        ),
    )
    connection.commit()
    connection.close()


def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        admin_user = get_current_admin_user()

        if admin_user is None or not admin_user["is_active"]:
            session.clear()
            flash("Please sign in to access the website editor.", "error")
            return redirect(url_for("admin_login", next=request.path))

        return view_function(*args, **kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    invalid_roles = set(allowed_roles) - VALID_ADMIN_ROLES

    if invalid_roles:
        raise ValueError(f"Unknown administrator roles: {invalid_roles}")

    def decorator(view_function):
        @wraps(view_function)
        @admin_required
        def wrapped_view(*args, **kwargs):
            admin_user = get_current_admin_user()

            if admin_user["role"] not in allowed_roles:
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


def validate_csrf_token():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    if not submitted_token or not session_token:
        abort(400)

    if not compare_digest(submitted_token, session_token):
        abort(400)


@app.context_processor
def inject_admin_context():
    return {
        "csrf_token": get_csrf_token,
        "current_admin_user": get_current_admin_user(),
    }


def is_safe_admin_redirect(target):
    return bool(target and target.startswith("/admin/") and not target.startswith("//"))


@app.cli.command("create-owner")
@click.option("--first-name", prompt="First name")
@click.option("--last-name", prompt="Last name")
@click.option("--email", prompt="Email address")
@click.password_option(confirmation_prompt=True)
def create_owner_command(first_name, last_name, email, password):
    """Create the first owner account or another approved owner."""
    first_name = first_name.strip()
    last_name = last_name.strip()
    email = normalize_email(email)

    if not first_name or not last_name:
        raise click.ClickException("First and last name are required.")

    if "@" not in email:
        raise click.ClickException("Enter a valid email address.")

    if len(password) < 12:
        raise click.ClickException(
            "The password must contain at least 12 characters."
        )

    connection = get_db_connection()
    existing_user = connection.execute(
        "SELECT id FROM admin_users WHERE email = ?",
        (email,),
    ).fetchone()

    if existing_user:
        connection.close()
        raise click.ClickException(
            "An administrator with that email address already exists."
        )

    now = current_timestamp()
    cursor = connection.execute(
        """
        INSERT INTO admin_users (
            first_name,
            last_name,
            email,
            password_hash,
            role,
            is_active,
            email_verified,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, 'owner', 1, 1, ?, ?)
        """,
        (
            first_name,
            last_name,
            email,
            generate_password_hash(password),
            now,
            now,
        ),
    )
    owner_id = cursor.lastrowid

    connection.execute(
        """
        INSERT INTO admin_audit_log (
            admin_user_id,
            action,
            category,
            entity_type,
            entity_id,
            description,
            created_at
        )
        VALUES (?, 'owner_created', 'security', 'admin_user', ?, ?, ?)
        """,
        (
            owner_id,
            owner_id,
            f"Initial owner account created for {email}.",
            now,
        ),
    )

    connection.commit()
    connection.close()

    click.echo(f"Owner account created for {email}.")


# =========================================================
# PROJECT HELPERS
# =========================================================

def create_slug(value):
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    value = re.sub(r"[\s_-]+", "-", value)
    return value.strip("-")


def create_unique_project_slug(connection, title, project_id=None):
    base_slug = create_slug(title)

    if not base_slug:
        base_slug = "project"

    slug = base_slug
    suffix = 2

    while True:
        if project_id is None:
            existing_project = connection.execute(
                """
                SELECT id
                FROM projects
                WHERE slug = ?
                """,
                (slug,),
            ).fetchone()
        else:
            existing_project = connection.execute(
                """
                SELECT id
                FROM projects
                WHERE slug = ?
                  AND id != ?
                """,
                (slug, project_id),
            ).fetchone()

        if existing_project is None:
            return slug

        slug = f"{base_slug}-{suffix}"
        suffix += 1


def normalize_project_status(value):
    if value == "published":
        return "published"

    return "draft"


def allowed_image_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def get_project_upload_directory(project_id):
    return os.path.join(PROJECT_UPLOAD_ROOT, str(project_id))


def get_project_images(connection, project_id):
    return connection.execute(
        """
        SELECT *
        FROM project_images
        WHERE project_id = ?
        ORDER BY display_order ASC, id ASC
        """,
        (project_id,),
    ).fetchall()


def normalize_project_image_order(connection, project_id):
    images = connection.execute(
        """
        SELECT id
        FROM project_images
        WHERE project_id = ?
        ORDER BY display_order ASC, id ASC
        """,
        (project_id,),
    ).fetchall()

    for position, image in enumerate(images):
        connection.execute(
            """
            UPDATE project_images
            SET display_order = ?
            WHERE id = ?
              AND project_id = ?
            """,
            (position, image["id"], project_id),
        )


def get_project_form_data():
    return {
        "title": request.form.get("title", "").strip(),
        "project_type": request.form.get("project_type", "").strip(),
        "location_city": request.form.get("location_city", "").strip(),
        "location_state": request.form.get("location_state", "").strip(),
        "roofing_system": request.form.get("roofing_system", "").strip(),
        "manufacturer": request.form.get("manufacturer", "").strip(),
        "panel_profile": request.form.get("panel_profile", "").strip(),
        "color": request.form.get("color", "").strip(),
        "scope": request.form.get("scope", "").strip(),
        "completion_date": request.form.get("completion_date", "").strip(),
        "short_description": request.form.get(
            "short_description",
            "",
        ).strip(),
        "full_description": request.form.get(
            "full_description",
            "",
        ).strip(),
        "status": normalize_project_status(
            request.form.get("status", "draft")
        ),
        "is_featured": 1 if request.form.get("is_featured") else 0,
        "display_order": request.form.get("display_order", "0").strip(),
    }


def save_homepage_hero_image(uploaded_file):
    original_name = secure_filename(uploaded_file.filename or "")

    if not original_name or not allowed_image_file(original_name):
        return None

    extension = original_name.rsplit(".", 1)[1].lower()
    unique_name = (
        f"{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}_"
        f"{secrets.token_hex(6)}.{extension}"
    )

    os.makedirs(HOMEPAGE_HERO_UPLOAD_ROOT, exist_ok=True)
    uploaded_file.save(os.path.join(HOMEPAGE_HERO_UPLOAD_ROOT, unique_name))

    return f"uploads/homepage_hero/{unique_name}"


def normalize_hero_slide_order(connection):
    slides = connection.execute(
        """
        SELECT id
        FROM homepage_hero_slides
        ORDER BY display_order ASC, id ASC
        """
    ).fetchall()

    for position, slide in enumerate(slides):
        connection.execute(
            "UPDATE homepage_hero_slides SET display_order = ? WHERE id = ?",
            (position, slide["id"]),
        )


@app.context_processor
def inject_site_settings():
    connection = get_db_connection()
    settings = connection.execute(
        "SELECT * FROM site_settings WHERE id = 1"
    ).fetchone()
    connection.close()
    return {"site_settings": settings}


# =========================================================
# PUBLIC ROUTES
# =========================================================

@app.route("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.route("/sitemap.xml")
def sitemap():
    connection = get_db_connection()

    published_projects = connection.execute(
        """
        SELECT slug, updated_at
        FROM projects
        WHERE status = 'published'
        ORDER BY updated_at DESC
        """
    ).fetchall()

    published_articles = connection.execute(
        """
        SELECT slug, updated_at
        FROM learning_articles
        WHERE status = 'published'
        ORDER BY updated_at DESC
        """
    ).fetchall()

    connection.close()

    static_pages = [
        url_for("home", _external=True),
        url_for("roof_repair", _external=True),
        url_for("roof_restoration", _external=True),
        url_for("roof_replacement", _external=True),
        url_for("about", _external=True),
        url_for("service_areas", _external=True),
        url_for("contact", _external=True),
        url_for("public_projects", _external=True),
        url_for("public_learning_center", _external=True),
    ]

    project_pages = [
        {
            "loc": url_for(
                "public_project_detail",
                slug=project["slug"],
                _external=True,
            ),
            "lastmod": project["updated_at"][:10]
            if project["updated_at"]
            else None,
        }
        for project in published_projects
    ]

    article_pages = [
        {
            "loc": url_for(
                "public_learning_article",
                slug=article["slug"],
                _external=True,
            ),
            "lastmod": article["updated_at"][:10]
            if article["updated_at"]
            else None,
        }
        for article in published_articles
    ]

    xml = render_template(
        "sitemap.xml",
        static_pages=static_pages,
        project_pages=project_pages,
        article_pages=article_pages,
    )

    return Response(xml, mimetype="application/xml")

@app.route("/")
def home():
    connection = get_db_connection()

    hero_slides = connection.execute(
        """
        SELECT *
        FROM homepage_hero_slides
        WHERE is_active = 1
        ORDER BY display_order ASC, id ASC
        LIMIT ?
        """,
        (MAX_HOMEPAGE_HERO_SLIDES,),
    ).fetchall()

    featured_projects = connection.execute(
        """
        SELECT
            projects.*,
            project_images.filename AS cover_filename,
            project_images.alt_text AS cover_alt_text
        FROM projects
        LEFT JOIN project_images
            ON project_images.project_id = projects.id
           AND project_images.is_cover = 1
        WHERE projects.status = 'published'
        ORDER BY
            projects.is_featured DESC,
            projects.display_order ASC,
            projects.published_at DESC,
            projects.created_at DESC
        LIMIT 3
        """
    ).fetchall()

    latest_articles = connection.execute(
        """
        SELECT id, title, slug, summary, article_type, published_at
        FROM learning_articles
        WHERE status = 'published'
        ORDER BY
            is_featured DESC,
            published_at DESC,
            created_at DESC
        LIMIT 3
        """
    ).fetchall()

    connection.close()

    return render_template(
        "index.html",
        featured_projects=featured_projects,
        hero_slides=hero_slides,
        latest_articles=latest_articles,
    )


@app.route("/roof-repair")
def roof_repair():
    return render_template("repair.html")

@app.route("/roof-restoration")
def roof_restoration():
    return render_template("restoration.html")

@app.route("/roof-replacement")
def roof_replacement():
    return render_template("replacement.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/service-areas")
def service_areas():
    return render_template("service_areas.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        company = request.form.get("company", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        property_address = request.form.get("property_address", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        building_type = request.form.get("building_type", "").strip()
        service_needed = request.form.get("service_needed", "").strip()
        message = request.form.get("message", "").strip()
        consent = request.form.get("consent", "").strip()

        required_fields_complete = all([
            name,
            phone,
            email,
            property_address,
            city,
            state,
            message,
        ])

        valid_state = state in {"OH", "PA"}

        if (
            not required_fields_complete
            or not valid_state
            or consent != "yes"
        ):
            flash("Please complete all required fields.", "error")
            return render_template(
                "contact.html",
                form_data=request.form,
            )

        try:
            send_contact_email(request.form)

        except (EmailConfigurationError, EmailDeliveryError):
            app.logger.exception(
                "The Request an Evaluation email could not be sent."
            )

            flash(
                "We could not send your request right now. "
                "Please call us or try again shortly.",
                "error",
            )

            return render_template(
                "contact.html",
                form_data=request.form,
            )

        return redirect(url_for("request_received"))

    return render_template("contact.html", form_data={})

@app.route("/request-received")
def request_received():
    return render_template("request_received.html")

@app.route("/projects")
def public_projects():
    connection = get_db_connection()

    projects = connection.execute(
        """
        SELECT
            projects.*,
            project_images.filename AS cover_filename,
            project_images.alt_text AS cover_alt_text
        FROM projects
        LEFT JOIN project_images
            ON project_images.project_id = projects.id
           AND project_images.is_cover = 1
        WHERE projects.status = 'published'
        ORDER BY
            projects.is_featured DESC,
            projects.display_order ASC,
            projects.published_at DESC,
            projects.created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "projects.html",
        projects=projects,
    )


@app.route("/projects/<slug>")
def public_project_detail(slug):
    connection = get_db_connection()

    project = connection.execute(
        """
        SELECT *
        FROM projects
        WHERE slug = ?
          AND status = 'published'
        """,
        (slug,),
    ).fetchone()

    if project is None:
        connection.close()
        abort(404)

    project_images = get_project_images(connection, project["id"])
    connection.close()

    return render_template(
        "project_detail.html",
        project=project,
        project_images=project_images,
    )


# =========================================================
# PUBLIC LEARNING CENTER
# =========================================================

def learning_article_select_sql():
    return """
        SELECT
            a.*,
            (
                SELECT GROUP_CONCAT(topic_name, '||')
                FROM (
                    SELECT t.name AS topic_name
                    FROM learning_article_topics lat
                    JOIN learning_topics t ON t.id = lat.topic_id
                    WHERE lat.article_id = a.id
                    ORDER BY t.display_order, t.name
                )
            ) AS topic_names
        FROM learning_articles a
    """


@app.route("/learning-center")
def public_learning_center():
    connection = get_db_connection()

    search_query = request.args.get("q", "").strip()
    selected_topic_slugs = [
        slug.strip()
        for slug in request.args.getlist("topic")
        if slug.strip()
    ]

    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1

    per_page = 9
    filters = ["a.status = 'published'"]
    parameters = []

    if search_query:
        search_value = f"%{search_query}%"
        filters.append(
            """
            (
                a.title LIKE ?
                OR a.summary LIKE ?
                OR a.body LIKE ?
                OR a.focus_keyword LIKE ?
            )
            """
        )
        parameters.extend([search_value] * 4)

    if selected_topic_slugs:
        placeholders = ", ".join("?" for _ in selected_topic_slugs)
        filters.append(
            f"""
            EXISTS (
                SELECT 1
                FROM learning_article_topics selected_lat
                JOIN learning_topics selected_topic
                    ON selected_topic.id = selected_lat.topic_id
                WHERE selected_lat.article_id = a.id
                  AND selected_topic.slug IN ({placeholders})
            )
            """
        )
        parameters.extend(selected_topic_slugs)

    where_sql = " AND ".join(filters)

    total_articles = connection.execute(
        f"SELECT COUNT(*) AS total FROM learning_articles a WHERE {where_sql}",
        parameters,
    ).fetchone()["total"]

    total_pages = max(1, (total_articles + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    articles = connection.execute(
        learning_article_select_sql()
        + f"""
        WHERE {where_sql}
        ORDER BY
            a.is_featured DESC,
            a.published_at DESC,
            a.created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*parameters, per_page, offset],
    ).fetchall()

    featured_article = connection.execute(
        learning_article_select_sql()
        + """
        WHERE a.status = 'published'
          AND a.is_featured = 1
        ORDER BY a.published_at DESC, a.created_at DESC
        LIMIT 1
        """
    ).fetchone()

    public_topics = connection.execute(
        """
        SELECT *
        FROM learning_topics
        WHERE is_active = 1
          AND show_as_public_filter = 1
        ORDER BY display_order, name
        """
    ).fetchall()

    connection.close()

    return render_template(
        "learning_center.html",
        articles=articles,
        featured_article=featured_article,
        public_topics=public_topics,
        search_query=search_query,
        selected_topic_slugs=selected_topic_slugs,
        total_articles=total_articles,
        page=page,
        total_pages=total_pages,
    )


@app.route("/learning-center/<slug>")
def public_learning_article(slug):
    connection = get_db_connection()

    article = connection.execute(
        """
        SELECT *
        FROM learning_articles
        WHERE slug = ?
          AND status = 'published'
        """,
        (slug,),
    ).fetchone()

    if article is None:
        connection.close()
        abort(404)

    topics = connection.execute(
        """
        SELECT t.*
        FROM learning_topics t
        JOIN learning_article_topics lat ON lat.topic_id = t.id
        WHERE lat.article_id = ?
        ORDER BY t.display_order, t.name
        """,
        (article["id"],),
    ).fetchall()

    related_articles = connection.execute(
        """
        SELECT DISTINCT
            related.id,
            related.title,
            related.slug,
            related.summary,
            related.featured_image_url,
            related.featured_image_alt_text,
            related.published_at
        FROM learning_articles related
        JOIN learning_article_topics related_lat
            ON related_lat.article_id = related.id
        WHERE related.status = 'published'
          AND related.id != ?
          AND related_lat.topic_id IN (
              SELECT topic_id
              FROM learning_article_topics
              WHERE article_id = ?
          )
        ORDER BY related.published_at DESC, related.created_at DESC
        LIMIT 3
        """,
        (article["id"], article["id"]),
    ).fetchall()

    connection.close()

    return render_template(
        "learning_article.html",
        article=article,
        topics=topics,
        related_articles=related_articles,
    )


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if get_current_admin_user() is not None:
        return redirect(url_for("admin_website_dashboard"))

    if request.method == "POST":
        validate_csrf_token()

        submitted_email = normalize_email(
            request.form.get("email", "")
        )
        submitted_password = request.form.get("password", "")

        connection = get_db_connection()
        admin_user = connection.execute(
            """
            SELECT *
            FROM admin_users
            WHERE email = ?
            """,
            (submitted_email,),
        ).fetchone()

        login_succeeded = bool(
            admin_user
            and admin_user["is_active"]
            and check_password_hash(
                admin_user["password_hash"],
                submitted_password,
            )
        )

        if login_succeeded:
            now = current_timestamp()
            connection.execute(
                """
                UPDATE admin_users
                SET last_login = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, admin_user["id"]),
            )
            connection.commit()
            connection.close()

            session.clear()
            session["admin_user_id"] = admin_user["id"]
            session["csrf_token"] = secrets.token_hex(32)

            write_audit_log(
                action="login_succeeded",
                category="security",
                description=f'{admin_user["email"]} signed in.',
                admin_user_id=admin_user["id"],
                entity_type="admin_user",
                entity_id=admin_user["id"],
            )

            flash("You are now signed in.", "success")

            next_page = request.args.get("next", "")
            if is_safe_admin_redirect(next_page):
                return redirect(next_page)

            return redirect(url_for("admin_website_dashboard"))

        connection.close()

        write_audit_log(
            action="login_failed",
            category="security",
            description=(
                "An unsuccessful sign-in attempt was made for "
                f"{submitted_email or 'a blank email address'}."
            ),
            admin_user_id=admin_user["id"] if admin_user else None,
            entity_type="admin_user" if admin_user else None,
            entity_id=admin_user["id"] if admin_user else None,
        )

        flash("The email address or password was incorrect.", "error")

    return render_template("admin_login.html")

@app.route(
    "/admin/forgot-password",
    methods=["GET", "POST"],
)
def admin_forgot_password():
    if get_current_admin_user() is not None:
        return redirect(
            url_for("admin_website_dashboard")
        )

    if request.method == "POST":
        validate_csrf_token()

        submitted_email = normalize_email(
            request.form.get("email", "")
        )

        ip_address = get_request_ip_address()

        connection = get_db_connection()

        allowed = password_reset_request_allowed(
            connection,
            submitted_email,
            ip_address,
        )

        record_password_reset_request(
            connection,
            submitted_email,
            ip_address,
        )

        admin_user = connection.execute(
            """
            SELECT *
            FROM admin_users
            WHERE email = ?
              AND is_active = 1
            """,
            (submitted_email,),
        ).fetchone()

        if allowed and admin_user is not None:
            raw_token = (
                create_admin_password_reset_token(
                    connection,
                    admin_user["id"],
                )
            )

            connection.commit()

            reset_url = url_for(
                "admin_reset_password",
                token=raw_token,
                _external=True,
                _scheme="https"
                if not app.debug
                else None,
            )

            try:
                send_admin_password_reset_email(
                    recipient_email=admin_user["email"],
                    first_name=admin_user["first_name"],
                    reset_url=reset_url,
                )

                write_audit_log(
                    action="password_reset_requested",
                    category="security",
                    description=(
                        "A password reset email "
                        f"was sent to {admin_user['email']}."
                    ),
                    admin_user_id=admin_user["id"],
                    entity_type="admin_user",
                    entity_id=admin_user["id"],
                )

            except (
                EmailConfigurationError,
                EmailDeliveryError,
            ):
                app.logger.exception(
                    "Unable to send administrator "
                    "password reset email."
                )

        else:
            connection.commit()

        connection.close()

        flash(
            (
                "If an active administrator account "
                "exists for that email address, a "
                "password reset link has been sent."
            ),
            "success",
        )

        return redirect(
            url_for("admin_forgot_password")
        )

    return render_template(
        "admin_forgot_password.html"
    )

@app.route(
    "/admin/reset-password/<token>",
    methods=["GET", "POST"],
)
def admin_reset_password(token):
    connection = get_db_connection()

    reset_record = get_valid_admin_password_reset(
        connection,
        token,
    )

    if reset_record is None:
        connection.close()

        flash(
            (
                "That password reset link is invalid "
                "or has expired. Please request a "
                "new password reset."
            ),
            "error",
        )

        return redirect(
            url_for("admin_forgot_password")
        )

    if request.method == "POST":
        validate_csrf_token()

        new_password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        password_error = validate_admin_password(
            new_password
        )

        if password_error:
            connection.close()

            flash(
                password_error,
                "error",
            )

            return render_template(
                "admin_reset_password.html",
                token=token,
            )

        if new_password != confirm_password:
            connection.close()

            flash(
                "The passwords did not match.",
                "error",
            )

            return render_template(
                "admin_reset_password.html",
                token=token,
            )

        now = current_timestamp()

        connection.execute(
            """
            UPDATE admin_users
            SET
                password_hash = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                generate_password_hash(
                    new_password
                ),
                now,
                reset_record["admin_user_id"],
            ),
        )

        connection.execute(
            """
            UPDATE admin_password_reset_tokens
            SET used_at = ?
            WHERE id = ?
            """,
            (
                now,
                reset_record["id"],
            ),
        )

        connection.execute(
            """
            UPDATE admin_password_reset_tokens
            SET invalidated_at = ?
            WHERE admin_user_id = ?
              AND id != ?
              AND used_at IS NULL
              AND invalidated_at IS NULL
            """,
            (
                now,
                reset_record["admin_user_id"],
                reset_record["id"],
            ),
        )

        connection.commit()
        connection.close()

        session.clear()

        write_audit_log(
            action="password_reset_completed",
            category="security",
            description=(
                f'{reset_record["email"]} '
                "reset their administrator password."
            ),
            admin_user_id=reset_record[
                "admin_user_id"
            ],
            entity_type="admin_user",
            entity_id=reset_record[
                "admin_user_id"
            ],
        )

        try:
            send_admin_password_changed_email(
                recipient_email=reset_record["email"],
                first_name=reset_record["first_name"],
            )

        except (
            EmailConfigurationError,
            EmailDeliveryError,
        ):
            app.logger.exception(
                "Unable to send administrator "
                "password-change confirmation email."
            )

        flash(
            (
                "Your password has been changed. "
                "You can now sign in."
            ),
            "success",
        )

        return redirect(
            url_for("admin_login")
        )

    connection.close()

    return render_template(
        "admin_reset_password.html",
        token=token,
    )

@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    validate_csrf_token()

    admin_user = get_current_admin_user()
    write_audit_log(
        action="logout",
        category="security",
        description=f'{admin_user["email"]} signed out.',
        admin_user_id=admin_user["id"],
        entity_type="admin_user",
        entity_id=admin_user["id"],
    )

    session.clear()
    flash("You have been signed out.", "success")

    return redirect(url_for("admin_login"))


# =========================================================
# WEBSITE ADMINISTRATION
# =========================================================

@app.route("/admin/website")
@admin_required
def admin_website_dashboard():
    connection = get_db_connection()

    project_count = connection.execute(
        "SELECT COUNT(*) AS total FROM projects"
    ).fetchone()["total"]

    published_count = connection.execute(
        "SELECT COUNT(*) AS total FROM projects WHERE status = 'published'"
    ).fetchone()["total"]

    draft_count = connection.execute(
        "SELECT COUNT(*) AS total FROM projects WHERE status = 'draft'"
    ).fetchone()["total"]

    featured_count = connection.execute(
        "SELECT COUNT(*) AS total FROM projects WHERE is_featured = 1"
    ).fetchone()["total"]

    featured_project = connection.execute(
        """
        SELECT id, title
        FROM projects
        WHERE is_featured = 1
        LIMIT 1
        """
    ).fetchone()

    hero_slides = connection.execute(
        """
        SELECT *
        FROM homepage_hero_slides
        ORDER BY display_order ASC, id ASC
        """
    ).fetchall()

    active_hero_count = sum(
        1 for slide in hero_slides if slide["is_active"]
    )

    site_settings = connection.execute(
        """
        SELECT
            site_settings.*,
            admin_users.first_name AS updated_by_first_name,
            admin_users.last_name AS updated_by_last_name
        FROM site_settings
        LEFT JOIN admin_users
            ON admin_users.id = site_settings.updated_by
        WHERE site_settings.id = 1
        """
    ).fetchone()

    latest_project_update = connection.execute(
        "SELECT MAX(updated_at) AS updated_at FROM projects"
    ).fetchone()["updated_at"]

    latest_hero_update = connection.execute(
        "SELECT MAX(updated_at) AS updated_at FROM homepage_hero_slides"
    ).fetchone()["updated_at"]

    connection.close()

    update_candidates = [
        site_settings["updated_at"] if site_settings else None,
        latest_project_update,
        latest_hero_update,
    ]
    update_candidates = [value for value in update_candidates if value]
    website_last_updated = max(update_candidates) if update_candidates else None

    company_information_complete = bool(
        site_settings
        and site_settings["public_name"]
        and site_settings["legal_name"]
        and site_settings["service_area_summary"]
    )
    contact_information_complete = bool(
        site_settings
        and site_settings["phone_display"]
        and site_settings["phone_link"]
        and site_settings["public_email"]
    )
    homepage_ready = bool(active_hero_count and contact_information_complete)
    projects_enabled = bool(published_count)

    social_connections = {
        "Facebook": bool(site_settings and site_settings["facebook_url"]),
        "Instagram": bool(site_settings and site_settings["instagram_url"]),
        "LinkedIn": bool(site_settings and site_settings["linkedin_url"]),
        "YouTube": bool(site_settings and site_settings["youtube_url"]),
    }

    return render_template(
        "admin_website.html",
        project_count=project_count,
        published_count=published_count,
        draft_count=draft_count,
        featured_count=featured_count,
        featured_project=featured_project,
        hero_slides=hero_slides,
        active_hero_count=active_hero_count,
        max_hero_slides=MAX_HOMEPAGE_HERO_SLIDES,
        site_settings=site_settings,
        social_connections=social_connections,
        company_information_complete=company_information_complete,
        contact_information_complete=contact_information_complete,
        homepage_ready=homepage_ready,
        projects_enabled=projects_enabled,
        website_last_updated=website_last_updated,
    )


@app.route("/admin/website/company-settings", methods=["POST"])
@admin_required
def admin_company_settings_update():
    validate_csrf_token()

    public_name = request.form.get("public_name", "").strip()
    legal_name = request.form.get("legal_name", "").strip()
    phone_display = request.form.get("phone_display", "").strip()
    phone_link = request.form.get("phone_link", "").strip()
    public_email = request.form.get("public_email", "").strip()
    address_line_1 = request.form.get("address_line_1", "").strip()
    address_line_2 = request.form.get("address_line_2", "").strip()
    service_area_summary = request.form.get("service_area_summary", "").strip()
    facebook_url = request.form.get("facebook_url", "").strip()
    instagram_url = request.form.get("instagram_url", "").strip()
    linkedin_url = request.form.get("linkedin_url", "").strip()
    youtube_url = request.form.get("youtube_url", "").strip()

    if not public_name or not legal_name or not phone_display or not phone_link or not public_email:
        flash("Company name, legal name, phone, phone link, and email are required.", "error")
        return redirect(url_for("admin_website_dashboard") + "#company-information")

    current_admin = get_current_admin_user()
    now = current_timestamp()
    connection = get_db_connection()
    connection.execute(
        """
        UPDATE site_settings
        SET public_name = ?, legal_name = ?, phone_display = ?,
            phone_link = ?, public_email = ?, address_line_1 = ?,
            address_line_2 = ?, service_area_summary = ?,
            facebook_url = ?, instagram_url = ?, linkedin_url = ?,
            youtube_url = ?, updated_at = ?, updated_by = ?
        WHERE id = 1
        """,
        (
            public_name, legal_name, phone_display, phone_link, public_email,
            address_line_1, address_line_2, service_area_summary,
            facebook_url, instagram_url, linkedin_url, youtube_url,
            now, current_admin["id"] if current_admin else None,
        ),
    )
    connection.commit()
    connection.close()

    flash("Company and contact information updated.", "success")
    return redirect(url_for("admin_website_dashboard") + "#company-information")


@app.route("/admin/website/hero-slides/upload", methods=["POST"])
@admin_required
def admin_homepage_hero_slide_upload():
    validate_csrf_token()
    connection = get_db_connection()

    slide_count = connection.execute(
        "SELECT COUNT(*) AS total FROM homepage_hero_slides"
    ).fetchone()["total"]

    if slide_count >= MAX_HOMEPAGE_HERO_SLIDES:
        connection.close()
        flash(
            f"The homepage rotation can contain up to {MAX_HOMEPAGE_HERO_SLIDES} photos. "
            "Remove an older photo before adding another.",
            "error",
        )
        return redirect(url_for("admin_website_dashboard"))

    uploaded_file = request.files.get("hero_image")
    if uploaded_file is None or not uploaded_file.filename:
        connection.close()
        flash("Choose a photo to upload.", "error")
        return redirect(url_for("admin_website_dashboard"))

    stored_filename = save_homepage_hero_image(uploaded_file)
    if stored_filename is None:
        connection.close()
        flash("Use a JPG, JPEG, PNG, or WebP image.", "error")
        return redirect(url_for("admin_website_dashboard"))

    project_title = request.form.get("project_title", "").strip()
    location = request.form.get("location", "").strip()
    alt_text = request.form.get("alt_text", "").strip()

    if not project_title or not location:
        connection.close()
        file_path = os.path.join(BASE_DIR, "static", *stored_filename.split("/"))
        if os.path.isfile(file_path):
            os.remove(file_path)
        flash("Enter both a project title and a location.", "error")
        return redirect(url_for("admin_website_dashboard"))
    admin_user = get_current_admin_user()
    now = current_timestamp()

    next_order = connection.execute(
        "SELECT COALESCE(MAX(display_order), -1) + 1 AS next_order FROM homepage_hero_slides"
    ).fetchone()["next_order"]

    cursor = connection.execute(
        """
        INSERT INTO homepage_hero_slides (
            filename, alt_text, caption, project_title, location,
            display_order, is_active, is_builtin, created_at, updated_at,
            created_by, updated_by
        )
        VALUES (?, ?, '', ?, ?, ?, 1, 0, ?, ?, ?, ?)
        """,
        (
            stored_filename, alt_text, project_title, location, next_order,
            now, now, admin_user["id"], admin_user["id"],
        ),
    )
    slide_id = cursor.lastrowid
    connection.commit()
    connection.close()

    write_audit_log(
        action="homepage_hero_slide_added",
        category="website",
        description="Added a photo to the homepage hero rotation.",
        entity_type="homepage_hero_slide",
        entity_id=slide_id,
    )
    flash("Homepage hero photo added.", "success")
    return redirect(url_for("admin_website_dashboard"))


@app.route("/admin/website/hero-slides/<int:slide_id>/update", methods=["POST"])
@admin_required
def admin_homepage_hero_slide_update(slide_id):
    validate_csrf_token()
    connection = get_db_connection()
    slide = connection.execute(
        "SELECT * FROM homepage_hero_slides WHERE id = ?",
        (slide_id,),
    ).fetchone()

    if slide is None:
        connection.close()
        abort(404)

    project_title = request.form.get("project_title", "").strip()
    location = request.form.get("location", "").strip()
    alt_text = request.form.get("alt_text", "").strip()
    is_active = 1 if request.form.get("is_active") else 0

    if not project_title or not location:
        connection.close()
        flash("Enter both a project title and a location.", "error")
        return redirect(url_for("admin_website_dashboard"))

    active_count = connection.execute(
        "SELECT COUNT(*) AS total FROM homepage_hero_slides WHERE is_active = 1"
    ).fetchone()["total"]
    if slide["is_active"] and not is_active and active_count <= 1:
        connection.close()
        flash("At least one homepage hero photo must remain active.", "error")
        return redirect(url_for("admin_website_dashboard"))

    admin_user = get_current_admin_user()
    connection.execute(
        """
        UPDATE homepage_hero_slides
        SET project_title = ?, location = ?, caption = '', alt_text = ?,
            is_active = ?, updated_at = ?, updated_by = ?
        WHERE id = ?
        """,
        (
            project_title, location, alt_text, is_active, current_timestamp(),
            admin_user["id"], slide_id,
        ),
    )
    connection.commit()
    connection.close()

    flash("Hero photo details updated.", "success")
    return redirect(url_for("admin_website_dashboard"))


@app.route("/admin/website/hero-slides/<int:slide_id>/move/<direction>", methods=["POST"])
@admin_required
def admin_homepage_hero_slide_move(slide_id, direction):
    validate_csrf_token()
    if direction not in {"up", "down"}:
        abort(404)

    connection = get_db_connection()
    normalize_hero_slide_order(connection)
    slides = connection.execute(
        "SELECT id, display_order FROM homepage_hero_slides ORDER BY display_order ASC"
    ).fetchall()
    ids = [slide["id"] for slide in slides]

    if slide_id not in ids:
        connection.close()
        abort(404)

    current_index = ids.index(slide_id)
    target_index = current_index - 1 if direction == "up" else current_index + 1

    if 0 <= target_index < len(ids):
        current = slides[current_index]
        target = slides[target_index]
        connection.execute(
            "UPDATE homepage_hero_slides SET display_order = ? WHERE id = ?",
            (target["display_order"], current["id"]),
        )
        connection.execute(
            "UPDATE homepage_hero_slides SET display_order = ? WHERE id = ?",
            (current["display_order"], target["id"]),
        )
        connection.commit()

    connection.close()
    return redirect(url_for("admin_website_dashboard"))


@app.route("/admin/website/hero-slides/<int:slide_id>/delete", methods=["POST"])
@admin_required
def admin_homepage_hero_slide_delete(slide_id):
    validate_csrf_token()
    connection = get_db_connection()
    slide = connection.execute(
        "SELECT * FROM homepage_hero_slides WHERE id = ?",
        (slide_id,),
    ).fetchone()

    if slide is None:
        connection.close()
        abort(404)

    slide_count = connection.execute(
        "SELECT COUNT(*) AS total FROM homepage_hero_slides"
    ).fetchone()["total"]
    if slide_count <= 1:
        connection.close()
        flash("At least one homepage hero photo must remain.", "error")
        return redirect(url_for("admin_website_dashboard"))

    connection.execute("DELETE FROM homepage_hero_slides WHERE id = ?", (slide_id,))
    normalize_hero_slide_order(connection)
    connection.commit()
    connection.close()

    if not slide["is_builtin"] and slide["filename"].startswith("uploads/homepage_hero/"):
        file_path = os.path.join(BASE_DIR, "static", *slide["filename"].split("/"))
        if os.path.isfile(file_path):
            os.remove(file_path)

    write_audit_log(
        action="homepage_hero_slide_deleted",
        category="website",
        description="Removed a photo from the homepage hero rotation.",
        entity_type="homepage_hero_slide",
        entity_id=slide_id,
    )
    flash("Homepage hero photo removed.", "success")
    return redirect(url_for("admin_website_dashboard"))


@app.route("/admin/website/projects")
@admin_required
def admin_projects():
    connection = get_db_connection()

    projects = connection.execute(
        """
        SELECT *
        FROM projects
        ORDER BY
            is_featured DESC,
            display_order ASC,
            created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "admin_projects.html",
        projects=projects,
    )


@app.route(
    "/admin/website/projects/new",
    methods=["GET", "POST"],
)
@admin_required
def admin_project_new():
    if request.method == "POST":
        validate_csrf_token()
        project_data = get_project_form_data()

        if not project_data["title"]:
            flash("Project title is required.", "error")

            return render_template(
                "admin_project_form.html",
                project=None,
                form_data=project_data,
                page_heading="Add Project",
            )

        try:
            display_order = int(project_data["display_order"] or 0)
        except ValueError:
            display_order = 0

        connection = get_db_connection()
        slug = create_unique_project_slug(
            connection,
            project_data["title"],
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        published_at = None

        if project_data["status"] == "published":
            published_at = now

        if project_data["is_featured"]:
            connection.execute(
                """
                UPDATE projects
                SET is_featured = 0
                """
            )

        cursor = connection.execute(
            """
            INSERT INTO projects (
                title,
                slug,
                project_type,
                location_city,
                location_state,
                roofing_system,
                manufacturer,
                panel_profile,
                color,
                scope,
                completion_date,
                short_description,
                full_description,
                status,
                is_featured,
                display_order,
                created_at,
                updated_at,
                published_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_data["title"],
                slug,
                project_data["project_type"],
                project_data["location_city"],
                project_data["location_state"],
                project_data["roofing_system"],
                project_data["manufacturer"],
                project_data["panel_profile"],
                project_data["color"],
                project_data["scope"],
                project_data["completion_date"],
                project_data["short_description"],
                project_data["full_description"],
                project_data["status"],
                project_data["is_featured"],
                display_order,
                now,
                now,
                published_at,
            ),
        )

        project_id = cursor.lastrowid

        connection.commit()
        connection.close()

        flash("The project was created.", "success")

        return redirect(
            url_for(
                "admin_project_edit",
                project_id=project_id,
            )
        )

    return render_template(
        "admin_project_form.html",
        project=None,
        form_data=None,
        page_heading="Add Project",
    )


@app.route(
    "/admin/website/projects/<int:project_id>/edit",
    methods=["GET", "POST"],
)
@admin_required
def admin_project_edit(project_id):
    connection = get_db_connection()

    project = connection.execute(
        """
        SELECT *
        FROM projects
        WHERE id = ?
        """,
        (project_id,),
    ).fetchone()

    if project is None:
        connection.close()
        abort(404)

    project_images = get_project_images(connection, project_id)

    if request.method == "POST":
        validate_csrf_token()
        project_data = get_project_form_data()

        if not project_data["title"]:
            connection.close()

            flash("Project title is required.", "error")

            return render_template(
                "admin_project_form.html",
                project=project,
                form_data=project_data,
                page_heading="Edit Project",
                project_images=project_images,
            )

        try:
            display_order = int(project_data["display_order"] or 0)
        except ValueError:
            display_order = 0

        slug = create_unique_project_slug(
            connection,
            project_data["title"],
            project_id=project_id,
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        published_at = project["published_at"]

        if (
            project_data["status"] == "published"
            and not published_at
        ):
            published_at = now

        if project_data["status"] == "draft":
            published_at = None

        if project_data["is_featured"]:
            connection.execute(
                """
                UPDATE projects
                SET is_featured = 0
                WHERE id != ?
                """,
                (project_id,),
            )

        connection.execute(
            """
            UPDATE projects
            SET
                title = ?,
                slug = ?,
                project_type = ?,
                location_city = ?,
                location_state = ?,
                roofing_system = ?,
                manufacturer = ?,
                panel_profile = ?,
                color = ?,
                scope = ?,
                completion_date = ?,
                short_description = ?,
                full_description = ?,
                status = ?,
                is_featured = ?,
                display_order = ?,
                updated_at = ?,
                published_at = ?
            WHERE id = ?
            """,
            (
                project_data["title"],
                slug,
                project_data["project_type"],
                project_data["location_city"],
                project_data["location_state"],
                project_data["roofing_system"],
                project_data["manufacturer"],
                project_data["panel_profile"],
                project_data["color"],
                project_data["scope"],
                project_data["completion_date"],
                project_data["short_description"],
                project_data["full_description"],
                project_data["status"],
                project_data["is_featured"],
                display_order,
                now,
                published_at,
                project_id,
            ),
        )

        connection.commit()
        connection.close()

        flash("The project was updated.", "success")

        return redirect(
            url_for(
                "admin_project_edit",
                project_id=project_id,
            )
        )

    connection.close()

    return render_template(
        "admin_project_form.html",
        project=project,
        form_data=None,
        page_heading="Edit Project",
        project_images=project_images,
    )


@app.route(
    "/admin/website/projects/<int:project_id>/images/upload",
    methods=["POST"],
)
@admin_required
def admin_project_images_upload(project_id):
    validate_csrf_token()

    connection = get_db_connection()
    project = connection.execute(
        "SELECT id, title FROM projects WHERE id = ?",
        (project_id,),
    ).fetchone()

    if project is None:
        connection.close()
        abort(404)

    uploaded_files = request.files.getlist("project_images")
    uploaded_files = [file for file in uploaded_files if file and file.filename]

    if not uploaded_files:
        connection.close()
        flash("Choose at least one photo to upload.", "error")
        return redirect(url_for("admin_project_edit", project_id=project_id))

    invalid_files = [
        file.filename
        for file in uploaded_files
        if not allowed_image_file(file.filename)
    ]

    if invalid_files:
        connection.close()
        flash(
            "Only JPG, JPEG, PNG, and WebP images can be uploaded.",
            "error",
        )
        return redirect(url_for("admin_project_edit", project_id=project_id))

    upload_directory = get_project_upload_directory(project_id)
    os.makedirs(upload_directory, exist_ok=True)

    current_count = connection.execute(
        "SELECT COUNT(*) AS total FROM project_images WHERE project_id = ?",
        (project_id,),
    ).fetchone()["total"]

    highest_order = connection.execute(
        """
        SELECT COALESCE(MAX(display_order), -1) AS highest_order
        FROM project_images
        WHERE project_id = ?
        """,
        (project_id,),
    ).fetchone()["highest_order"]

    now = current_timestamp()
    uploaded_count = 0

    for index, uploaded_file in enumerate(uploaded_files, start=1):
        original_name = secure_filename(uploaded_file.filename)
        extension = original_name.rsplit(".", 1)[1].lower()
        stored_name = f"{secrets.token_hex(16)}.{extension}"
        absolute_path = os.path.join(upload_directory, stored_name)
        relative_path = f"uploads/projects/{project_id}/{stored_name}"

        uploaded_file.save(absolute_path)

        connection.execute(
            """
            INSERT INTO project_images (
                project_id,
                filename,
                alt_text,
                caption,
                display_order,
                is_cover,
                created_at
            )
            VALUES (?, ?, ?, '', ?, ?, ?)
            """,
            (
                project_id,
                relative_path,
                project["title"],
                highest_order + index,
                1 if current_count == 0 and uploaded_count == 0 else 0,
                now,
            ),
        )
        uploaded_count += 1

    connection.commit()
    connection.close()

    write_audit_log(
        action="project_images_uploaded",
        category="content",
        description=(
            f'{uploaded_count} photo(s) uploaded to "{project["title"]}".'
        ),
        entity_type="project",
        entity_id=project_id,
    )

    flash(f"{uploaded_count} project photo(s) uploaded.", "success")
    return redirect(url_for("admin_project_edit", project_id=project_id))



@app.route(
    "/admin/website/projects/<int:project_id>/images/<int:image_id>/update",
    methods=["POST"],
)
@admin_required
def admin_project_image_update(project_id, image_id):
    validate_csrf_token()

    alt_text = request.form.get("alt_text", "").strip()
    caption = request.form.get("caption", "").strip()

    if len(alt_text) > 250:
        flash("Alt text must be 250 characters or fewer.", "error")
        return redirect(url_for("admin_project_edit", project_id=project_id))

    if len(caption) > 300:
        flash("Photo captions must be 300 characters or fewer.", "error")
        return redirect(url_for("admin_project_edit", project_id=project_id))

    connection = get_db_connection()
    image = connection.execute(
        """
        SELECT project_images.id, projects.title
        FROM project_images
        JOIN projects
            ON projects.id = project_images.project_id
        WHERE project_images.id = ?
          AND project_images.project_id = ?
        """,
        (image_id, project_id),
    ).fetchone()

    if image is None:
        connection.close()
        abort(404)

    connection.execute(
        """
        UPDATE project_images
        SET alt_text = ?, caption = ?
        WHERE id = ?
          AND project_id = ?
        """,
        (alt_text, caption, image_id, project_id),
    )
    connection.commit()
    connection.close()

    write_audit_log(
        action="project_image_details_updated",
        category="content",
        description=(
            f'Updated photo details for an image in "{image["title"]}".'
        ),
        entity_type="project_image",
        entity_id=image_id,
    )

    flash("Photo details updated.", "success")
    return redirect(url_for("admin_project_edit", project_id=project_id))


@app.route(
    "/admin/website/projects/<int:project_id>/images/<int:image_id>/move/<direction>",
    methods=["POST"],
)
@admin_required
def admin_project_image_move(project_id, image_id, direction):
    validate_csrf_token()

    if direction not in {"up", "down"}:
        abort(404)

    connection = get_db_connection()

    project = connection.execute(
        "SELECT id FROM projects WHERE id = ?",
        (project_id,),
    ).fetchone()

    if project is None:
        connection.close()
        abort(404)

    normalize_project_image_order(connection, project_id)

    images = connection.execute(
        """
        SELECT id, display_order
        FROM project_images
        WHERE project_id = ?
        ORDER BY display_order ASC, id ASC
        """,
        (project_id,),
    ).fetchall()

    image_ids = [image["id"] for image in images]

    if image_id not in image_ids:
        connection.close()
        abort(404)

    current_index = image_ids.index(image_id)
    target_index = current_index - 1 if direction == "up" else current_index + 1

    if 0 <= target_index < len(images):
        current_image = images[current_index]
        target_image = images[target_index]

        connection.execute(
            """
            UPDATE project_images
            SET display_order = ?
            WHERE id = ?
              AND project_id = ?
            """,
            (target_image["display_order"], current_image["id"], project_id),
        )
        connection.execute(
            """
            UPDATE project_images
            SET display_order = ?
            WHERE id = ?
              AND project_id = ?
            """,
            (current_image["display_order"], target_image["id"], project_id),
        )
        connection.commit()

    connection.close()

    flash("Photo order updated.", "success")
    return redirect(url_for("admin_project_edit", project_id=project_id))


@app.route(
    "/admin/website/projects/<int:project_id>/images/<int:image_id>/cover",
    methods=["POST"],
)
@admin_required
def admin_project_image_cover(project_id, image_id):
    validate_csrf_token()

    connection = get_db_connection()
    image = connection.execute(
        """
        SELECT id
        FROM project_images
        WHERE id = ? AND project_id = ?
        """,
        (image_id, project_id),
    ).fetchone()

    if image is None:
        connection.close()
        abort(404)

    connection.execute(
        "UPDATE project_images SET is_cover = 0 WHERE project_id = ?",
        (project_id,),
    )
    connection.execute(
        "UPDATE project_images SET is_cover = 1 WHERE id = ?",
        (image_id,),
    )
    connection.commit()
    connection.close()

    flash("The project cover photo was updated.", "success")
    return redirect(url_for("admin_project_edit", project_id=project_id))


@app.route(
    "/admin/website/projects/<int:project_id>/images/<int:image_id>/delete",
    methods=["POST"],
)
@admin_required
def admin_project_image_delete(project_id, image_id):
    validate_csrf_token()

    connection = get_db_connection()
    image = connection.execute(
        """
        SELECT *
        FROM project_images
        WHERE id = ? AND project_id = ?
        """,
        (image_id, project_id),
    ).fetchone()

    if image is None:
        connection.close()
        abort(404)

    was_cover = bool(image["is_cover"])
    connection.execute("DELETE FROM project_images WHERE id = ?", (image_id,))

    if was_cover:
        replacement = connection.execute(
            """
            SELECT id
            FROM project_images
            WHERE project_id = ?
            ORDER BY display_order ASC, id ASC
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        if replacement:
            connection.execute(
                "UPDATE project_images SET is_cover = 1 WHERE id = ?",
                (replacement["id"],),
            )

    normalize_project_image_order(connection, project_id)
    connection.commit()
    connection.close()

    absolute_path = os.path.join(BASE_DIR, "static", image["filename"])
    if os.path.isfile(absolute_path):
        os.remove(absolute_path)

    flash("The project photo was deleted.", "success")
    return redirect(url_for("admin_project_edit", project_id=project_id))


@app.route(
    "/admin/website/projects/<int:project_id>/delete",
    methods=["POST"],
)
@admin_required
def admin_project_delete(project_id):
    validate_csrf_token()

    connection = get_db_connection()

    project = connection.execute(
        """
        SELECT id, title
        FROM projects
        WHERE id = ?
        """,
        (project_id,),
    ).fetchone()

    if project is None:
        connection.close()
        abort(404)

    connection.execute(
        """
        DELETE FROM projects
        WHERE id = ?
        """,
        (project_id,),
    )

    connection.commit()
    connection.close()

    project_upload_directory = get_project_upload_directory(project_id)
    if os.path.isdir(project_upload_directory):
        shutil.rmtree(project_upload_directory)

    flash(
        f'"{project["title"]}" was deleted.',
        "success",
    )

    return redirect(url_for("admin_projects"))



# =========================================================
# PHASE 7B: LEARNING CENTER TOPIC LIBRARY
# =========================================================

LEARNING_ARTICLE_TYPES = (
    "Roofing Education",
    "Frequently Asked Roofing Questions",
    "Project Spotlight",
    "Industry News",
)
LEARNING_SEARCH_INTENTS = (
    "Informational",
    "Educational",
    "Buying Guide",
    "FAQ",
    "Case Study",
    "Industry News",
)


def ensure_learning_center_schema():
    connection = get_db_connection()
    now = datetime.now(UTC).isoformat(timespec="seconds")

    # Keep the original category table long enough to migrate existing data.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS article_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            slug TEXT NOT NULL UNIQUE,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS learning_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            summary TEXT,
            body TEXT,
            article_type TEXT NOT NULL DEFAULT 'Roofing Education',
            category_id INTEGER,
            search_intent TEXT NOT NULL DEFAULT 'Informational',
            status TEXT NOT NULL DEFAULT 'draft',
            is_featured INTEGER NOT NULL DEFAULT 0,
            featured_image_url TEXT,
            featured_image_alt_text TEXT,
            seo_title TEXT,
            seo_description TEXT,
            focus_keyword TEXT,
            canonical_url TEXT,
            social_image_url TEXT,
            published_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (category_id)
                REFERENCES article_categories (id)
                ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS learning_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            slug TEXT NOT NULL UNIQUE,
            seo_phrase TEXT,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            show_as_public_filter INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS learning_article_topics (
            article_id INTEGER NOT NULL,
            topic_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (article_id, topic_id),
            FOREIGN KEY (article_id)
                REFERENCES learning_articles (id)
                ON DELETE CASCADE,
            FOREIGN KEY (topic_id)
                REFERENCES learning_topics (id)
                ON DELETE CASCADE
        )
        """
    )

    default_topics = (
        ("Commercial Roofing", "commercial-roofing", "commercial roofing", 10),
        ("Residential Roofing", "residential-roofing", "residential roofing", 20),
        ("Roof Inspections", "roof-inspections", "roof inspection", 30),
        ("Roof Repair", "roof-repair", "roof repair", 40),
        ("Roof Restoration & Coatings", "roof-restoration-coatings", "roof restoration and coatings", 50),
        ("Roof Replacement", "roof-replacement", "roof replacement", 60),
        ("Metal Roofing", "metal-roofing", "metal roofing", 70),
        ("Flat & Low-Slope Roofing", "flat-low-slope-roofing", "flat and low-slope roofing", 80),
        ("Shingle Roofing", "shingle-roofing", "shingle roofing", 90),
        ("Preventive Maintenance", "preventive-maintenance", "preventive roof maintenance", 100),
        ("Leaks & Storm Damage", "leaks-storm-damage", "roof leaks and storm damage", 110),
        ("Roofing Warranties", "roofing-warranties", "roofing warranties", 120),
    )
    for name, slug, seo_phrase, display_order in default_topics:
        connection.execute(
            """
            INSERT OR IGNORE INTO learning_topics (
                name, slug, seo_phrase, display_order,
                is_active, show_as_public_filter, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, 1, ?, ?)
            """,
            (name, slug, seo_phrase, display_order, now, now),
        )

    # Migrate every existing category into the Topic Library.
    legacy_categories = connection.execute(
        "SELECT * FROM article_categories ORDER BY display_order, id"
    ).fetchall()
    for category in legacy_categories:
        connection.execute(
            """
            INSERT OR IGNORE INTO learning_topics (
                name, slug, seo_phrase, display_order,
                is_active, show_as_public_filter, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                category["name"],
                category["slug"],
                category["name"].lower(),
                category["display_order"],
                category["is_active"],
                category["created_at"],
                category["updated_at"],
            ),
        )
        topic = connection.execute(
            "SELECT id FROM learning_topics WHERE name = ? COLLATE NOCASE",
            (category["name"],),
        ).fetchone()
        if topic:
            articles = connection.execute(
                "SELECT id FROM learning_articles WHERE category_id = ?",
                (category["id"],),
            ).fetchall()
            for article in articles:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO learning_article_topics (
                        article_id, topic_id, created_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (article["id"], topic["id"], now),
                )

    connection.execute(
        """
        UPDATE learning_articles
        SET article_type = 'Frequently Asked Roofing Questions'
        WHERE article_type = 'Ask the Roofer'
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_learning_status ON learning_articles (status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_learning_type ON learning_articles (article_type)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_learning_topic_order ON learning_topics (display_order, name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_learning_article_topics_topic ON learning_article_topics (topic_id, article_id)"
    )
    connection.commit()
    connection.close()


def unique_article_slug(connection, title, article_id=None):
    base_slug = create_slug(title) or "article"
    slug = base_slug
    number = 2
    while True:
        if article_id is None:
            existing = connection.execute(
                "SELECT id FROM learning_articles WHERE slug = ?", (slug,)
            ).fetchone()
        else:
            existing = connection.execute(
                "SELECT id FROM learning_articles WHERE slug = ? AND id != ?",
                (slug, article_id),
            ).fetchone()
        if existing is None:
            return slug
        slug = f"{base_slug}-{number}"
        number += 1


def unique_topic_slug(connection, name, topic_id=None):
    base_slug = create_slug(name) or "topic"
    slug = base_slug
    number = 2
    while True:
        if topic_id is None:
            existing = connection.execute(
                "SELECT id FROM learning_topics WHERE slug = ?", (slug,)
            ).fetchone()
        else:
            existing = connection.execute(
                "SELECT id FROM learning_topics WHERE slug = ? AND id != ?",
                (slug, topic_id),
            ).fetchone()
        if existing is None:
            return slug
        slug = f"{base_slug}-{number}"
        number += 1


def normalize_topic_order(connection):
    topics = connection.execute(
        "SELECT id FROM learning_topics ORDER BY display_order, name, id"
    ).fetchall()
    for position, topic in enumerate(topics, start=1):
        connection.execute(
            "UPDATE learning_topics SET display_order = ? WHERE id = ?",
            (position * 10, topic["id"]),
        )


def learning_form_data():
    fields = (
        "title", "summary", "body", "article_type", "search_intent",
        "status", "featured_image_url", "featured_image_alt_text",
        "seo_title", "seo_description", "focus_keyword", "canonical_url",
        "social_image_url",
    )
    data = {key: request.form.get(key, "").strip() for key in fields}
    data["is_featured"] = 1 if request.form.get("is_featured") else 0
    data["topic_ids"] = [
        int(value) for value in request.form.getlist("topic_ids")
        if value.isdigit()
    ]
    return data


def save_learning_article_image(uploaded_file):
    original_name = secure_filename(uploaded_file.filename or "")
    if not original_name or not allowed_image_file(original_name):
        return None
    extension = original_name.rsplit(".", 1)[1].lower()
    unique_name = (
        f"{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}_"
        f"{secrets.token_hex(8)}.{extension}"
    )
    os.makedirs(LEARNING_UPLOAD_ROOT, exist_ok=True)
    uploaded_file.save(os.path.join(LEARNING_UPLOAD_ROOT, unique_name))
    return f"uploads/learning_center/{unique_name}"


def remove_learning_article_image(relative_path):
    if not relative_path or not relative_path.startswith("uploads/learning_center/"):
        return
    absolute_path = os.path.join(BASE_DIR, "static", *relative_path.split("/"))
    if os.path.isfile(absolute_path):
        os.remove(absolute_path)


def apply_learning_image_upload(data, existing_image=None):
    uploaded_file = request.files.get("featured_image")
    remove_image = bool(request.form.get("remove_featured_image"))
    if remove_image:
        remove_learning_article_image(existing_image)
        data["featured_image_url"] = ""
        return data
    if uploaded_file and uploaded_file.filename:
        stored_path = save_learning_article_image(uploaded_file)
        if stored_path is None:
            raise ValueError("Use a JPG, JPEG, PNG, or WebP image.")
        remove_learning_article_image(existing_image)
        data["featured_image_url"] = stored_path
    elif not data["featured_image_url"] and existing_image:
        data["featured_image_url"] = existing_image
    return data


def get_article_topic_ids(connection, article_id):
    return {
        row["topic_id"]
        for row in connection.execute(
            "SELECT topic_id FROM learning_article_topics WHERE article_id = ?",
            (article_id,),
        ).fetchall()
    }


def save_article_topics(connection, article_id, topic_ids):
    valid_ids = {
        row["id"]
        for row in connection.execute(
            "SELECT id FROM learning_topics WHERE is_active = 1 OR id IN (SELECT topic_id FROM learning_article_topics WHERE article_id = ?)",
            (article_id,),
        ).fetchall()
    }
    selected_ids = set(topic_ids) & valid_ids
    connection.execute(
        "DELETE FROM learning_article_topics WHERE article_id = ?", (article_id,)
    )
    now = current_timestamp()
    for topic_id in selected_ids:
        connection.execute(
            "INSERT INTO learning_article_topics (article_id, topic_id, created_at) VALUES (?, ?, ?)",
            (article_id, topic_id, now),
        )


@app.route("/admin/website/learning-center")
@admin_required
def admin_learning_center():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    article_type = request.args.get("article_type", "").strip()
    topic_id = request.args.get("topic_id", "").strip()
    connection = get_db_connection()
    counts = {
        "total": connection.execute("SELECT COUNT(*) AS total FROM learning_articles").fetchone()["total"],
        "published": connection.execute("SELECT COUNT(*) AS total FROM learning_articles WHERE status = 'published'").fetchone()["total"],
        "draft": connection.execute("SELECT COUNT(*) AS total FROM learning_articles WHERE status = 'draft'").fetchone()["total"],
        "featured": connection.execute("SELECT COUNT(*) AS total FROM learning_articles WHERE is_featured = 1").fetchone()["total"],
    }
    filters, params = [], []
    if q:
        filters.append("(a.title LIKE ? OR a.summary LIKE ? OR a.focus_keyword LIKE ? OR EXISTS (SELECT 1 FROM learning_article_topics latq JOIN learning_topics tq ON tq.id = latq.topic_id WHERE latq.article_id = a.id AND tq.name LIKE ?))")
        params.extend([f"%{q}%"] * 4)
    if status in {"draft", "published"}:
        filters.append("a.status = ?")
        params.append(status)
    if article_type in LEARNING_ARTICLE_TYPES:
        filters.append("a.article_type = ?")
        params.append(article_type)
    if topic_id.isdigit():
        filters.append("EXISTS (SELECT 1 FROM learning_article_topics latf WHERE latf.article_id = a.id AND latf.topic_id = ?)")
        params.append(int(topic_id))
    where_clause = "WHERE " + " AND ".join(filters) if filters else ""
    articles = connection.execute(
        f"""
        SELECT a.*,
               GROUP_CONCAT(t.name, '||') AS topic_names
        FROM learning_articles a
        LEFT JOIN learning_article_topics lat ON lat.article_id = a.id
        LEFT JOIN learning_topics t ON t.id = lat.topic_id
        {where_clause}
        GROUP BY a.id
        ORDER BY a.is_featured DESC, a.updated_at DESC, a.title ASC
        """,
        params,
    ).fetchall()
    topics = connection.execute(
        """
        SELECT t.*, COUNT(lat.article_id) AS article_count
        FROM learning_topics t
        LEFT JOIN learning_article_topics lat ON lat.topic_id = t.id
        GROUP BY t.id
        ORDER BY t.display_order, t.name
        """
    ).fetchall()
    connection.close()
    return render_template(
        "admin_learning_center.html", articles=articles, topics=topics,
        counts=counts, q=q, status_filter=status, type_filter=article_type,
        topic_filter=topic_id, article_types=LEARNING_ARTICLE_TYPES,
    )


@app.route("/admin/website/learning-center/new", methods=["GET", "POST"])
@admin_required
def admin_learning_article_new():
    connection = get_db_connection()
    topics = connection.execute(
        "SELECT * FROM learning_topics WHERE is_active = 1 ORDER BY display_order, name"
    ).fetchall()
    if request.method == "POST":
        validate_csrf_token()
        data = learning_form_data()
        if not data["title"]:
            connection.close()
            flash("Article title is required.", "error")
            return render_template("admin_learning_article_form.html", article=None, form_data=data, topics=topics, selected_topic_ids=set(data["topic_ids"]), article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Add Article")
        try:
            data = apply_learning_image_upload(data)
        except ValueError as error:
            connection.close()
            flash(str(error), "error")
            return render_template("admin_learning_article_form.html", article=None, form_data=data, topics=topics, selected_topic_ids=set(data["topic_ids"]), article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Add Article")
        slug = unique_article_slug(connection, data["title"])
        now = current_timestamp()
        status_value = "published" if data["status"] == "published" else "draft"
        published_at = now if status_value == "published" else None
        cursor = connection.execute(
            """
            INSERT INTO learning_articles (
                title, slug, summary, body, article_type, category_id,
                search_intent, status, is_featured, featured_image_url,
                featured_image_alt_text, seo_title, seo_description,
                focus_keyword, canonical_url, social_image_url,
                published_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data["title"], slug, data["summary"], data["body"], data["article_type"] if data["article_type"] in LEARNING_ARTICLE_TYPES else "Roofing Education", data["search_intent"] if data["search_intent"] in LEARNING_SEARCH_INTENTS else "Informational", status_value, data["is_featured"], data["featured_image_url"], data["featured_image_alt_text"], data["seo_title"], data["seo_description"], data["focus_keyword"], data["canonical_url"], data["social_image_url"], published_at, now, now),
        )
        article_id = cursor.lastrowid
        save_article_topics(connection, article_id, data["topic_ids"])
        connection.commit(); connection.close()
        flash("The Learning Center article was created.", "success")
        return redirect(url_for("admin_learning_article_edit", article_id=article_id))
    connection.close()
    return render_template("admin_learning_article_form.html", article=None, form_data=None, topics=topics, selected_topic_ids=set(), article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Add Article")


@app.route("/admin/website/learning-center/<int:article_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_learning_article_edit(article_id):
    connection = get_db_connection()
    article = connection.execute("SELECT * FROM learning_articles WHERE id = ?", (article_id,)).fetchone()
    if article is None:
        connection.close(); abort(404)
    selected_topic_ids = get_article_topic_ids(connection, article_id)
    topics = connection.execute(
        """
        SELECT * FROM learning_topics
        WHERE is_active = 1 OR id IN (SELECT topic_id FROM learning_article_topics WHERE article_id = ?)
        ORDER BY display_order, name
        """, (article_id,)
    ).fetchall()
    if request.method == "POST":
        validate_csrf_token(); data = learning_form_data()
        selected_topic_ids = set(data["topic_ids"])
        if not data["title"]:
            connection.close(); flash("Article title is required.", "error")
            return render_template("admin_learning_article_form.html", article=article, form_data=data, topics=topics, selected_topic_ids=selected_topic_ids, article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Edit Article")
        try:
            data = apply_learning_image_upload(data, existing_image=article["featured_image_url"])
        except ValueError as error:
            connection.close(); flash(str(error), "error")
            return render_template("admin_learning_article_form.html", article=article, form_data=data, topics=topics, selected_topic_ids=selected_topic_ids, article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Edit Article")
        slug = unique_article_slug(connection, data["title"], article_id)
        now = current_timestamp(); status_value = "published" if data["status"] == "published" else "draft"
        published_at = (article["published_at"] or now) if status_value == "published" else None
        connection.execute(
            """
            UPDATE learning_articles SET title=?, slug=?, summary=?, body=?, article_type=?, category_id=NULL,
                search_intent=?, status=?, is_featured=?, featured_image_url=?, featured_image_alt_text=?,
                seo_title=?, seo_description=?, focus_keyword=?, canonical_url=?, social_image_url=?,
                published_at=?, updated_at=? WHERE id=?
            """,
            (data["title"], slug, data["summary"], data["body"], data["article_type"] if data["article_type"] in LEARNING_ARTICLE_TYPES else "Roofing Education", data["search_intent"] if data["search_intent"] in LEARNING_SEARCH_INTENTS else "Informational", status_value, data["is_featured"], data["featured_image_url"], data["featured_image_alt_text"], data["seo_title"], data["seo_description"], data["focus_keyword"], data["canonical_url"], data["social_image_url"], published_at, now, article_id),
        )
        save_article_topics(connection, article_id, data["topic_ids"])
        connection.commit(); connection.close()
        flash("The Learning Center article was updated.", "success")
        return redirect(url_for("admin_learning_article_edit", article_id=article_id))
    connection.close()
    return render_template("admin_learning_article_form.html", article=article, form_data=None, topics=topics, selected_topic_ids=selected_topic_ids, article_types=LEARNING_ARTICLE_TYPES, search_intents=LEARNING_SEARCH_INTENTS, page_heading="Edit Article")


@app.route("/admin/website/learning-center/<int:article_id>/delete", methods=["POST"])
@admin_required
def admin_learning_article_delete(article_id):
    validate_csrf_token(); connection = get_db_connection()
    article = connection.execute("SELECT id, featured_image_url FROM learning_articles WHERE id = ?", (article_id,)).fetchone()
    if article is None:
        connection.close(); abort(404)
    connection.execute("DELETE FROM learning_articles WHERE id = ?", (article_id,))
    connection.commit(); connection.close(); remove_learning_article_image(article["featured_image_url"])
    flash("The Learning Center article was deleted.", "success")
    return redirect(url_for("admin_learning_center"))


@app.route("/admin/website/learning-center/topics/new", methods=["POST"])
@roles_required("owner", "administrator")
def admin_learning_topic_new():
    validate_csrf_token()
    name = request.form.get("name", "").strip()
    seo_phrase = request.form.get("seo_phrase", "").strip()
    show_as_public_filter = 1 if request.form.get("show_as_public_filter") else 0
    if not name:
        flash("Topic name is required.", "error")
        return redirect(url_for("admin_learning_center") + "#topics")
    connection = get_db_connection()
    if connection.execute("SELECT id FROM learning_topics WHERE name = ? COLLATE NOCASE", (name,)).fetchone():
        connection.close(); flash("A topic with that name already exists.", "error")
        return redirect(url_for("admin_learning_center") + "#topics")
    slug = unique_topic_slug(connection, name)
    next_order = connection.execute("SELECT COALESCE(MAX(display_order), 0) + 10 AS next_order FROM learning_topics").fetchone()["next_order"]
    now = current_timestamp()
    connection.execute("INSERT INTO learning_topics (name, slug, seo_phrase, display_order, is_active, show_as_public_filter, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)", (name, slug, seo_phrase, next_order, show_as_public_filter, now, now))
    connection.commit(); connection.close(); flash("Learning Center topic added.", "success")
    return redirect(url_for("admin_learning_center") + "#topics")


@app.route("/admin/website/learning-center/topics/<int:topic_id>/update", methods=["POST"])
@roles_required("owner", "administrator")
def admin_learning_topic_update(topic_id):
    validate_csrf_token()
    name = request.form.get("name", "").strip(); seo_phrase = request.form.get("seo_phrase", "").strip()
    is_active = 1 if request.form.get("is_active") else 0
    show_as_public_filter = 1 if request.form.get("show_as_public_filter") else 0
    if not name:
        flash("Topic name is required.", "error"); return redirect(url_for("admin_learning_center") + "#topics")
    connection = get_db_connection(); topic = connection.execute("SELECT * FROM learning_topics WHERE id = ?", (topic_id,)).fetchone()
    if topic is None:
        connection.close(); abort(404)
    if connection.execute("SELECT id FROM learning_topics WHERE name = ? COLLATE NOCASE AND id != ?", (name, topic_id)).fetchone():
        connection.close(); flash("A topic with that name already exists.", "error")
        return redirect(url_for("admin_learning_center") + "#topics")
    slug = unique_topic_slug(connection, name, topic_id)
    connection.execute("UPDATE learning_topics SET name=?, slug=?, seo_phrase=?, is_active=?, show_as_public_filter=?, updated_at=? WHERE id=?", (name, slug, seo_phrase, is_active, show_as_public_filter, current_timestamp(), topic_id))
    connection.commit(); connection.close(); flash("Topic updated.", "success")
    return redirect(url_for("admin_learning_center") + "#topics")


@app.route("/admin/website/learning-center/topics/<int:topic_id>/move/<direction>", methods=["POST"])
@roles_required("owner", "administrator")
def admin_learning_topic_move(topic_id, direction):
    validate_csrf_token()
    if direction not in {"up", "down"}: abort(404)
    connection = get_db_connection(); normalize_topic_order(connection)
    topics = connection.execute("SELECT id, display_order FROM learning_topics ORDER BY display_order, name, id").fetchall()
    ids = [topic["id"] for topic in topics]
    if topic_id not in ids:
        connection.close(); abort(404)
    current_index = ids.index(topic_id); target_index = current_index - 1 if direction == "up" else current_index + 1
    if 0 <= target_index < len(topics):
        current, target = topics[current_index], topics[target_index]
        connection.execute("UPDATE learning_topics SET display_order=? WHERE id=?", (target["display_order"], current["id"]))
        connection.execute("UPDATE learning_topics SET display_order=? WHERE id=?", (current["display_order"], target["id"]))
        connection.commit()
    connection.close(); return redirect(url_for("admin_learning_center") + "#topics")


@app.route("/admin/website/learning-center/topics/<int:topic_id>/delete", methods=["POST"])
@roles_required("owner", "administrator")
def admin_learning_topic_delete(topic_id):
    validate_csrf_token(); connection = get_db_connection()
    topic = connection.execute("SELECT * FROM learning_topics WHERE id = ?", (topic_id,)).fetchone()
    if topic is None:
        connection.close(); abort(404)
    article_count = connection.execute("SELECT COUNT(*) AS total FROM learning_article_topics WHERE topic_id = ?", (topic_id,)).fetchone()["total"]
    if article_count:
        connection.close(); flash("Remove this topic from its articles before deleting it.", "error")
        return redirect(url_for("admin_learning_center") + "#topics")
    connection.execute("DELETE FROM learning_topics WHERE id = ?", (topic_id,)); normalize_topic_order(connection)
    connection.commit(); connection.close(); flash("Topic deleted.", "success")
    return redirect(url_for("admin_learning_center") + "#topics")


ensure_database_schema()
ensure_learning_center_schema()

if __name__ == "__main__":
    app.run(debug=True)