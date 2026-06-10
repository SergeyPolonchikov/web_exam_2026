import os
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown
import bleach

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, "library.db"))

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key-change-this-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
csrf = CSRFProtect(app)

# Association table for books and genres
book_genres = db.Table(
    "book_genres",
    db.Column("book_id", db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), primary_key=True),
    db.Column("genre_id", db.Integer, db.ForeignKey("genres.id", ondelete="CASCADE"), primary_key=True),
)


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(128), nullable=False)
    middle_name = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Role")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def full_name(self):
        return " ".join(x for x in [self.last_name, self.first_name, self.middle_name] if x)


class Genre(db.Model):
    __tablename__ = "genres"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)


class Book(db.Model):
    __tablename__ = "books"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    publisher = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    pages = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    genres = db.relationship("Genre", secondary=book_genres, backref="books")
    cover = db.relationship("Cover", backref="book", uselist=False, cascade="all, delete-orphan")
    reviews = db.relationship("Review", backref="book", cascade="all, delete-orphan")

    @property
    def avg_rating(self):
        ratings = [r.rating for r in self.reviews]
        if ratings:
            return round(sum(ratings) / len(ratings), 1)
        return 0


class Cover(db.Model):
    __tablename__ = "covers"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False)
    md5_hash = db.Column(db.String(64), unique=True, nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False)


class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("book_id", "user_id", name="uq_review_book_user"),)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_globals():
    years = [y[0] for y in db.session.query(Book.year).distinct().order_by(Book.year.desc()).all()]
    return dict(current_years=years)


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Для выполнения данного действия необходимо пройти процедуру аутентификации")
                return redirect(url_for("login"))
            if current_user.role.name not in roles:
                flash("У вас недостаточно прав для выполнения данного действия")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def clean_md(text):
    html = markdown.markdown(text or "", extensions=["extra", "codehilite"])
    allowed_tags = bleach.sanitizer.ALLOWED_TAGS.union({
        "p", "h1", "h2", "h3", "h4", "h5", "h6",
        "pre", "code", "br", "hr", "blockquote",
        "ul", "ol", "li", "strong", "em", "a", "img"
    })
    allowed_attrs = {
        "a": ["href", "title", "target"],
        "img": ["src", "alt", "title"]
    }
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs, strip=True)


def save_cover(file_storage, book):
    data = file_storage.read()
    md5_hash = hashlib.md5(data).hexdigest()
    existing = Cover.query.filter_by(md5_hash=md5_hash).first()
    if existing:
        existing.book_id = book.id
        db.session.add(existing)
        return

    filename = secure_filename(file_storage.filename)
    ext = os.path.splitext(filename)[1]
    cover = Cover(filename="", mime_type=file_storage.mimetype, md5_hash=md5_hash, book_id=book.id)
    db.session.add(cover)
    db.session.flush()

    final_name = f"{cover.id}{ext}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
    with open(path, "wb") as f:
        f.write(data)

    cover.filename = final_name


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/")
def index():
    q = Book.query
    title = request.args.get("title", "").strip()
    author = request.args.get("author", "").strip()
    genres = request.args.getlist("genre")
    years = request.args.getlist("year")
    vol_from = request.args.get("volume_from", "").strip()
    vol_to = request.args.get("volume_to", "").strip()

    if title:
        q = q.filter(Book.title.ilike(f"%{title}%"))
    if author:
        q = q.filter(Book.author.ilike(f"%{author}%"))
    if years:
        q = q.filter(Book.year.in_(years))
    if vol_from.isdigit():
        q = q.filter(Book.pages >= int(vol_from))
    if vol_to.isdigit():
        q = q.filter(Book.pages <= int(vol_to))
    if genres:
        q = q.join(Book.genres).filter(Genre.id.in_(genres)).group_by(Book.id)

    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(Book.year.desc()).paginate(page=page, per_page=10, error_out=False)

    # Preserve filter args for pagination
    filter_args = request.args.copy()
    return render_template(
        "index.html",
        pagination=pagination,
        genres=Genre.query.all(),
        filters=filter_args
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_value = request.form.get("login")
        password_value = request.form.get("password")
        
        user = User.query.filter_by(login=login_value).first()
        
        if user and user.check_password(password_value):
            login_user(user, remember=bool(request.form.get("remember")))
            flash(f"Добро пожаловать, {user.full_name()}!")
            return redirect(url_for("index"))
        
        flash("Невозможно аутентифицироваться с указанными логином и паролем")
    
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        login_value = request.form.get("login", "").strip()
        password = request.form.get("password", "")
        last_name = request.form.get("last_name", "").strip()
        first_name = request.form.get("first_name", "").strip()
        middle_name = request.form.get("middle_name", "").strip() or None

        if not login_value or not password or not last_name or not first_name:
            flash("Заполните обязательные поля")
            return render_template("register.html")

        if User.query.filter_by(login=login_value).first():
            flash("Пользователь с таким логином уже существует")
            return render_template("register.html")

        role = Role.query.filter_by(name="Пользователь").first()
        if not role:
            flash("В базе нет роли 'Пользователь'")
            return render_template("register.html")

        user = User(
            login=login_value,
            last_name=last_name,
            first_name=first_name,
            middle_name=middle_name,
            role=role,
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            flash("Регистрация прошла успешно. Теперь войдите в систему.")
            return redirect(url_for("login"))
        except Exception:
            db.session.rollback()
            flash("При сохранении данных возникла ошибка")

    return render_template("register.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы")
    return redirect(request.referrer or url_for("index"))


@app.route("/book/<int:book_id>")
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    user_review = None
    if current_user.is_authenticated:
        user_review = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
    return render_template("book_detail.html", book=book, user_review=user_review, clean_md=clean_md)


@app.route("/book/add", methods=["GET", "POST"])
@role_required("Администратор")
def book_add():
    genres = Genre.query.all()
    if request.method == "POST":
        try:
            # Validate required fields
            if not request.form.get("title") or not request.form.get("description"):
                flash("Заполните обязательные поля")
                return render_template("book_form.html", book=None, genres=genres)
            
            book = Book(
                title=request.form["title"],
                description=bleach.clean(request.form["description"]),
                year=int(request.form["year"]),
                publisher=request.form["publisher"],
                author=request.form["author"],
                pages=int(request.form["pages"]),
            )
            for gid in request.form.getlist("genres"):
                genre = Genre.query.get(int(gid))
                if genre:
                    book.genres.append(genre)

            db.session.add(book)
            db.session.flush()

            if "cover" in request.files and request.files["cover"].filename:
                save_cover(request.files["cover"], book)

            db.session.commit()
            flash("Книга успешно добавлена!")
            return redirect(url_for("book_detail", book_id=book.id))
        except Exception:
            db.session.rollback()
            flash("При сохранении данных возникла ошибка. Проверьте корректность введённых данных.")
            return render_template("book_form.html", book=None, genres=genres)

    return render_template("book_form.html", book=None, genres=genres)


@app.route("/book/<int:book_id>/edit", methods=["GET", "POST"])
@role_required("Администратор", "Модератор")
def book_edit(book_id):
    book = Book.query.get_or_404(book_id)
    genres = Genre.query.all()

    if request.method == "POST":
        try:
            book.title = request.form["title"]
            book.description = bleach.clean(request.form["description"])
            book.year = int(request.form["year"])
            book.publisher = request.form["publisher"]
            book.author = request.form["author"]
            book.pages = int(request.form["pages"])
            book.genres = [
                Genre.query.get(int(gid))
                for gid in request.form.getlist("genres")
                if Genre.query.get(int(gid))
            ]
            db.session.commit()
            flash("Книга успешно обновлена!")
            return redirect(url_for("book_detail", book_id=book.id))
        except Exception:
            db.session.rollback()
            flash("При сохранении данных возникла ошибка. Проверьте корректность введённых данных.")
            return render_template("book_form.html", book=book, genres=genres)

    return render_template("book_form.html", book=book, genres=genres)


@app.route("/book/<int:book_id>/delete", methods=["POST"])
@role_required("Администратор")
def book_delete(book_id):
    book = Book.query.get_or_404(book_id)
    cover_path = None
    if book.cover:
        cover_path = os.path.join(app.config["UPLOAD_FOLDER"], book.cover.filename)

    db.session.delete(book)
    db.session.commit()

    if cover_path and os.path.exists(cover_path):
        os.remove(cover_path)

    flash("Книга успешно удалена")
    return redirect(url_for("index"))


@app.route("/book/<int:book_id>/review/add", methods=["GET", "POST"])
@login_required
def review_add(book_id):
    book = Book.query.get_or_404(book_id)

    if current_user.role.name not in ["Пользователь", "Модератор", "Администратор"]:
        flash("У вас недостаточно прав для выполнения данного действия")
        return redirect(url_for("index"))

    existing = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
    if existing:
        flash("Вы уже оставили рецензию на эту книгу")
        return redirect(url_for("book_detail", book_id=book.id))

    if request.method == "POST":
        try:
            review_text = request.form.get("text", "")
            print(f"Получен текст рецензии: {review_text[:100]}...")  # Отладка
            
            review = Review(
                book_id=book.id,
                user_id=current_user.id,
                rating=int(request.form["rating"]),
                text=bleach.clean(review_text),
            )
            db.session.add(review)
            db.session.commit()
            
            flash("Рецензия успешно добавлена!", "success")
            return redirect(url_for("book_detail", book_id=book.id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Ошибка при сохранении рецензии: {e}")
            flash("При сохранении данных возникла ошибка. Проверьте корректность введённых данных.", "danger")
            return render_template("review_form.html", book=book)

    return render_template("review_form.html", book=book)


# Initialize database with roles and sample data
with app.app_context():
    db.create_all()
    
    # Create roles if they don't exist
    roles_data = [
        ("Пользователь", "Обычный пользователь, может оставлять рецензии"),
        ("Модератор", "Может редактировать книги и модерировать рецензии"),
        ("Администратор", "Полный доступ к системе")
    ]
    
    for role_name, role_desc in roles_data:
        if not Role.query.filter_by(name=role_name).first():
            role = Role(name=role_name, description=role_desc)
            db.session.add(role)
    
    db.session.commit()
    
    # Create some sample genres if none exist
    if Genre.query.count() == 0:
        sample_genres = ["Роман", "Фантастика", "Детектив", "Поэзия", "Научная литература", "История", "Приключения"]
        for genre_name in sample_genres:
            genre = Genre(name=genre_name)
            db.session.add(genre)
    
    db.session.commit()
    
    # Create admin user if not exists
    admin_role = Role.query.filter_by(name="Администратор").first()
    if admin_role:
        admin_user = User.query.filter_by(login="admin").first()
        if not admin_user:
            admin = User(
                login="admin",
                last_name="Администратор",
                first_name="Системный",
                middle_name="",
                role=admin_role
            )
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print("=" * 50)
            print("✅ Администратор успешно создан!")
            print(f"📝 Логин: admin")
            print(f"🔑 Пароль: admin123")
            print("=" * 50)
        else:
            # Verify admin password works
            if not admin_user.check_password("admin123"):
                print("⚠️ Сброс пароля администратора...")
                admin_user.set_password("admin123")
                db.session.commit()
                print("✅ Пароль администратора сброшен на 'admin123'")
            else:
                print("✅ Администратор уже существует, пароль работает корректно")
    
    print("\n🏁 Приложение готово к работе!")
    print(f"📁 База данных: {DB_PATH}")
    print(f"📁 Папка загрузок: {UPLOAD_FOLDER}")
    print("=" * 50)


if __name__ == "__main__":
    app.run(debug=True)