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

PROTECTED_ADMIN_LOGIN = "admin"
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
        # Исправляем: фильтрация по жанрам
        q = q.join(Book.genres).filter(Genre.id.in_(genres)).distinct()

    page = request.args.get("page", 1, type=int)
    per_page = 10
    
    # Обёртка в try-except для отладки
    try:
        pagination = q.order_by(Book.year.desc()).paginate(page=page, per_page=per_page, error_out=False)
    except Exception as e:
        print(f"Ошибка пагинации: {e}")
        # Если ошибка, показываем первую страницу без фильтров
        pagination = Book.query.order_by(Book.year.desc()).paginate(page=1, per_page=per_page, error_out=False)
    
    # Сохраняем параметры фильтрации для ссылок
    filter_args = request.args.copy()
    # Удаляем page из копии, чтобы не дублировать
    if 'page' in filter_args:
        filter_args.pop('page')
    
    return render_template(
        "index.html",
        pagination=pagination,
        genres=Genre.query.all(),
        filters=filter_args
    )


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
            old_title = book.title
            
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
            
            # Обработка новой обложки
            if "cover" in request.files and request.files["cover"].filename:
                # Удаляем старую обложку из файловой системы, если она есть
                if book.cover:
                    old_cover_path = os.path.join(app.config["UPLOAD_FOLDER"], book.cover.filename)
                    if os.path.exists(old_cover_path):
                        os.remove(old_cover_path)
                    # Удаляем запись о старой обложке из БД
                    db.session.delete(book.cover)
                    db.session.flush()
                
                # Сохраняем новую обложку
                save_cover(request.files["cover"], book)
            
            db.session.commit()
            flash(f"Книга «{book.title}» успешно обновлена!", "success")
            return redirect(url_for("book_detail", book_id=book.id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Ошибка при редактировании: {e}")
            flash("При сохранении данных возникла ошибка. Проверьте корректность введённых данных.", "danger")
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_value = request.form.get("login")
        password_value = request.form.get("password")
        
        user = User.query.filter_by(login=login_value).first()
        
        if user and user.check_password(password_value):
            login_user(user, remember=bool(request.form.get("remember")))
            flash(f"Добро пожаловать, {user.full_name()}!", "success")
            
            # Перенаправляем на страницу, откуда пришли, или на главную
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            return redirect(url_for("index"))
        
        flash("Невозможно аутентифицироваться с указанными логином и паролем", "danger")
    
    return render_template("login.html")

with app.app_context():
    db.create_all()
    
    # Создание ролей (если их нет)
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
    
    # Создание жанров (если их нет)
    if Genre.query.count() == 0:
        sample_genres = ["Роман", "Фантастика", "Детектив", "Поэзия", "Научная литература", "История", "Приключения"]
        for genre_name in sample_genres:
            genre = Genre(name=genre_name)
            db.session.add(genre)
    
    db.session.commit()
    
    # Создание администратора (если его нет)
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
            if not admin_user.check_password("admin123"):
                print("⚠️ Сброс пароля администратора...")
                admin_user.set_password("admin123")
                db.session.commit()
                print("✅ Пароль администратора сброшен на 'admin123'")
            else:
                print("✅ Администратор уже существует, пароль работает корректно")
    
    moderator_role = Role.query.filter_by(name="Модератор").first()
    if moderator_role:
        moderator_user = User.query.filter_by(login="moderator").first()
        if not moderator_user:
            moderator = User(
                login="moderator",
                last_name="Модераторов",
                first_name="Модератор",
                middle_name="Тестович",
                role=moderator_role
            )
            moderator.set_password("moderator123")
            db.session.add(moderator)
            db.session.commit()
            print("✅ Модератор успешно создан!")
            print(f"📝 Логин: moderator")
            print(f"🔑 Пароль: moderator123")
        else:
            if not moderator_user.check_password("moderator123"):
                print("⚠️ Сброс пароля модератора...")
                moderator_user.set_password("moderator123")
                db.session.commit()
                print("✅ Пароль модератора сброшен на 'moderator123'")
    
    user_role = Role.query.filter_by(name="Пользователь").first()
    if user_role:
        regular_user = User.query.filter_by(login="user").first()
        if not regular_user:
            user = User(
                login="user",
                last_name="Пользователей",
                first_name="Обычный",
                middle_name="Петрович",
                role=user_role
            )
            user.set_password("user123")
            db.session.add(user)
            db.session.commit()
            print("✅ Обычный пользователь успешно создан!")
            print(f"📝 Логин: user")
            print(f"🔑 Пароль: user123")
        else:
            if not regular_user.check_password("user123"):
                regular_user.set_password("user123")
                db.session.commit()
                print("✅ Пароль пользователя сброшен на 'user123'")
    
    print("\n🏁 Приложение готово к работе!")
    print(f"📁 База данных: {DB_PATH if 'DB_PATH' in dir() else 'PostgreSQL'}")
    print(f"📁 Папка загрузок: {UPLOAD_FOLDER}")
    print("=" * 50)

@app.route("/admin/users")
@role_required("Администратор")
def admin_users():
    users = User.query.all()
    roles = Role.query.all()
    return render_template("admin_users.html", users=users, roles=roles)


@app.route("/admin/user/<int:user_id>/change_role", methods=["POST"])
@role_required("Администратор")
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    
    # Защита: нельзя менять роль защищённого администратора
    if user.login == PROTECTED_ADMIN_LOGIN:
        flash("Нельзя изменить роль системного администратора!", "danger")
        return redirect(url_for("admin_users"))
    
    new_role_id = request.form.get("role_id")
    
    # Защита: нельзя изменить роль последнего администратора (кроме защищённого)
    if user.role.name == "Администратор":
        # Считаем только НЕ защищённых администраторов
        admin_count = User.query.filter(
            User.role.has(name="Администратор"),
            User.login != PROTECTED_ADMIN_LOGIN
        ).count()
        if admin_count <= 1:
            flash("Нельзя изменить роль единственного администратора (кроме системного)!", "danger")
            return redirect(url_for("admin_users"))
    
    role = Role.query.get(new_role_id)
    if role:
        old_role = user.role.name
        user.role = role
        db.session.commit()
        
        # Особое сообщение при назначении администратора
        if role.name == "Администратор":
            flash(f"⚠️ Пользователь {user.full_name()} назначен администратором! Будьте осторожны.", "warning")
        else:
            flash(f"Роль пользователя {user.full_name()} изменена с {old_role} на {role.name}", "success")
    
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@role_required("Администратор")
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Защита: нельзя удалить защищённого администратора
    if user.login == PROTECTED_ADMIN_LOGIN:
        flash("❌ Нельзя удалить системного администратора!", "danger")
        return redirect(url_for("admin_users"))
    
    # Защита: нельзя удалить самого себя
    if user.id == current_user.id:
        flash("❌ Нельзя удалить свою учётную запись", "danger")
        return redirect(url_for("admin_users"))
    
    # Защита: нельзя удалить последнего администратора (кроме защищённого)
    if user.role.name == "Администратор":
        admin_count = User.query.filter(
            User.role.has(name="Администратор"),
            User.login != PROTECTED_ADMIN_LOGIN
        ).count()
        if admin_count <= 1:
            flash("❌ Нельзя удалить единственного администратора (кроме системного)!", "danger")
            return redirect(url_for("admin_users"))
    
    # Сохраняем имя для сообщения
    user_full_name = user.full_name()
    user_login = user.login
    
    # Удаляем пользователя
    db.session.delete(user)
    db.session.commit()
    
    flash(f"✅ Пользователь {user_full_name} (логин: {user_login}) удалён", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/reviews")
@role_required("Администратор", "Модератор")
def admin_reviews():
    """Страница управления рецензиями"""
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    return render_template("admin_reviews.html", reviews=reviews)


@app.route("/admin/review/<int:review_id>/delete", methods=["POST"])
@role_required("Администратор", "Модератор")
def admin_delete_review(review_id):
    """Удаление рецензии (для модератора и админа)"""
    review = Review.query.get_or_404(review_id)
    book_title = review.book.title
    user_name = review.user.full_name()
    
    db.session.delete(review)
    db.session.commit()
    
    flash(f"Рецензия пользователя {user_name} на книгу «{book_title}» удалена", "success")
    return redirect(request.referrer or url_for("admin_reviews"))


@app.route("/admin/review/<int:review_id>/edit", methods=["GET", "POST"])
@role_required("Администратор", "Модератор")
def admin_edit_review(review_id):
    """Редактирование рецензии (для модератора и админа)"""
    review = Review.query.get_or_404(review_id)
    
    if request.method == "POST":
        try:
            review.rating = int(request.form["rating"])
            review.text = bleach.clean(request.form["text"])
            db.session.commit()
            flash("Рецензия успешно отредактирована", "success")
            return redirect(url_for("admin_reviews"))
        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка при редактировании: {str(e)}", "danger")
    
    return render_template("admin_edit_review.html", review=review)

with app.app_context():
    db.create_all()
    
    # Создание ролей
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
    
    # Создание жанров
    if Genre.query.count() == 0:
        sample_genres = ["Роман", "Фантастика", "Детектив", "Поэзия", "Научная литература", "История", "Приключения"]
        for genre_name in sample_genres:
            genre = Genre(name=genre_name)
            db.session.add(genre)
    
    db.session.commit()
    
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
        else:
            # Проверка пароля
            if not admin_user.check_password("admin123"):
                admin_user.set_password("admin123")
                db.session.commit()
    
    moderator_role = Role.query.filter_by(name="Модератор").first()
    if moderator_role:
        moderator_user = User.query.filter_by(login="moderator").first()
        if not moderator_user:
            moderator = User(
                login="moderator",
                last_name="Модераторов",
                first_name="Модератор",
                middle_name="Тестович",
                role=moderator_role
            )
            moderator.set_password("moderator123")
            db.session.add(moderator)
            db.session.commit()
    
    user_role = Role.query.filter_by(name="Пользователь").first()
    if user_role:
        regular_user = User.query.filter_by(login="user").first()
        if not regular_user:
            user = User(
                login="user",
                last_name="Пользователей",
                first_name="Обычный",
                middle_name="Петрович",
                role=user_role
            )
            user.set_password("user123")
            db.session.add(user)
            db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)