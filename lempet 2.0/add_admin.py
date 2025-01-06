from app import db, User
from werkzeug.security import generate_password_hash

def add_admin():
    username = input("Введіть ім'я адміністратора: ")
    email = input("Введіть email адміністратора: ")
    password = input("Введіть пароль адміністратора: ")

    # Перевірка, чи існує такий користувач
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print("Користувач із таким ім'ям вже існує.")
        return

    # Додаємо адміністратора
    admin = User(
        username=username,
        email=email,
        password=generate_password_hash(password, method="pbkdf2:sha256"),
        role="admin"
    )
    db.session.add(admin)
    db.session.commit()
    print("Адміністратор успішно доданий!")

if __name__ == "__main__":
    add_admin()
