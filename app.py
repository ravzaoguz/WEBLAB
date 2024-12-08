import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

# .env dosyasını yüklüyoruz
load_dotenv()

# SECRET_KEY'i .env dosyasından alıyoruz
SECRET_KEY = os.getenv("SECRET_KEY")

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY  # Flask app'inin SECRET_KEY değerini ayarlıyoruz

# Basit kullanıcı veritabanı
users_db = {}

# Token doğrulama işlemi
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')  # Header'dan token alıyoruz
        if not token:
            return jsonify({"error": "Yetkisiz"}), 401  # Token yoksa yetkisiz

        try:
            token = token.split(" ")[1]  # Token'ı 'Bearer ' kısmından ayırıyoruz
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = decoded_token['username']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token süresi doldu."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Geçersiz token."}), 401

        return f(current_user, *args, **kwargs)
    return decorated_function

# Kullanıcı kaydı (signup)
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users_db:
        return jsonify({"error": "Kullanıcı zaten mevcut."}), 400

    hashed_password = generate_password_hash(password)
    users_db[username] = hashed_password

    return jsonify({"message": "Kullanıcı başarıyla kaydedildi."}), 201

# Kullanıcı girişi (login)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user_password = users_db.get(username)
    if not user_password or not check_password_hash(user_password, password):
        return jsonify({"error": "Geçersiz kimlik bilgileri."}), 401

    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token 1 saat geçerli
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"message": "Giriş başarılı.", "token": token}), 200

# Kullanıcı çıkışı (logout)
@app.route('/logout', methods=['DELETE'])
@token_required
def logout(current_user):
    return jsonify({"message": "Başarıyla çıkış yapıldı."}), 200

# Özel bir rota (private route)
@app.route('/private_route', methods=['GET'])
@token_required
def private_route(current_user):
    return jsonify({"message": f"Merhaba {current_user}, özel alana hoşgeldiniz"}), 200

# Şifre sıfırlama (forgot password)
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')

    if username not in users_db:
        return jsonify({"error": "Kullanıcı bulunamadı."}), 404

    # Burada şifre sıfırlama işlemi yapılabilir (örneğin, e-posta gönderme)
    return jsonify({"message": "Şifre sıfırlama bağlantısı e-posta adresinize gönderildi."}), 200

# Ana sayfa
@app.route('/')
def home():
    return "Merhaba, Flask çalışıyor!"

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Flask uygulamasını çalıştırıyoruz