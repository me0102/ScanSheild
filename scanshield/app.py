from flask import Flask, request, render_template, redirect, url_for, flash, session
from featureExtractor import featureExtraction
from pycaret.classification import load_model, predict_model
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os

model = load_model('model/phishingdetection')

# Configuration de la base de données
DATABASE = 'users.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Décorateur pour vérifier si l'utilisateur est connecté
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Veuillez vous connecter pour accéder à cette page", "error")
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

def predict(url):
    try:
        data = featureExtraction(url)
        result = predict_model(model, data=data)
        prediction_label = result['prediction_label'][0]
        prediction_score = result['prediction_score'][0]
        
        # Conversion du label numérique en texte
        is_safe = prediction_label == 0  # 0 pour sécurisé, 1 pour malveillant
        
        return {
            'url': url,
            'prediction_label': 'safe' if is_safe else 'malicious',
            'prediction_score': (1 - prediction_score if is_safe else prediction_score) * 100
        }
    except Exception as e:
        print(f"Erreur lors de la prédiction: {str(e)}")
        raise e

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète_ici'  # À changer en production
app.config['PERMANENT_SESSION_LIFETIME'] = 7 * 24 * 3600  # Session valide pendant 7 jours

# Initialisation de la base de données au démarrage
with app.app_context():
    init_db()

@app.route("/")
def home():
    return render_template("index.html", user=session.get('user'))

@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    data = None
    error = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            try:
                data = predict(url)
                return render_template('scan.html', url=url, data=data, user=session.get('user'))
            except Exception as e:
                error = "Une erreur s'est produite lors de l'analyse de l'URL"
        else:
            error = "Veuillez entrer une URL"
    return render_template("scan.html", data=data, error=error, user=session.get('user'))

@app.route("/auth")
def auth():
    if "user" in session:
        return redirect(url_for("home"))
    return render_template("auth.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    remember = request.form.get("rememberMe") == "on"
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    db.close()
    
    if user and check_password_hash(user['password'], password):
        session["user"] = {"email": user['email'], "name": user['name']}
        if remember:
            session.permanent = True
        flash("Connexion réussie!", "success")
        return redirect(url_for("home"))
    
    flash("Email ou mot de passe incorrect", "error")
    return redirect(url_for("auth"))

@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    
    db = get_db()
    try:
        db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                  (name, email, generate_password_hash(password)))
        db.commit()
        flash("Inscription réussie! Vous pouvez maintenant vous connecter", "success")
    except sqlite3.IntegrityError:
        flash("Cet email est déjà utilisé", "error")
    finally:
        db.close()
    
    return redirect(url_for("auth"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Vous avez été déconnecté", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
