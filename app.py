from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from neo4j import GraphDatabase
import smtplib
import random
from flask import session
import smtplib
from email.mime.text import MIMEText
from flask_openid import OpenID
import re
import requests
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import jwt  # PyJWT library for JWT creation

def generate_jwt(user, secret_key='your_secret_key', algorithm='HS256'):
    """
    Generates a JWT token for the given user dictionary.
    """
    payload = {
        'username': user.get('username'),
        'email': user.get('email'),
        'steam_id': user.get('steam_id'),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize Neo4j driver
NEO4J_URI = "bolt://localhost:7687"  # Change as needed
NEO4J_USER = "neo4j"                 # Change as needed
NEO4J_PASSWORD = "Fr4nzJermido"          # Change as needed
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Add this to your app config
app.config['OPENID_STORE_FS_PATH'] = os.path.join(app.root_path, 'flask_openid_store')
oid = OpenID(app, app.config['OPENID_STORE_FS_PATH'])

# Steam OpenID URL
STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login'
STEAM_API_KEY = "D07EC4B741BCF3749C0D25980BD1B7F8"  # Get from https://steamcommunity.com/dev/apikey

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_steam_id_from_openid(identity_url):
    """
    Extracts the Steam ID from the OpenID identity URL.
    """
    if not identity_url:
        return None
    match = re.search(r'https://steamcommunity.com/openid/id/(\d+)', identity_url)
    if match:
        return match.group(1)
    return None

@app.route("/steam_login")
def steam_login():
    if "openid.identity" not in request.args:
        steam_openid_url = (
            "https://steamcommunity.com/openid/login"
            "?openid.ns=http://specs.openid.net/auth/2.0"
            "&openid.mode=checkid_setup"
            f"&openid.return_to={url_for('steam_login', _external=True)}"
            f"&openid.realm={request.host_url}"
            "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select"
            "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select"
        )
        return redirect(steam_openid_url)

    steam_id = get_steam_id_from_openid(request.args.get("openid.identity"))
    if not steam_id:
        flash("Steam login failed.", "danger")
        return redirect(url_for("login"))

    # --- Linking Steam account to existing user ---
    if session.get("linking_steam"):
        email = session.get("email")
        if not email:
            flash("You must be logged in to link your Steam account.", "warning")
            return redirect(url_for("login"))

        with driver.session() as neo_session:
            result = neo_session.run(
                "MATCH (u:User {steam_id: $steam_id}) RETURN u.email AS email",
                steam_id=steam_id
            ).single()
        if result and result["email"] != email:
            flash("This Steam account is already linked to another user.", "danger")
            session.pop("linking_steam", None)
            return redirect(url_for("profile"))

        try:
            r = requests.get(
                "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                params={"key": STEAM_API_KEY, "steamids": steam_id}
            )
            r.raise_for_status()
            data = r.json().get("response", {}).get("players", [])
        except Exception as e:
            flash(f"Failed to fetch Steam profile: {e}", "danger")
            return redirect(url_for("profile"))

        if data:
            player = data[0]
            steam_name = player.get("personaname", "")
            steam_avatar = player.get("avatarfull", "")
        else:
            steam_name = ""
            steam_avatar = ""

        with driver.session() as neo_session:
            neo_session.run("""
                MATCH (u:User {email: $email})
                SET u.steam_id = $steam_id,
                    u.steam_name = $steam_name,
                    u.steam_avatar = $steam_avatar
            """, email=email, steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar)

        session.pop("linking_steam", None)
        flash("Steam account linked to your profile!", "success")
        return redirect(url_for("profile"))

    # --- Normal Steam login/signup ---
    with driver.session() as neo_session:
        result = neo_session.run("MATCH (u:User {steam_id: $steam_id}) RETURN u", steam_id=steam_id).single()

    if result:
        user_node = result["u"]
        user = dict(user_node)
        session["user"] = user.get("username")
        session["email"] = user.get("email")
        token = generate_jwt(user)
        session["jwt_token"] = token
        flash("Logged in with Steam!", "success")
        return redirect(url_for("home"))

    session["steam_id"] = steam_id
    return redirect(url_for("steam_signup"))


@app.route("/link_steam")
def link_steam():
    session["linking_steam"] = True
    return redirect("https://steamcommunity.com/openid/login"
                    "?openid.ns=http://specs.openid.net/auth/2.0"
                    "&openid.mode=checkid_setup"
                    "&openid.return_to=http://localhost:5000/steam_login"
                    "&openid.realm=http://localhost:5000/"
                    "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select"
                    "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select")


@app.route("/steam_signup", methods=["GET", "POST"])
def steam_signup():
    steam_id = session.get("steam_id")
    steam_name = session.get("steam_name")
    steam_avatar = session.get("steam_avatar")

    if not steam_id:
        flash("Steam ID missing. Please try again.", "danger")
        return redirect(url_for("login"))

    if not steam_name or not steam_avatar:
        r = requests.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
            params={"key": STEAM_API_KEY, "steamids": steam_id}
        )
        data = r.json().get("response", {}).get("players", [])
        if data:
            player = data[0]
            steam_name = player.get("personaname")
            steam_avatar = player.get("avatarfull")
            session["steam_name"] = steam_name
            session["steam_avatar"] = steam_avatar
        else:
            steam_name = ""
            steam_avatar = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()

        if not username or not email:
            flash("Username and email are required.", "danger")
            return render_template("steam_signup.html", steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar, username=username, email=email)

        with driver.session() as db:
            result = db.run(
                "MATCH (u:User) WHERE u.username = $username OR u.email = $email RETURN u LIMIT 1",
                username=username, email=email
            ).single()
            if result:
                flash("Username or email already exists.", "danger")
                return render_template("steam_signup.html", steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar, username=username, email=email)

            result = db.run("""
                CREATE (u:User {
                    id: randomUUID(),
                    username: $username,
                    email: $email,
                    steam_id: $steam_id,
                    steam_name: $steam_name,
                    steam_avatar: $steam_avatar
                }) RETURN u
            """, username=username, email=email, steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar).single()

        session.pop("steam_id", None)
        session.pop("steam_name", None)
        session.pop("steam_avatar", None)
        user = result["u"]
        session["user"] = user["username"]
        session["email"] = user["email"]
        token = generate_jwt(user)
        flash("Account created successfully!", "success")
        return redirect(url_for("home"))

    return render_template(
        "steam_signup.html",
        steam_id=steam_id,
        steam_name=steam_name,
        steam_avatar=steam_avatar,
        username="",
        email=""
    )


@oid.after_login
def after_steam_login(resp):
    if not resp or not resp.identity_url:
        flash("Steam login failed.", "danger")
        return redirect(url_for('login'))

    match = re.search(r'https://steamcommunity.com/openid/id/(\d+)', resp.identity_url)
    if not match:
        flash("Invalid Steam response.", "danger")
        return redirect(url_for('login'))

    steam_id = match.group(1)

    r = requests.get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                     params={"key": STEAM_API_KEY, "steamids": steam_id})
    data = r.json().get("response", {}).get("players", [])
    if not data:
        flash("Unable to fetch Steam profile.", "danger")
        return redirect(url_for('login'))

    player = data[0]
    steam_name = player.get("personaname")
    steam_avatar = player.get("avatarfull")

    if session.get('linking_steam') is True:
        email = session.get('email')
        if not email:
            flash("You must be logged in to link your Steam account.", "warning")
            return redirect(url_for('login'))

        with driver.session() as session_neo:
            session_neo.run("""
                MATCH (u:User {email: $email})
                SET u.steam_id = $steam_id,
                    u.steam_name = $steam_name,
                    u.steam_avatar = $steam_avatar
            """, email=email, steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar)

        flash("Steam account linked to your profile!", "success")
        return redirect(url_for('profile'))

    else:
        session["user"] = steam_name
        session["email"] = ""
        flash("Logged in via Steam!", "success")
        return redirect(url_for('home'))



characters = [
    {
        "name": "Yu Narukami",
        "slug": "yu-narukami",
        "arcana": "Fool",
        "role": "Protagonist",
        "desc": "A calm and collected transfer student who leads the Investigation Team.",
        "persona": "Izanagi / Izanagi-no-Okami",
        "element": "Varies",
        "skills": ["Zio", "Rakukaja", "Power Charge", "Myriad Truths"],
        "img": "yu.png",
        "persona_evolution": [
            {
                "name": "Izanagi",
                "img": "P4_Izanagi_artwork.png"
            },
            {
                "name": "Izanagi-no-Okami",
                "img": "P4_Izanagi-no-Okami_Artwork.png"
            }
        ]
    },
    {
        "name": "Yosuke Hanamura",
        "slug": "yosuke-hanamura",
        "arcana": "Magician",
        "role": "Wind Persona User",
        "desc": "Yu's cheerful classmate who uses wind and healing abilities.",
        "persona": "Jiraiya / Susano-o",
        "element": "Wind",
        "skills": ["Garu", "Diarama", "Magarula", "Wind Boost"],
        "img": "yosuke.png",
        "persona_evolution": [
            {
                "name": "Jiraiya",
                "img": "P4_Jiraiya_Artwork.png"
            },
            {
                "name": "Susano-o",
                "img": "P4_Susano-o_Artwork.png"
            }
        ]
    },
    {
        "name": "Chie Satonaka",
        "slug": "chie-satonaka",
        "arcana": "Chariot",
        "role": "Physical Persona User",
        "desc": "An energetic girl who loves kung-fu movies and excels in physical attacks.",
        "persona": "Tomoe / Suzuka Gongen",
        "element": "Ice",
        "skills": ["Bufula", "Rebellion", "Power Charge", "God's Hand"],
        "img": "chie.png",
        "persona_evolution": [
            {
                "name": "Tomoe",
                "img": "P4-TomoeGozen.png"
            },
            {
                "name": "Suzuka Gongen",
                "img": "P4_Suzuka_Gongen_Artwork.png"
            }
        ]
    },
    {
        "name": "Yukiko Amagi",
        "slug": "yukiko-amagi",
        "arcana": "Priestess",
        "role": "Fire Persona User",
        "desc": "A refined girl from a traditional inn-keeping family, adept with fire and healing magic.",
        "persona": "Konohana Sakuya / Amaterasu",
        "element": "Fire",
        "skills": ["Agi", "Media", "Agidyne", "Salvation"],
        "img": "yukiko.png",
        "persona_evolution": [
            {
                "name": "Konohana Sakuya",
                "img": "P4_Konohana_Sakuya_Artwork.png"
            },
            {
                "name": "Amaterasu",
                "img": "P4_Amaterasu_Artwork.png"
            }
        ]
    },
    {
        "name": "Kanji Tatsumi",
        "slug": "kanji-tatsumi",
        "arcana": "Emperor",
        "role": "Physical Persona User",
        "desc": "A tough delinquent with a soft side, specializing in physical and lightning attacks.",
        "persona": "Take-Mikazuchi / Rokuten Maoh",
        "element": "Electric",
        "skills": ["Ziodyne", "Fatal End", "Primal Force", "Matarukaja"],
        "img": "kanji.png",
        "persona_evolution": [
            {
                "name": "Take-Mikazuchi",
                "img": "P4_Take-Mikazuchi_Artwork.png"
            },
            {
                "name": "Rokuten Maoh",
                "img": "P4_Rokuten-Maoh_Artwork.png"
            }
        ]
    },
    {
        "name": "Teddie",
        "slug": "teddie",
        "arcana": "Star",
        "role": "Ice Persona User",
        "desc": "A mysterious bear-like creature who supports the team with ice and healing skills.",
        "persona": "Kintoki-Douji / Kamui",
        "element": "Ice",
        "skills": ["Bufula", "Mediarama", "Ice Boost", "Samarecarm"],
        "img": "teddie.png",
        "persona_evolution": [
            {
                "name": "Kintoki-Douji",
                "img": "P4G_Kintoki-Douji_Graphic.png"
            },
            {
                "name": "Kamui",
                "img": "P4G_Kamui_Graphic.png"
            }
        ]
    },
    {
        "name": "Naoto Shirogane",
        "slug": "naoto-shirogane",
        "arcana": "Fortune",
        "role": "Almighty Persona User",
        "desc": "A young detective prodigy skilled in light, dark, and almighty abilities.",
        "persona": "Sukuna-Hikona / Yamato Takeru",
        "element": "Light & Dark",
        "skills": ["Hamaon", "Mudoon", "Megidolaon", "Shield of Justice"],
        "img": "naoto.png",
        "persona_evolution": [
            {
                "name": "Sukuna-Hikona",
                "img": "P4_Sukuna-Hikona_Artwork.png"
            },
            {
                "name": "Yamato Takeru",
                "img": "P4G_Yamato-Takeru_Artwork.png"
            }
        ]
    },
    {
        "name": "Rise Kujikawa",
        "slug": "rise-kujikawa",
        "arcana": "Lovers",
        "role": "Support Navigator",
        "desc": "A former idol who provides invaluable support and analysis during battles.",
        "persona": "Himiko / Kanzeon",
        "element": "Support",
        "skills": ["Full Analysis", "Healing Wave", "Stat Buffs", "Third Eye"],
        "img": "rise.png",
        "persona_evolution": [
            {
                "name": "Himiko",
                "img": "P4_Himiko_Artwork.png"
            },
            {
                "name": "Kanzeon",
                "img": "P4_Kanzeon_Artwork.png"
            }
        ]
    }
]

def get_user_profile_pic():
    email = session.get('email')
    with driver.session() as session_neo:
        result = session_neo.run(
            "MATCH (u:User {email: $email}) RETURN u.profile_pic AS profile_pic",
            email=email
        )
        record = result.single()
        return record["profile_pic"] if record and record["profile_pic"] else "images/default_profile.png"

@app.route('/')
@login_required
def home():
    profile_pic = get_user_profile_pic()
    return render_template('index.html', profile_pic=profile_pic)

@app.route('/team')
@login_required
def team():
    return render_template('team.html', characters=characters)

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html', characters=characters)

@app.route('/character/<slug>')
@login_required
def character_detail(slug):
    character = next((char for char in characters if char["slug"] == slug), None)
    if character:
        return render_template("character.html", character=character)
    else:
        return "Character not found", 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'admin' and password == 'admin':
            session['admin'] = True
            flash('Logged in as admin.', 'success')
            return redirect(url_for('admin_dashboard'))

        with driver.session() as session_neo:
            result = session_neo.run(
                """
                MATCH (u:User {username: $username, password: $password})
                RETURN u.username AS username, u.email AS email
                """,
                username=username,
                password=password
            )
            record = result.single()

        if record:
            session['user'] = record["username"]
            session['email'] = record["email"]
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

email_codes = {}

def send_verification_email(email, code):
    sender_email = "ermido09a@gmail.com"
    sender_password = "Fr4nzJermido"
    subject = "Your Persona 4 Golden Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [email], msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        code = str(random.randint(100000, 999999))

        email_codes[email] = {'code': code, 'username': username, 'password': password}

        if send_verification_email(email, code):
            flash("Verification code sent to your Gmail. Please enter it below.", "info")
            return redirect(url_for('verify_email', email=email))
        else:
            flash("Failed to send email. Try again.", "danger")

    return render_template('signup.html')


@app.route('/verify/<email>', methods=['GET', 'POST'])
def verify_email(email):
    if request.method == 'POST':
        input_code = request.form.get('verification_code')

        if email in email_codes and input_code == email_codes[email]['code']:
            username = email_codes[email]['username']
            password = email_codes[email]['password']

            with driver.session() as session_neo:
                session_neo.run(
                    """
                    CREATE (u:User {username: $username, password: $password, email: $email})
                    """,
                    username=username, password=password, email=email
                )
            del email_codes[email]
            flash("Email verified. You can now log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid code. Please try again.", "danger")

    return render_template('verify.html', email=email)

@app.route('/profile')
@login_required
def profile():
    email = session.get('email')
    with driver.session() as session_neo:
        result = session_neo.run(
            """
            MATCH (u:User {email: $email})
            RETURN u.username AS username, u.email AS email, u.steam_id AS steam_id, u.steam_name AS steam_name, u.steam_avatar AS steam_avatar, u.profile_pic AS profile_pic
            """,
            email=email
        )
        record = result.single()
        user = {
            "username": record["username"] if record else "",
            "email": record["email"] if record else email,
            "steam_id": record["steam_id"] if record else None,
            "steam_name": record["steam_name"] if record else None,
            "steam_avatar": record["steam_avatar"] if record else None,
            "profile_pic": record["profile_pic"] if record and record["profile_pic"] else "images/default_profile.png"
        }
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    email = session.get('email')
    with driver.session() as session_neo:
        result = session_neo.run(
            "MATCH (u:User {email: $email}) RETURN u.username AS username, u.email AS email, u.profile_pic AS profile_pic",
            email=email
        )
        record = result.single()
        user = {
            "username": record["username"] if record else "",
            "email": record["email"] if record else email,
            "profile_pic": record["profile_pic"] if record and record["profile_pic"] else "images/default_profile.png"
        }

    if request.method == 'POST':
        username = request.form['username']
        new_email = request.form['email']
        password = request.form['password']
        file = request.files.get('profile_pic')
        profile_pic_path = user["profile_pic"]

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(app.root_path, UPLOAD_FOLDER)
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            profile_pic_path = f'uploads/{filename}'
            with driver.session() as session_neo:
                session_neo.run(
                    """
                    MATCH (u:User {email: $email})
                    SET u.username = $username,
                        u.email = $new_email,
                        u.profile_pic = $profile_pic
                    """,
                    email=email,
                    username=username,
                    new_email=new_email,
                    profile_pic=profile_pic_path
                )
        else:
            with driver.session() as session_neo:
                session_neo.run(
                    """
                    MATCH (u:User {email: $email})
                    SET u.username = $username,
                        u.email = $new_email
                    """,
                    email=email,
                    username=username,
                    new_email=new_email
                )
            if password:
                pass

        session['email'] = new_email

        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/resend/<email>')
def resend_email(email):
    code = str(random.randint(100000, 999999))
    if email in email_codes:
        username = email_codes[email]['username']
        password = email_codes[email]['password']
    else:
        username = ""
        password = ""
    email_codes[email] = {'code': code, 'username': username, 'password': password}
    send_verification_email(email, code)
    flash("A new verification code has been sent to your email.")
    return redirect(url_for('verify_email', email=email))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    flash('Logged out as admin.', 'info')
    return redirect(url_for('login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    with driver.session() as session_neo:
        result = session_neo.run(
            "MATCH (u:User) RETURN u.username AS username, u.email AS email, u.steam_id AS steam_id, u.steam_name AS steam_name, u.steam_avatar AS steam_avatar"
        )
        users = [record.data() for record in result]
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/edit/<email>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(email):
    with driver.session() as session_neo:
        if request.method == 'POST':
            username = request.form.get('username')
            new_email = request.form.get('email')
            session_neo.run(
                "MATCH (u:User {email: $email}) SET u.username = $username, u.email = $new_email",
                email=email, username=username, new_email=new_email
            )
            flash('User updated.', 'success')
            return redirect(url_for('admin_dashboard'))
        result = session_neo.run(
            "MATCH (u:User {email: $email}) RETURN u.username AS username, u.email AS email",
            email=email
        )
        user = result.single()
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/delete/<email>', methods=['POST'])
@admin_required
def admin_delete_user(email):
    with driver.session() as session_neo:
        session_neo.run("MATCH (u:User {email: $email}) DETACH DELETE u", email=email)
    flash('User deleted.', 'info')
    return redirect(url_for('admin_dashboard'))

chat_messages = []

@app.route('/discussion')
def discussion():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('discussion.html')

@app.route('/get_messages')
def get_messages():
    return jsonify(messages=chat_messages[-100:])

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 403
    data = request.get_json()
    text = data.get('text', '').strip()
    if text:
        chat_messages.append({
            'user': session['user'],
            'text': text,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify({'success': True})

import os

@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'user' not in session:
        return redirect(url_for('login'))
    file = request.files['profile_pic']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        email = session.get('email')
        with driver.session() as session_neo:
            session_neo.run(
                "MATCH (u:User {email: $email}) SET u.profile_pic = $profile_pic",
                email=email,
                profile_pic=f'uploads/{filename}'
            )
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)