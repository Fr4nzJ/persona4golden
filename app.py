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

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Add this to your app config
app.config['OPENID_STORE_FS_PATH'] = '/tmp/flask_openid'
oid = OpenID(app, app.config['OPENID_STORE_FS_PATH'])

# Steam OpenID URL
STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login'
STEAM_API_KEY = "D07EC4B741BCF3749C0D25980BD1B7F8"  # Get from https://steamcommunity.com/dev/apikey

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/steam_login')
@oid.loginhandler
def steam_login():
    return oid.try_login(STEAM_OPENID_URL, ask_for=[])

@app.route('/link_steam')
@login_required
def link_steam():
    return oid.try_login(STEAM_OPENID_URL, ask_for=[])

@oid.after_login
def after_steam_login(resp):
    steam_id_match = re.search(r'https://steamcommunity.com/openid/id/(\d+)', resp.identity_url)
    if steam_id_match:
        steam_id = steam_id_match.group(1)
        # Fetch Steam profile info
        r = requests.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
            params={"key": STEAM_API_KEY, "steamids": steam_id}
        )
        player = r.json()["response"]["players"][0] if r.json()["response"]["players"] else {}
        steam_name = player.get("personaname", "")
        steam_avatar = player.get("avatarfull", "")

        # Save to Neo4j
        email = session.get('email')
        with driver.session() as session_neo:
            session_neo.run(
                """
                MATCH (u:User {email: $email})
                SET u.steam_id = $steam_id, u.steam_name = $steam_name, u.steam_avatar = $steam_avatar
                """,
                email=email, steam_id=steam_id, steam_name=steam_name, steam_avatar=steam_avatar
            )
        flash("Steam account linked!", "success")
        return redirect(url_for('profile'))
    flash("Failed to link Steam account.", "danger")
    return redirect(url_for('profile'))

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "Fr4nzJermido"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

email_codes = {}  # Temporary store: {email: code}

def send_verification_email(receiver_email, code):
    sender_email = "ermido09a@gmail.com"  # Replace with your Gmail
    app_password = "qlfa kgjy wdrt gszv"     # Replace with App Password

    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        return True
    except Exception as e:
        print("Email failed:", e)
        return False


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
@app.route('/')
@login_required
def home():
    return render_template('index.html')

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

        # Admin login check
        if username == 'admin' and password == 'admin':
            session['admin'] = True
            flash('Logged in as admin.', 'success')
            return redirect(url_for('admin_dashboard'))

        # Regular user login
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
    session.pop('email', None)  # <-- Clear email from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

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
        input_code = request.form.get('verification_code')  # <-- Fix here

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
            RETURN u.username AS username, u.email AS email, u.steam_id AS steam_id, u.steam_name AS steam_name, u.steam_avatar AS steam_avatar
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
        }
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    email = session.get('email')  # <-- Use email from session
    with driver.session() as session_neo:
        result = session_neo.run(
            "MATCH (u:User {email: $email}) RETURN u.username AS username, u.email AS email",
            email=email
        )
        record = result.single()
        user = {
            "username": record["username"] if record else "",
            "email": record["email"] if record else email
        }
    # Handle POST logic here as needed...
    return render_template('edit_profile.html', user=user)

@app.route('/resend/<email>')
def resend_email(email):
    # Generate a new code and resend the verification email
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
    session.pop('admin', None)  # Remove admin session
    flash('Logged out as admin.', 'info')
    return redirect(url_for('login'))  # Redirect to normal login page

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

# In-memory message store (replace with DB for production)
chat_messages = []

@app.route('/discussion')
def discussion():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('discussion.html')

@app.route('/get_messages')
def get_messages():
    return jsonify(messages=chat_messages[-100:])  # last 100 messages

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

if __name__ == '__main__':
    app.run(debug=True)