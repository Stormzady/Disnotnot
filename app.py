from flask import Flask, render_template, request, redirect, session, url_for, jsonify, send_from_directory, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson.json_util import dumps
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
STATIC_FOLDER = os.path.join(app.root_path, 'static')

app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(
    app,
    cookie_options={"samesite": "None", "secure": True}  # keep Socket.IO happy too
)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["chatcat"]
users_col = db["users"]
messages_col = db["messages"]

oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id='1364667028992036904',
    client_secret='0AJ5Vo3RNSePLz9AubKA9H00niiqT9mH',
    access_token_url='https://discord.com/api/oauth2/token',
    access_token_params=None,
    authorize_url='https://discord.com/api/oauth2/authorize',
    authorize_params=None,
    api_base_url='https://discord.com/api/',
    client_kwargs={'scope': 'identify email'},
)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    user = users_col.find_one({"username": username})
    return User(username) if user else None

@app.route('/')
def index():
    if current_user.is_authenticated:
        # Load last 50 messages, sorted by timestamp (oldest first)
        raw_messages = messages_col.find().sort("timestamp", 1).limit(50)
        messages = []

        for msg in raw_messages:
            timestamp = msg.get("timestamp")
            # Format the datetime for display
            if isinstance(timestamp, datetime):
                formatted = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted = str(timestamp)

            messages.append({
                "username": msg.get("username", "unknown"),
                "message": msg.get("message", ""),
                "timestamp": formatted
        })

        return render_template("index.html", username=current_user.id, messages=messages)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = users_col.find_one({"$or": [{"username": username}, {"email": email}]})

        if existing_user:
            return "Username or email already taken!"

        users_col.insert_one({
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "created_via": "username_password",
            "original_username": username
        })
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/register/discord', methods=['GET', 'POST'])
def discord_register():
    if 'discord_user_info' not in session:
        return redirect(url_for('login'))

    info = session['discord_user_info']

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        if users_col.find_one({"$or": [{"username": username}, {"email": email}]}):
            return "Username or email already taken."

        users_col.insert_one({
            "username": username,
            "email": email,
            "discord_id": info["discord_id"],
            "created_via": "discord",
            "original_username": info["original_username"]
        })

        login_user(User(username))
        session.pop('discord_user_info', None)
        return redirect(url_for('index'))

    return render_template('discord_register.html', original_username=info['original_username'], email=info['email'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = users_col.find_one({"username": request.form['username']})
        if user and check_password_hash(user['password_hash'], request.form['password']):
            login_user(User(user['username']))
            return redirect(url_for('index'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/login/discord')
def login_discord():
    redirect_uri = url_for('authorize_discord', _external=True)
    return discord.authorize_redirect(redirect_uri)

@app.route('/authorize/discord')
def authorize_discord():
    token = discord.authorize_access_token()
    user_info = discord.get('users/@me').json()
    discord_username = user_info['username']
    discord_id = user_info['id']
    discord_email = user_info.get('email', '')

    user = users_col.find_one({"discord_id": discord_id})
    if user:
        login_user(User(user['username']))
        return redirect(url_for('index'))

    # New Discord user — ask to choose username/email
    session['discord_user_info'] = {
        "discord_id": discord_id,
        "original_username": discord_username,
        "email": discord_email
    }
    return redirect(url_for('discord_register'))

@app.route('/link_discord')
@login_required
def link_discord():
    """
    Renders a simple page with a “Connect Discord” button
    unless the account is already linked.
    """
    user = users_col.find_one({"username": current_user.id})
    if user.get("discord_id"):
        flash("Your account is already linked to Discord.", "info")
        return redirect(url_for('account'))
    return render_template('link_discord.html')

@app.route('/link_discord/start')
@login_required
def link_discord_start():
    """
    Starts the OAuth2 handshake specifically for linking.
    """
    redirect_uri = url_for('link_discord_callback', _external=True)
    session['linking_discord'] = True        # flag so we know WHY we’re authorising
    return discord.authorize_redirect(redirect_uri)

@app.route('/link_discord/callback')
@login_required
def link_discord_callback():
    """
    Handles the OAuth2 callback and stores the Discord ID
    on the *current* ChatCat user document (if it isn’t
    linked to someone else already).
    """
    if not session.pop('linking_discord', None):
        # Someone hit this URL directly; fall back to the
        # regular authorise handler so nothing breaks.
        return redirect(url_for('authorize_discord'))

    token = discord.authorize_access_token()
    user_info = discord.get('users/@me').json()
    discord_id = user_info['id']
    discord_username = user_info['username']

    # Prevent double-linking
    other = users_col.find_one({"discord_id": discord_id})
    if other and other['username'] != current_user.id:
        return (
            "That Discord account is already linked to another ChatCat account.",
            400
        )

    # Add the ID to the logged-in user
    users_col.update_one(
        {"username": current_user.id},
        {"$set": {"discord_id": discord_id, "created_via": "discord", "original_username": discord_username}}
    )
    flash("Discord linked successfully!  🎉", "success")
    return redirect(url_for('account'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/pick_username", methods=["GET", "POST"])
def pick_username():
    if "oauth_original_username" not in session or "oauth_provider" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        chosen = request.form["username"].strip()
        if users_col.find_one({"username": chosen}):
            return "That username is taken!"

        users_col.insert_one({
            "username": chosen,
            "original_username": session["oauth_original_username"],
            "created_via": session["oauth_provider"],
            "password_hash": ""
        })

        login_user(User(chosen))
        # Clear temp session keys
        session.pop("oauth_original_username")
        session.pop("oauth_provider")
        return redirect(url_for("index"))

    return render_template("pick_username.html")

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = users_col.find_one({"username": current_user.id})

    message = None

    # Set password form submission
    if request.method == 'POST' and 'new_password' in request.form:
        new_password = request.form['new_password']
        password_hash = generate_password_hash(new_password)
        users_col.update_one({"username": current_user.id}, {"$set": {"password_hash": password_hash}})
        message = "Password set successfully."

    # Update bio form submission
    if request.method == 'POST' and 'bio' in request.form:
        bio = request.form['bio']
        users_col.update_one({"username": current_user.id}, {"$set": {"bio": bio}})
        message = "Bio updated successfully."

    # Check if Discord is linked
    discord_linked = "discord_id" in user
    original_username = user.get("original_username", "N/A")
    created_via = user.get("created_via", "unknown")
    email = user.get("email", "Not set")
    bio = user.get("bio", "No bio set.")

    return render_template("account.html",
                           username=current_user.id,
                           email=email,
                           created_via=created_via,
                           original_username=original_username,
                           discord_linked=discord_linked,
                           password_set="password_hash" in user,
                           message=message,
                           bio=bio)

@app.route('/u/<username>')
def user_profile(username):
    user = users_col.find_one({"username": username})
    if user:
        bio = user.get("bio", "No bio set.")
        email = user.get("email", "Not set")
        created_via = user.get("created_via", "unknown")
        original_username = user.get("original_username", "N/A")
        is_staff = user.get("is_staff", False)
        return render_template("profile.html", 
                               username=username, 
                               email=email, 
                               created_via=created_via, 
                               original_username=original_username, 
                               bio=bio,
                               is_staff=is_staff)
    return "User not found", 404




@app.route('/<path:filename>')
def serve_static_file(filename):
    # If the URL ends with .html, remove the extension
    if filename.endswith('.html'):
        filename = filename[:-5]  # Remove ".html" from the URL path

    # Try to serve static files from the static folder
    file_path = os.path.join(STATIC_FOLDER, filename)

    # If the file exists, serve it
    if os.path.exists(file_path):
        return send_from_directory(STATIC_FOLDER, filename)
    
    # If no matching file, return a 404
    return "File not found", 404

@socketio.on('message')
def handle_message(msg):
    username = current_user.id
    timestamp = datetime.utcnow()
    
    # Insert the message into MongoDB
    messages_col.insert_one({
        "username": username,
        "message": msg,
        "timestamp": timestamp
    })
    
    # Emit the message along with username and timestamp
    emit('message', {
        'username': username,
        'message': msg,
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=80, host='0.0.0.0')