from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ✅ User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin', 'manager', 'user'

# ✅ File Model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ Initialize Database
with app.app_context():
    db.create_all()

# ✅ Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# ✅ Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form['nickname']
        name = request.form['name']
        last_name = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
        elif User.query.filter_by(nickname=nickname).first():
            flash("Nickname already exists!", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(nickname=nickname, name=name, last_name=last_name, email=email, 
                            username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created! You can now log in.", "success")
            return redirect(url_for('login'))

    return render_template('register.html')

# ✅ Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("User does not exist. Please register first.", "danger")
        elif not check_password_hash(user.password, password):
            flash("Incorrect password!", "danger")
        else:
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html')

# ✅ Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ✅ Dashboard (Displays Files Based on Role)
@app.route('/dashboard')
@login_required
def dashboard():
    users = {user.id: user for user in User.query.all()}  # Dictionary of users

    if current_user.role == "admin":
        files = File.query.all()
    elif current_user.role == "manager":
        files = File.query.filter(
            (File.uploaded_by == current_user.id) | 
            (File.uploaded_by.in_([user.id for user in User.query.filter_by(role="user")]))
        ).all()
    else:
        files = File.query.filter_by(uploaded_by=current_user.id).all()

    return render_template('dashboard.html', files=files, role=current_user.role, users=users, nickname=current_user.nickname)

# ✅ File Upload Route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        
        if not file or file.filename == '':
            flash("No file selected!", "danger")
            return redirect(url_for('upload'))

        if file.filename.split('.')[-1].lower() not in ALLOWED_EXTENSIONS:
            flash("Invalid file type!", "danger")
            return redirect(url_for('upload'))

        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        new_file = File(filename=filename, uploaded_by=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        flash("File uploaded successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

# ✅ Edit File Route (Admin & Manager Only)
@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    file = File.query.get_or_404(file_id)
    uploader = User.query.get(file.uploaded_by)

    if current_user.role == "admin" or (current_user.role == "manager" and uploader.role == "user"):
        if request.method == "POST":
            new_filename = request.form['filename'].strip()
            if new_filename:
                file.filename = new_filename
                db.session.commit()
                flash("File updated successfully!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Filename cannot be empty!", "danger")

        return render_template('edit.html', file=file)

    flash("Access Denied!", "danger")
    return redirect(url_for('dashboard'))

# ✅ Delete File Route (Admin & Manager Only)
@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    uploader = User.query.get(file.uploaded_by)

    if current_user.role == "admin" or (current_user.role == "manager" and uploader.role == "user"):
        db.session.delete(file)
        db.session.commit()
        flash("File deleted successfully!", "success")
    else:
        flash("Access Denied!", "danger")

    return redirect(url_for('dashboard'))

# ✅ Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
