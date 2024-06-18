from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app, jsonify, g, abort
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, current_user, login_required, UserMixin, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
import logging
import string
import random
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_DEBUG'] = True
db = SQLAlchemy(app)
mail = Mail(app)
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
logging.basicConfig(level=logging.ERROR)




class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(255), default='uploads/default.jpg')
    click_count = db.Column(db.Integer, default=0)

    messages = db.relationship('Message', backref='user', cascade='all, delete-orphan', lazy=True)
    posts = db.relationship('Post', backref='author', cascade='all, delete-orphan', lazy=True)
    comments = db.relationship('Comment', backref='user', cascade='all, delete-orphan', lazy=True)
    reactions = db.relationship('Reaction', backref='user', cascade='all, delete-orphan', lazy=True)
    favorite_posts = db.relationship('Post', secondary='favorite', backref=db.backref('favorited_by', lazy='dynamic'))

    sent_friend_requests = db.relationship('Friend', 
                                           foreign_keys='Friend.sender_id', 
                                           backref=db.backref('sender', lazy='joined'), 
                                           lazy='dynamic',
                                           cascade='all, delete-orphan')

    received_friend_requests = db.relationship('Friend', 
                                               foreign_keys='Friend.recipient_id', 
                                               backref=db.backref('recipient', lazy='joined'), 
                                               lazy='dynamic',
                                               cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'

    def is_friends_with(self, user):
        return self.received_friend_requests.filter_by(sender_id=user.id, status='accepted').first() is not None

    def has_pending_friend_request(self, user):
        return self.sent_friend_requests.filter_by(recipient_id=user.id, status='pending').first() is not None

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    media_path = db.Column(db.String(255), nullable=True)

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    media_path = db.Column(db.String(255), nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_direct_messages', cascade='all, delete-orphan'))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_direct_messages', cascade='all, delete-orphan'))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_path = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    reactions = db.relationship('Reaction', backref='post', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Post {self.id} by {self.author.username}>'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Comment {self.id} by {self.user.username} on Post {self.post.id}>'

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reaction_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))


class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(10), nullable=False, default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Friend {self.sender.username} to {self.recipient.username} - {self.status}>'

    @classmethod
    def cancel_request(cls, sender_id, recipient_id):
        friend_request = cls.query.filter_by(sender_id=sender_id, recipient_id=recipient_id, status='pending').first()
        if friend_request:
            db.session.delete(friend_request)
            db.session.commit()
            return True
        return False



def create_db():
    with app.app_context():
        db.create_all()


def set_directory_permissions():
    flask_app_dir = os.path.dirname(os.path.abspath(__file__))
    permissions = 0o755
    os.chmod(flask_app_dir, permissions)


set_directory_permissions()

@app.before_request
def before_request():
    if 'user_id' in session:
        session_user = User.query.get(session['user_id'])
        g.user = session_user
    else:
        g.user = None

@app.context_processor
def inject_user():
    return dict(user=g.user)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


def check_authenticated(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))  
    return wrapper



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(username) < 6 or len(username) > 16:
            flash('Username must be between 6 and 16 characters long.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6 or len(password) > 12:
            flash('Password must be between 6 and 12 characters long.', 'error')
            return redirect(url_for('register'))

        if ' ' in username:
            flash('Username cannot contain spaces.', 'error')
            return redirect(url_for('register'))
        if ' ' in password:
            flash('Password cannot contain spaces.', 'error')
            return redirect(url_for('register'))

        if username.isdigit():
            flash('Username cannot consist only of numbers.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        default_profile_picture = 'uploads/default.jpg'

        new_user = User(username=username, email=email, password=generate_password_hash(password),
                        profile_picture=default_profile_picture)
        
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/promote_to_admin')
def promote_to_admin():
    username = 'zd'
    user = User.query.filter_by(username=username).first()

    if user:
        user.is_admin = True
        db.session.commit()
        return f'User {username} promoted to admin successfully!'
    else:
        return f'User {username} not found!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')



@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.session.get(User, user_id) 
        return render_template('profile.html', user=user)
    else:
        flash('Please log in to view your profile.', 'error')
        return redirect(url_for('login'))
    

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('profile'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    if user.id == current_user.id:
        flash('Admins cannot delete themselves.', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':

        try:
            for favorite in user.favorite_posts:
                db.session.delete(favorite)
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('manage_users'))

    return render_template('delete_user.html', user=user)






@app.route('/admin/manage_users', methods=['GET', 'POST'])
def manage_users():
    if request.method == 'POST':
        if 'user_id' in session:
            current_user = User.query.get(session['user_id'])
            if current_user.is_admin:
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                user.is_admin = True
                db.session.commit()
                flash('User promoted to administrator successfully!', 'success')
                return redirect(url_for('manage_users'))
            else:
                flash('You do not have permission to perform this action.', 'danger')
                return redirect(url_for('profile'))
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
        if current_user.is_admin:
            users = User.query.all()
            return render_template('manage_users.html', users=users, user=current_user)
        else:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('profile'))
    else:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        repeat_password = request.form['repeat_password']

        if not check_password_hash(user.password, old_password):
            flash('Old password is incorrect. Please try again.', 'danger')
            return redirect(url_for('profile'))

        if new_password != repeat_password:
            flash('New password and repeated password do not match. Please try again.', 'danger')
            return redirect(url_for('profile'))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Please log in to change your password.', 'error')
        return redirect(url_for('login'))




@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' in session:
        if request.method == 'POST':
            user_id = session['user_id']
            content = request.form['message']
            media = request.files.get('photo')  

            new_message = Message(user_id=user_id, content=content)
            
            if media:
                media_filename = secure_filename(media.filename)
                media_path = os.path.join('static/uploads', media_filename)
                media.save(media_path)
                new_message.media_path = f'uploads/{media_filename}'

            db.session.add(new_message)
            db.session.commit()

            return redirect(url_for('chat'))
        else:
            messages = Message.query.order_by(Message.created_at).all()
            user_id = session['user_id']
            user = User.query.get(user_id)
            return render_template('chat.html', messages=messages, user=user)
    else:
        flash('Please log in to access the chat.', 'error')
        return redirect(url_for('login'))





@app.route('/delete_message/<int:message_id>', methods=['GET', 'POST'])
def delete_message(message_id):
    source = request.referrer  
    
    if source.endswith('/chat'):  
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)
            message = Message.query.get(message_id)
            
            if user.is_admin or message.user_id == user_id:
                db.session.delete(message)
                db.session.commit()

            else:
                pass
            
            return redirect(url_for('chat'))
        else:
            return redirect(url_for('login'))
    else:
        return jsonify({'source': source})
        



@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.session.get(User, user_id)
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            upload_folder = 'static/uploads'
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            filename = secure_filename(profile_picture.filename)
            file_path = os.path.join(upload_folder, filename)
            profile_picture.save(file_path)
            user.profile_picture = f'uploads/{filename}'
            db.session.commit()
            flash('Profile picture uploaded successfully!', 'success')
        else:
            flash('No profile picture uploaded.', 'danger')
    else:
        flash('Please log in to upload a profile picture.', 'danger')
    return redirect(url_for('profile'))

@app.route('/clicking_game', methods=['GET', 'POST'])
def clicking_game():
    if 'user_id' not in session:
        flash('Please log in to access the clicking game.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.filter_by(id=user_id).first_or_404()

    if request.method == 'POST':
        user.click_count += 1
        db.session.commit()
        return jsonify({'counter': user.click_count})  

    return render_template('clicking_game.html', counter=user.click_count)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@check_authenticated
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    likes = Reaction.query.filter_by(post_id=post_id, reaction_type='like').count()
    dislikes = Reaction.query.filter_by(post_id=post_id, reaction_type='dislike').count()

    if request.method == 'POST':
        comment_text = request.form.get('comment')
        if comment_text:
            new_comment = Comment(text=comment_text, user_id=session.get('user_id'), post_id=post_id)
            try:
                db.session.add(new_comment)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error adding comment: {str(e)}')

        return redirect(url_for('post', post_id=post_id))

    return render_template('post.html', post=post, comments=comments, likes=likes, dislikes=dislikes)

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@check_authenticated
def add_comment(post_id):
    if request.method == 'POST':
        comment_text = request.form.get('comment')
        if comment_text:
            new_comment = Comment(text=comment_text, user_id=session.get('user_id'), post_id=post_id)
            try:
                db.session.add(new_comment)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error adding comment: {str(e)}')

    return redirect(url_for('post', post_id=post_id))




@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    if request.method == 'POST':
        if 'user_id' in session:  
            title = request.form.get('title')
            text = request.form.get('text')
            media = request.files.get('media')

            new_post = Post(title=title, text=text, user_id=session['user_id'])
            
            if media:
                media_filename = secure_filename(media.filename)
                media_path = os.path.join('static/uploads', media_filename)
                media.save(media_path)
                new_post.media_path = f'uploads/{media_filename}'

            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('posts'))
        else:
            flash('You need to be logged in to create a post.', 'error')
            return redirect(url_for('login'))
    return render_template('create_post.html')


@app.route('/react_to_post/<int:post_id>/<string:reaction_type>', methods=['POST'])
def react_to_post(post_id, reaction_type):
    if 'user_id' in session:
        if reaction_type in ['like', 'dislike']:
            existing_reaction = Reaction.query.filter_by(post_id=post_id, user_id=session['user_id']).first()
            if existing_reaction:
                existing_reaction.reaction_type = reaction_type
            else:
                new_reaction = Reaction(reaction_type=reaction_type, user_id=session['user_id'], post_id=post_id)
                db.session.add(new_reaction)
            
            db.session.commit()
    
    return redirect(url_for('post', post_id=post_id))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id).options(db.joinedload(Comment.user)).all()
    if request.method == 'POST':
        if 'user_id' in session:  
            comment_text = request.form.get('comment')
            new_comment = Comment(text=comment_text, user_id=session['user_id'], post_id=post.id)
            db.session.add(new_comment)
            db.session.commit()
        return redirect(url_for('post', post_id=post.id))

    return render_template('post.html', post=post, comments=comments, current_user=current_user)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@check_authenticated
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == session.get('user_id') or current_user.is_admin:
        try:
            db.session.delete(comment)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error deleting comment: {str(e)}')
    
    return redirect(url_for('view_post', post_id=comment.post_id))

@app.route('/add_to_favorites/<int:post_id>', methods=['POST'])
@login_required
def add_to_favorites(post_id):
    post = Post.query.get_or_404(post_id)

    if post not in current_user.favorite_posts:
        current_user.favorite_posts.append(post)
        db.session.commit()

    return redirect(url_for('favorites'))

@app.route('/favorites')
@login_required
def favorites():
    favorite_posts = current_user.favorite_posts
    return render_template('favorites.html', favorite_posts=favorite_posts)

@app.route('/remove_from_favorites/<int:post_id>', methods=['POST'])
@login_required  
def remove_from_favorites(post_id):
    user = User.query.get(current_user.id)

    post = Post.query.get(post_id)

    if post:
        if post in user.favorite_posts:
            user.favorite_posts.remove(post)
            db.session.commit()
 
    return redirect(url_for('favorites'))

@app.route('/toggle_favorite/<int:post_id>', methods=['POST'])
@login_required
def toggle_favorite(post_id):
    post = Post.query.get_or_404(post_id)
    
    if current_user in post.favorited_by:
        post.favorited_by.remove(current_user)
        db.session.commit()
        return redirect(url_for('favorites'))
    else:
        post.favorited_by.append(current_user)
        db.session.commit()
        return redirect(url_for('favorites'))





# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form.get('email')

#         # Simulate user existence check (replace with actual logic)
#         user = {'email': email}  # Example user check

#         if not user:
#             flash('Email not found. Please enter a valid email.', 'error')
#             return render_template('forgot_password.html')

#         # Generate recovery code
#         recovery_code = generate_recovery_code()

#         # Send recovery email
#         send_recovery_email(email, recovery_code)
        
#         return render_template('forgot_password.html')
    
#     return render_template('forgot_password.html')

# def generate_recovery_code():
#     code = ''.join(random.choices(string.digits, k=6))
#     return code

# def send_recovery_email(email, recovery_code):
#     subject = "Password Recovery Code"
#     body = f"Your password recovery code is: {recovery_code}"
    
#     try:
#         msg = Message(subject=subject, recipients=[email])
#         msg.body = body
#         mail.send(msg)
#     except Exception as e:
#         flash(f"Failed to send recovery email: {str(e)}", "danger")


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        return redirect(url_for('posts'))
    try:
        db.session.delete(post)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
    return redirect(url_for('posts'))
@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/posts', methods=['GET'])
def posts():
    all_posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('posts.html', posts=all_posts)
    
@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('another_profile.html', user=user, current_user=current_user)

@app.route('/dm_chat/<int:recipient_id>')
@login_required
def dm_chat(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    messages = DirectMessage.query.filter(
        (DirectMessage.sender_id == current_user.id) & (DirectMessage.recipient_id == recipient_id) |
        (DirectMessage.sender_id == recipient_id) & (DirectMessage.recipient_id == current_user.id)
    ).order_by(DirectMessage.created_at.asc()).all()
    members = User.query.all()

    return render_template('dmchat.html', members=members, messages=messages, recipient=recipient)

@app.route('/send_dm/<int:recipient_id>', methods=['POST'])
@login_required
def send_dm(recipient_id):
    message_content = request.form.get('message')
    media = request.files.get('media')

    if message_content or media:
        new_message = DirectMessage(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            content=message_content
        )
        
        if media:
            media_filename = secure_filename(media.filename)
            media_path = os.path.join('static/uploads', media_filename)
            media.save(media_path)
            new_message.media_path = f'uploads/{media_filename}'

        db.session.add(new_message)
        db.session.commit()

    return redirect(url_for('dm_chat', recipient_id=recipient_id))

@app.route('/delete_directmessage/<int:message_id>', methods=['POST', 'DELETE'])
@login_required
def delete_directmessage(message_id):
    message = DirectMessage.query.get_or_404(message_id)
    if current_user.is_admin or message.sender_id == current_user.id:
        db.session.delete(message)
        db.session.commit()
        

    return redirect(url_for('dm_chat', recipient_id=message.recipient_id))

@app.route('/send_friend_request/<int:user_id>', methods=['POST'])
@login_required
def send_friend_request(user_id):
    if user_id == current_user.id:
        return redirect(url_for('user_profile', username=current_user.username))

    recipient = User.query.get(user_id)
    if not recipient:
        return redirect(url_for('user_profile', username=current_user.username))

    existing_request1 = Friend.query.filter_by(sender_id=current_user.id, recipient_id=user_id).first()
    existing_request2 = Friend.query.filter_by(sender_id=user_id, recipient_id=current_user.id).first()

    if existing_request1 and existing_request2:
        if existing_request1.status == 'pending' and existing_request2.status == 'pending':
            existing_request1.status = 'accepted'
            existing_request2.status = 'accepted'
            db.session.commit()
            flash('Friend request accepted. You are now friends.', 'success')
            return redirect(url_for('user_profile', username=recipient.username))

    if existing_request1:
        if existing_request1.status == 'pending':
            flash('You have already sent a friend request to this user.', 'warning')
            return redirect(url_for('user_profile', username=recipient.username))
        elif existing_request1.status == 'accepted':
            flash('You are already friends with this user.', 'warning')
            return redirect(url_for('user_profile', username=recipient.username))

    if existing_request2:
        if existing_request2.status == 'pending':
            flash('You have already received a friend request from this user.', 'warning')
            return redirect(url_for('inbox'))
        elif existing_request2.status == 'accepted':
            flash('You are already friends with this user.', 'warning')
            return redirect(url_for('user_profile', username=recipient.username))


    new_request = Friend(sender_id=current_user.id, recipient_id=user_id, status='pending')
    db.session.add(new_request)
    db.session.commit()

    return redirect(url_for('user_profile', username=recipient.username))


@app.route('/inbox')
@login_required
def inbox():
    received_requests = Friend.query.filter_by(recipient_id=current_user.id, status='pending').all()
    return render_template('inbox.html', received_requests=received_requests)


@app.route('/friend_request/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    friend_request = Friend.query.get(request_id)
    if not friend_request:
        return redirect(url_for('inbox'))

    if friend_request.recipient_id != current_user.id:
        return redirect(url_for('inbox'))

    friend_request.status = 'accepted'
    db.session.commit()

    new_friendship = Friend(sender_id=current_user.id, recipient_id=friend_request.sender_id, status='accepted')
    db.session.add(new_friendship)
    db.session.commit()

    return redirect(url_for('inbox'))


@app.route('/friend_request/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    friend_request = Friend.query.get(request_id)
    if not friend_request:
        return redirect(url_for('inbox'))

    if friend_request.recipient_id != current_user.id:
        return redirect(url_for('inbox'))

    friend_request.status = 'rejected'
    db.session.commit()

    if friend_request.status == 'rejected':
        friend1 = Friend.query.filter_by(sender_id=current_user.id, recipient_id=friend_request.sender_id, status='accepted').first()
        friend2 = Friend.query.filter_by(sender_id=friend_request.sender_id, recipient_id=current_user.id, status='accepted').first()

        if friend1:
            friend1.status = 'rejected'
        if friend2:
            friend2.status = 'rejected'

        db.session.commit()

    return redirect(url_for('inbox'))



@app.route('/remove_friend/<int:user_id>', methods=['POST'])
@login_required
def remove_friend(user_id):
    friendship1 = Friend.query.filter_by(sender_id=current_user.id, recipient_id=user_id, status='accepted').first()
    friendship2 = Friend.query.filter_by(sender_id=user_id, recipient_id=current_user.id, status='accepted').first()

    if friendship1:
        friendship1.status = 'rejected'
        db.session.commit()
        
        db.session.delete(friendship1)
        db.session.commit()

    if friendship2:
        friendship2.status = 'rejected'
        db.session.commit()
        
        db.session.delete(friendship2)
        db.session.commit()


    return redirect(url_for('user_profile', username=current_user.username))



@app.route('/cancel_friend_request/<int:user_id>', methods=['POST'])
@login_required
def cancel_friend_request(user_id):
    user = User.query.get(user_id)
    if not user:
        abort(404)

    friend_request = Friend.query.filter_by(sender_id=current_user.id, recipient_id=user_id, status='pending').first()

    if friend_request:
        db.session.delete(friend_request)
        db.session.commit()

    return redirect(url_for('user_profile', username=user.username))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('delete_password')
    if check_password_hash(current_user.password, password):
        user = User.query.get(current_user.id)
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been deleted.', 'success')
        return redirect(url_for('register'))
    else:
        flash('Incorrect password. Please try again.', 'danger')
        return redirect(url_for('profile'))
    
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    users = User.query.filter(User.username.like(f'%{query}%')).all()
    if users:
        return render_template('search_results.html', users=users)
    return render_template("404.html")

@app.route('/autocomplete', methods=['GET'])
def autocomplete():
    search = request.args.get('query')
    users = User.query.filter(User.username.like(f'%{search}%')).all()
    usernames = [user.username for user in users]
    return jsonify(usernames)


if __name__ == "__main__":
    with app.app_context():
        create_db()
        promote_to_admin()
    port = int(os.environ.get('PORT', 5000))
    debug = bool(os.environ.get('DEBUG', True))
    app.run(host='0.0.0.0', port=port, debug=debug)