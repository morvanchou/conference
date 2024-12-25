# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import config

app = Flask(__name__)
app.config.from_object(config)

db = SQLAlchemy(app)

# 确保上传文件夹存在
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# 添加文件类型检查函数
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# 修改提交论文的路由
@app.route('/submit', methods=['GET', 'POST'])
def submit_paper():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 检查文件是否存在
        if 'paper' not in request.files:
            flash('没有选择文件')
            return redirect(request.url)

        file = request.files['paper']
        # 如果用户没有选择文件，浏览器也会提交一个没有文件名的空文件
        if file.filename == '':
            flash('没有选择文件')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                # 使用时间戳和原始文件名组合，避免文件名冲突
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                paper = Paper(
                    title=request.form['title'],
                    abstract=request.form['abstract'],
                    keywords=request.form['keywords'],
                    filename=filename,
                    author_id=session['user_id']
                )

                db.session.add(paper)
                db.session.commit()
                flash('论文提交成功')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash('文件上传失败：' + str(e))
                return redirect(request.url)
        else:
            flash('不支持的文件类型')
            return redirect(request.url)

    return render_template('submit.html')



# 用户模型
# app.py 中添加/修改以下内容

# 修改 User 模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 角色: admin, reviewer, user
    is_admin = db.Column(db.Boolean, default=False)  # 是否是管理员
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# 添加管理员验证装饰器
from functools import wraps


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('需要管理员权限')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)

    return decorated_function


# 添加创建管理员账户的命令
@app.cli.command('create-admin')
def create_admin():
    username = input('请输入管理员用户名: ')
    email = input('请输入管理员邮箱: ')
    password = input('请输入管理员密码: ')

    if User.query.filter_by(username=username).first():
        print('用户名已存在')
        return

    admin = User(
        username=username,
        email=email,
        role='admin',
        is_admin=True
    )
    admin.set_password(password)

    db.session.add(admin)
    db.session.commit()
    print('管理员账户创建成功')


# 管理员专用路由
@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    papers = Paper.query.all()
    reviews = Review.query.all()
    return render_template('admin/panel.html', users=users, papers=papers, reviews=reviews)


@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']

        if request.form.get('is_admin'):
            user.is_admin = True
            user.role = 'admin'
        else:
            user.is_admin = False

        if request.form.get('new_password'):
            user.set_password(request.form['new_password'])

        db.session.commit()
        flash('用户信息更新成功')
        return redirect(url_for('manage_users'))

    return render_template('admin/edit_user.html', user=user)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if session['user_id'] == user_id:
        flash('不能删除当前登录的管理员账户')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('用户已删除')
    return redirect(url_for('manage_users'))


# 论文模型
class Paper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    abstract = db.Column(db.Text, nullable=False)
    keywords = db.Column(db.String(200))
    filename = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, under_review, accepted, rejected
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('papers', lazy=True))


# 评审模型
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # 1-5分
    comments = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paper = db.relationship('Paper', backref=db.backref('reviews', lazy=True))
    reviewer = db.relationship('User')


# 路由函数
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('注册成功，请登录')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('登录成功')
            return redirect(url_for('dashboard'))

        flash('用户名或密码错误')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('已退出登录')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    if user.role == 'admin':
        papers = Paper.query.all()
        users = User.query.all()
        return render_template('admin_dashboard.html', papers=papers, users=users)
    elif user.role == 'reviewer':
        reviews = Review.query.filter_by(reviewer_id=user_id).all()
        papers = Paper.query.filter_by(status='under_review').all()
        return render_template('reviewer_dashboard.html', reviews=reviews, papers=papers)
    else:
        papers = Paper.query.filter_by(author_id=user_id).all()
        return render_template('author_dashboard.html', papers=papers)



@app.route('/review/<int:paper_id>', methods=['GET', 'POST'])
def review_paper(paper_id):
    if 'user_id' not in session or session['role'] != 'reviewer':
        return redirect(url_for('login'))

    paper = Paper.query.get_or_404(paper_id)

    if request.method == 'POST':
        score = int(request.form['score'])
        comments = request.form['comments']

        review = Review(
            paper_id=paper_id,
            reviewer_id=session['user_id'],
            score=score,
            comments=comments
        )

        db.session.add(review)
        paper.status = 'under_review'
        db.session.commit()

        flash('评审意见提交成功')
        return redirect(url_for('dashboard'))

    return render_template('review.html', paper=paper)


@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin/assign_reviewer', methods=['POST'])
def assign_reviewer():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    paper_id = request.form['paper_id']
    reviewer_id = request.form['reviewer_id']

    paper = Paper.query.get_or_404(paper_id)
    paper.status = 'under_review'
    reviewer = User.query.get_or_404(reviewer_id)

    if reviewer.role != 'reviewer':
        reviewer.role = 'reviewer'

    db.session.commit()
    flash('评审人分配成功')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)