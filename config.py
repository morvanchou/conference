# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Flask配置
SECRET_KEY = 'your-secret-key-here'  # 请更改为随机字符串
DEBUG = True

# 数据库配置
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'conference.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# 文件上传配置
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 增加到100MB
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# 添加额外的Flask配置
class Config:
    # 增加请求体大小限制
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    # 配置上传文件夹
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)