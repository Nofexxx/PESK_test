from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jti, get_jwt
from redis import Redis
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv()


#Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_secret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt_secret')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)


#extenshion
db = SQLAlchemy(app)
jwt = JWTManager(app)
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_client = Redis(host=redis_host, port=redis_port, decode_responses=True)


#user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')


BLACKLIST_PREFIX = 'blacklist:'
BLACKLIST_TTL_SECONDS = 60 * 60 * 24  # 1 день
WHITELIST_PREFIX = 'whitelist:'
WHITELIST_TTL_SECONDS = BLACKLIST_TTL_SECONDS


def add_token_to_whitelist(jti):
    redis_client.setex(f'{WHITELIST_PREFIX}{jti}', WHITELIST_TTL_SECONDS, 'true')

def add_token_to_blacklist(jti):
    redis_client.setex(f'{BLACKLIST_PREFIX}{jti}', BLACKLIST_TTL_SECONDS, 'true')


def is_token_revoked(jwt_payload):
    jti = jwt_payload['jti']
    in_blacklist = redis_client.get(f'{BLACKLIST_PREFIX}{jti}')
    in_whitelist = redis_client.get(f'{WHITELIST_PREFIX}{jti}')
    return in_blacklist is not None or in_whitelist is None


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    return is_token_revoked(jwt_payload)


#create db tables
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return jsonify({'message': 'Auth microservice is running'}), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not data:
        return jsonify({'error': 'Invalid or missing JSON'}), 400

    if not username or not password:
        return jsonify({'message': 'User name or password required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()


    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'User name or password required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid or missing JSON'}), 400

    access_token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
    refresh_token = create_refresh_token(identity=str(user.id))
    jti = get_jti(access_token)
    add_token_to_whitelist(jti)

    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    add_token_to_blacklist(jti)
    redis_client.delete(f'{WHITELIST_PREFIX}{jti}')
    return jsonify({'message': 'User logout successfully'}), 200


@app.route('/admin-only', methods=['GET'])
@jwt_required()
def admin_only():
    claims = get_jwt()

    if claims.get('role') != 'admin':
        return jsonify({'message': 'Not an admin'}), 403
    return jsonify({'message': 'Hello, admin'}), 200


@app.route('/shared-content', methods=['GET'])
@jwt_required()
def shared_content():
    claims = get_jwt()
    return jsonify({'message': f'Hello your role is {claims.get('role')}'}), 200
