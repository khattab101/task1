from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
import datetime
from functools import wraps
import os
import base64
import pyotp
import qrcode
from io import BytesIO
import logging
from contextlib import closing
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration from environment variables with defaults
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'infosec_api')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['TOKEN_EXPIRY_MINUTES'] = int(os.getenv('TOKEN_EXPIRY_MINUTES', 30))
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')

# Initialize MySQL
mysql = MySQL(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = pyjwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = data['id']
        except Exception as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated

def twofa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = pyjwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            if '2fa_verified' not in data or not data['2fa_verified']:
                return jsonify({'message': '2FA verification required!'}), 403
            request.user_id = data['id']
        except Exception as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        logger.info(f"Received Data: {data}")

        required_fields = ['name', 'username', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing fields'}), 400

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        secret = pyotp.random_base32()
        
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("INSERT INTO users (name, username, password, totp_secret) VALUES (%s, %s, %s, %s)",
                        (data['name'], data['username'], hashed_password, secret))
            mysql.connection.commit()
            user_id = cur.lastrowid

        totp = pyotp.totp.TOTP(secret).provisioning_uri(name=data['username'], issuer_name="Infosec API")
        img = qrcode.make(totp)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'message': 'User registered successfully',
            'qr_code': img_str,
            'secret': secret
        }), 201

    except Exception as e:
        logger.error(f"Error during signup: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/setup-2fa', methods=['GET'])
@token_required
def setup_2fa():
    try:
        user_id = request.user_id
        
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("SELECT username, totp_secret FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        if not user['totp_secret']:
            secret = pyotp.random_base32()
            with closing(mysql.connection.cursor()) as cur:
                cur.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (secret, user_id))
                mysql.connection.commit()
        else:
            secret = user['totp_secret']
        
        totp = pyotp.totp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name="Infosec API")
        img = qrcode.make(totp)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'qr_code': img_str,
            'secret': secret
        }), 200

    except Exception as e:
        logger.error(f"Error setting up 2FA: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/verify-2fa', methods=['POST'])
@token_required
def verify_2fa():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({'message': 'Missing verification code'}), 400

        user_id = request.user_id
        
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

        if not user or not user['totp_secret']:
            return jsonify({'message': '2FA not setup for this user'}), 400

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(data['code']):
            token = pyjwt.encode(
                {
                    'id': user_id, 
                    '2fa_verified': True,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=app.config['TOKEN_EXPIRY_MINUTES'])
                },
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({'token': token, 'message': '2FA verification successful'})
        else:
            return jsonify({'message': 'Invalid verification code'}), 401

    except Exception as e:
        logger.error(f"Error verifying 2FA: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        logger.info(f"Received Data: {data}")

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        with closing(mysql.connection.cursor()) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
            user = cur.fetchone()

        if not user:
            logger.error(f"User not found: {data['username']}")
            return jsonify({'message': 'Invalid username or password'}), 401

        if not check_password_hash(user['password'], data['password']):
            return jsonify({'message': 'Invalid username or password'}), 401

        if user['totp_secret']:
            token = pyjwt.encode(
                {'id': user['id'], '2fa_required': True, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)},
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({
                'token': token,
                'message': '2FA required',
                '2fa_required': True
            })
        else:
            token = pyjwt.encode(
                {'id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=app.config['TOKEN_EXPIRY_MINUTES'])},
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({'token': token, '2fa_required': False})

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/users/<int:id>', methods=['PUT'])
@token_required
@twofa_required
def update_user(id):
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        logger.info(f"Received Data: {data}")

        required_fields = ['name', 'username']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing fields'}), 400

        with closing(mysql.connection.cursor()) as cur:
            cur.execute("UPDATE users SET name=%s, username=%s WHERE id=%s", 
                        (data['name'], data['username'], id))
            mysql.connection.commit()

        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/products', methods=['POST'])
@token_required
@twofa_required
def add_product():
    try:
        data = request.json
        required_fields = ['pname', 'description', 'price', 'stock']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing fields'}), 400

        with closing(mysql.connection.cursor()) as cur:
            cur.execute("INSERT INTO products (pname, description, price, stock, created_at) VALUES (%s, %s, %s, %s, NOW())", 
                        (data['pname'], data['description'], data['price'], data['stock']))
            mysql.connection.commit()

        return jsonify({'message': 'Product added successfully'}), 201

    except Exception as e:
        logger.error(f"Error adding product: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/products', methods=['GET'])
@token_required
@twofa_required
def get_products():
    try:
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("SELECT * FROM products")
            products = cur.fetchall()

        return jsonify(products)

    except Exception as e:
        logger.error(f"Error fetching products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:pid>', methods=['GET'])
@token_required
@twofa_required
def get_product(pid):
    try:
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("SELECT * FROM products WHERE pid = %s", (pid,))
            product = cur.fetchone()

        if not product:
            return jsonify({'message': 'Product not found'}), 404

        return jsonify(product)

    except Exception as e:
        logger.error(f"Error fetching product: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:pid>', methods=['PUT'])
@token_required
@twofa_required
def update_product(pid):
    try:
        data = request.json
        required_fields = ['pname', 'description', 'price', 'stock']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing fields'}), 400

        with closing(mysql.connection.cursor()) as cur:
            cur.execute("UPDATE products SET pname=%s, description=%s, price=%s, stock=%s WHERE pid=%s", 
                        (data['pname'], data['description'], data['price'], data['stock'], pid))
            mysql.connection.commit()

        return jsonify({'message': 'Product updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating product: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:pid>', methods=['DELETE'])
@token_required
@twofa_required
def delete_product(pid):
    try:
        with closing(mysql.connection.cursor()) as cur:
            cur.execute("DELETE FROM products WHERE pid = %s", (pid,))
            mysql.connection.commit()

        return jsonify({'message': 'Product deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Error deleting product: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])
