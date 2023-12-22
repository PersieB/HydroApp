"""
Signup and Login Endpoints using Flask
Using the POST method with a JSON payload for security reasons. 

Example testing with curl in terminal below:

curl -X POST -H "Content-Type: application/json" -d '{"name":"Percy","email":"pbrown@gmail.com","phone":"+23333","password":"hydro"}' http://127.0.0.1:5000/signup

"""
import psycopg2
import bcrypt
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import jwt
import os
import uuid
from decouple import config

# Load environment variables from .env file
DB_NAME = config('DB_NAME')
DB_USER = config('DB_USER')
DB_PASSWORD = config('DB_PASSWORD')
DB_HOST = config('DB_HOST')
DB_PORT = config('DB_PORT')

app = Flask(__name__)
# Generate a secure random secret key
secret_key = os.urandom(32)
app.config['SECRET_KEY'] = secret_key


def hash_password(password):
    # Generate a random salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(input_password, stored_hashed_password):
    # Verify if the input password matches the stored hashed password
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password)

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        if request.headers.get('Content-Type') == 'application/json':
            data = request.get_json()

            # user data on form
            name = data.get('name')
            email = data.get('email')
            phone = data.get('phone')
            password = data.get('password')

            # Establishing the connection
            conn = psycopg2.connect(
                database=DB_NAME, user=DB_USER, password=DB_PASSWORD,
                host=DB_HOST, port=DB_PORT
            )
            conn.autocommit = True

            # Creating a cursor object using the cursor() method
            cursor = conn.cursor()

            # Checking if the user already exists
            check_user_sql = '''SELECT "Id" FROM "Users" WHERE "Email" = %s;'''
            cursor.execute(check_user_sql, (email,))

            existing_user = cursor.fetchone()

            if existing_user:
                return jsonify({'message': 'Already existing user.'}), 400
            
            else:
                # Hashing the password using bcrypt
                hashed_password_for_signup = hash_password(password)

                # Inserting a new user record
                # Generate a random user ID
                user_id = str(uuid.uuid4())
                insert_user_sql = '''
                    INSERT INTO "Users" ("Id", "Name", "Email", "PhoneNumber", "Password", "CreatedAt") 
                    VALUES (%s, %s, %s, %s, %s, %s)
                '''
                cursor.execute(insert_user_sql, (user_id,name, email, phone, hashed_password_for_signup.decode('utf-8'), datetime.now()))

                # Closing the connection
                conn.close()

                    # Generate a token for the new user
                token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=1)}, app.config['SECRET_KEY'], algorithm='HS256')

                return jsonify({'message': 'User created successfully.',  'token': token}), 201

    else:
        # oor show signup form
        return jsonify({'message': 'No submission yet'}), 201
    

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.headers.get('Content-Type') == 'application/json':
            data = request.get_json()

            # user data on form
            email = data.get('email')
            input_password_for_login = data.get('password')

            # Establishing the connection
            conn = psycopg2.connect(
                database=DB_NAME, user=DB_USER, password=DB_PASSWORD,
                host=DB_HOST, port=DB_PORT
            )
            conn.autocommit = True

            # Creating a cursor object using the cursor() method
            cursor = conn.cursor()

            # Checking if the user already exists
            check_user_sql = '''SELECT "Id", "Password" FROM "Users" WHERE "Email" = %s;'''
            cursor.execute(check_user_sql, (email,))

            existing_user = cursor.fetchone()

            if existing_user:
                # Verifying the password using bcrypt
                if verify_password(input_password_for_login, existing_user[1].encode('utf-8')):
                    token = jwt.encode({'user_id': existing_user[0], 'exp': datetime.utcnow() + timedelta(days=1)}, app.config['SECRET_KEY'], algorithm='HS256')

                    return jsonify({'message': 'Login successfully.',  'token': token}), 201
                
                else:
                    return jsonify({'message': 'Invalid password. Reset or try again.'}), 400
            
            else:
                return jsonify({'message': 'Login credentials invalid.'}), 400

    else:
        # show login page
        return jsonify({'message': 'No login yet'}), 201


if __name__ == '__main__':
    app.run(debug=True)
