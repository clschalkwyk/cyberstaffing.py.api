from flask import Flask, jsonify, request
from passlib.context import CryptContext
from uuid import uuid4
from functools import wraps
import os
import boto3
import jwt
from datetime import datetime, timedelta

pwd_context = CryptContext(
    schemes=['pbkdf2_sha256'],
    default='pbkdf2_sha256',
    pbkdf2_sha256__default_rounds=30000
)

app = Flask(__name__)

IS_OFFLINE = os.environ.get('IS_OFFLINE')

if IS_OFFLINE == 'True':
    # TABLE_USERS = UsersTable os.environ['TABLE_USERS']
    TABLE_USERS = 'UsersTable-dev'
    dynamoClient = boto3.client(
        'dynamodb',
        region_name='localhost',
        endpoint_url='http://localhost:8000'
    )
    jwt_secret = "xxxxxx"
else:
    TABLE_USERS = os.environ['TABLE_USERS']
    jwt_secret = os.environ['JWT_SECRET']
    dynamoClient = boto3.client('dynamodb')


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'error': 'Access Denied'}), 401

        try:
            data = jwt.decode(token, jwt_secret)
            current_user = data
        except:
            return jsonify({'error': 'Access Denied'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/users/me', methods=['GET'])
@jwt_required
def get_user(current_user):
    return jsonify(current_user)


@app.route('/users', methods=['POST'])
def create_user():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        return jsonify({'error': 'Please provide a email and password'}), 400

    try:

        resp = dynamoClient.query(
            TableName=TABLE_USERS,
            IndexName='emailIdx',
            KeyConditionExpression='email = :email and sk = :sk',
            ExpressionAttributeValues={
                ':email': {'S': email},
                ':sk': {'S': 'USER'}
            }
        )
        if len(resp.get('Items')) == 0:
            passwd = pwd_context.hash(password)
            new_user = {
                'pk': {'S': uuid4().__str__()},
                'sk': {'S': 'USER'},
                'password': {'S': passwd},
                'email': {'S': email}
            }
            dynamoClient.put_item(
                TableName=TABLE_USERS,
                Item=new_user
            )

            return jsonify({'message': 'User created', 'status': 200}), 200
        else:
            return jsonify({'error': 'Account exists'}), 500
    except:
        return jsonify({'error': 'Error creating account'}), 500


@app.route('/users/login', methods=['POST'])
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        return jsonify({'error': 'Please provide a email and password'}), 400

    resp = dynamoClient.query(
        TableName=TABLE_USERS,
        IndexName='emailIdx',
        KeyConditionExpression='email = :email and sk = :sk',
        ExpressionAttributeValues={
            ':email': {'S': email},
            ':sk': {'S': 'USER'}
        }
    )
    if len(resp.get('Items')) == 1:
        found = resp.get('Items')[0]
        if pwd_context.verify(password, found['password']['S']):
            future:datetime = datetime.now() + timedelta(minutes=5)
            payload = {
                'userId': found['pk']['S'],
                'email': found['email']['S'],
                'expires': future.__str__()
            }
            encoded = jwt.encode(payload, jwt_secret).decode('utf8')
            return jsonify({'token': encoded})

    return jsonify({'error': 'Unauthorized'}), 401
