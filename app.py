from flask import Flask, jsonify, request
from passlib.context import CryptContext
from uuid import uuid4
import os
import boto3
from boto3.dynamodb.conditions import Key


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
else:
    TABLE_USERS = os.environ['TABLE_USERS']
    dynamoClient = boto3.client('dynamodb')


@app.route('/users/<string:user_id>')
def get_user(user_id):
    resp = dynamoClient.get_item(
        TableName=TABLE_USERS,
        Key={
            'pk': {'S': user_id},
            'sk': {'S': 'USER'}
        }
    )
    item = resp.get('Item')
    if not item:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'userId': item.get('pk').get('S'),
        'name': item.get('name').get('S')
    })


@app.route('/users', methods=['POST'])
def create_user():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        return jsonify({'error': 'Please provide a email and password'}), 400

    passwd = pwd_context.encrypt(password)
    new_user = {
            'pk': {'S': uuid4().__str__()},
            'sk': {'S': 'USER'},
            'password': {'S': passwd},
            'email': {'S': email}
        }

    resp = dynamoClient.put_item(
        TableName=TABLE_USERS,
        Item=new_user
    )

    return jsonify({'message': 'User created', 'user': new_user})


@app.route('/users/login', methods=['POST'])
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        return jsonify({'error': 'Please provide a email and password'}), 400

    # passwd = pwd_context.encrypt(password)

    resp = dynamoClient.query(
        TableName=TABLE_USERS,
        IndexName='emailIdx',
        KeyConditionExpression = 'email = :email and sk = :sk',
        ExpressionAttributeValues={
            ':email' : {'S' : email},
            ':sk' : {'S': 'USER'}
        }
    )

    return jsonify({'message': 'ok', 'found': resp.get('Items')})
