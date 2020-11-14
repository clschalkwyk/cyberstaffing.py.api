from flask import Flask, jsonify, request
import os
import boto3

app = Flask(__name__)


IS_OFFLINE = os.environ['IS_OFFLINE']

if IS_OFFLINE == 'True':
    # TABLE_USERS = UsersTable os.environ['TABLE_USERS']
    TABLE_USERS = 'UsersTable-dev'
    dynamoClient = boto3.client(
        'dynamodb',
        region_name='localhost',
        endpoint_url='http://localhost:8000'
    )
else:
    print("Running online")
    TABLE_USERS = os.environ['TABLE_USERS']
    dynamoClient= boto3.client('dynamodb')

@app.route('/')
def hello():
    return jsonify(os.environ)

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
        return jsonify({'error' : 'User not found'}), 404

    return jsonify({
        'userId': item.get('pk').get('S'),
        'name': item.get('name').get('S')
    })

@app.route('/users', methods=['POST'])
def create_user():
    user_id = request.json.get('userId')
    name = request.json.get('name')
    if not user_id or not name:
        return jsonify({'error': 'Please provide a name and userId'}), 400

    resp = dynamoClient.put_item(
        TableName=TABLE_USERS,
        Item={
            'pk': {'S' : user_id},
            'sk': {'S': 'USER'},
            'name': {'S': name}
        }
    )
