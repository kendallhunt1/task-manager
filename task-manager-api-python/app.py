from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask_jwt_extended import jwt_required, get_jwt_identity
import boto3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SECRET_KEY'] = 'userToken'
s3 = boto3.resource('s3', aws_access_key_id='AKIAU7WM7FLMK2LOT4E2', aws_secret_access_key='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', region_name='us-east-1')
db = SQLAlchemy(app)

# Allow CORS for all origins and methods
CORS(app, resources={r"/*": {"origins": "*"}})

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            # Do not serialize the password for security reasons
        }

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='todo')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'user_id': self.user_id
        }

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the user already exists in the database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists"}), 409

    # Hash the password before storing it in the database
    hashed_password = generate_password_hash(password)

    # Create a new user and add it to the database
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Log the contents of the User table
    users = User.query.all()
    for user in users:
        print(f"User ID: {user.id}, Username: {user.username}")

    return jsonify({"message": "Signup successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the user exists in the database
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    # Generate a token for the user
    token = jwt.encode(
        {
            'username': user.username,
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        },
        'userToken',
        algorithm='HS256'
    )

    return jsonify(token), 200

@app.route('/tasks/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')
    user_id = data.get('userId')

    # Create a new task and add it to the database
    new_task = Task(title=title, description=description, status=status, user_id=user_id)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({"message": "Task created successfully", "task": new_task.serialize()}), 201

@app.route('/get-user-info', methods=['GET', 'OPTIONS'])
def get_user_info():
    # Set the CORS headers for preflight response
    response = jsonify({'message': 'Preflight Request Handled'})
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'

    if request.method == 'OPTIONS':
        # Handle the preflight request for CORS
        return response, 200

    # Get the token from the request headers
    token = request.headers.get('Authorization')

    if token is None or not token.startswith('Bearer '):
        return jsonify({"message": "Authorization token not provided"}), 401

    try:
        # Decode the token to get the user information
        decoded_token = jwt.decode(token.split(" ")[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token.get('username')  # Modify this line to use 'username' as the key for user_id

        # Assuming you have a user_id, you can fetch the user information from the database
        # For example:
        user = User.query.filter_by(username=username).first()  # Modify this line to query by username
        if user:
            return jsonify(user.serialize()), 200
        else:
            return jsonify({"message": "User not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Add CORS headers in the response for the GET request
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'

    return response, 200

@app.route('/tasks', methods=['GET'])
def get_tasks_by_user_id():
    # Get the user ID from the query parameter
    user_id = request.args.get('user_id')

    if user_id is None:
        return jsonify({"message": "User ID not provided in the query parameter"}), 400

    try:
        # Fetch tasks for the specified user ID from the database
        tasks = Task.query.filter_by(user_id=user_id).all()
        return jsonify([task.serialize() for task in tasks]), 200

    except Exception as e:
        return jsonify({"message": "Error fetching tasks: " + str(e)}), 500

    # except jwt.ExpiredSignatureError:
    #     return jsonify({"message": "Token has expired"}), 401
    # except jwt.InvalidTokenError:
    #     return jsonify({"message": "Invalid token"}), 401

@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')

    # Find the task by its ID
    task = Task.query.get(task_id)

    if not task:
        return jsonify({"message": "Task not found"}), 404

    # Update the task attributes if the fields are provided
    if title is not None:
        task.title = title
    if description is not None:
        task.description = description
    if status is not None:
        task.status = status

    # Save the changes to the database
    db.session.commit()

    return jsonify({"message": "Task updated successfully", "task": task.serialize()}), 200

@app.route('/tasks/<int:task_id>/status', methods=['PUT', 'OPTIONS'])
def update_task_status(task_id):
    if request.method == 'OPTIONS':
        # Set the CORS headers for the preflight response
        response = jsonify({'message': 'Preflight Request Handled'})
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'PUT, OPTIONS'
        return response, 200

    task = Task.query.get(task_id)

    if task is None:
        return jsonify({"message": "Task not found"}), 404

    data = request.get_json()
    status = data.get('status')

    # Update the status of the task
    task.status = status

    db.session.commit()

    return jsonify(task.serialize()), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    # Find the task by its ID
    task = Task.query.get(task_id)

    if not task:
        return jsonify({"message": "Task not found"}), 404

    # Delete the task from the database
    db.session.delete(task)
    db.session.commit()

    return jsonify({"message": "Task deleted successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)
