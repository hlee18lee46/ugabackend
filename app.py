from flask import Flask, request, jsonify, render_template
from pymongo.mongo_client import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from flask_cors import CORS

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "your_secret_key"  # Change this to a secure key
jwt = JWTManager(app)

# MongoDB Connection
uri = os.getenv("MONGO_URI")
client = MongoClient(uri)
db = client['hackncCluster']
user_collection = db['users']

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Check if username exists
    if user_collection.find_one({"username": username}):
        return jsonify({"error": "Username already exists"}), 409

    # Hash the password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    user_collection.insert_one({
        "username": username,
        "password": hashed_password
    })

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Fetch user from database
    user = user_collection.find_one({"username": username})

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Create a JWT access token
    access_token = create_access_token(identity=username)
    return jsonify({"message": "Login successful", "token": access_token}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({"message": "This is a protected route!"})

collectionQuiz = db["beginner_quiz"]  # Updated collection name

@app.route('/quiz/categories', methods=['GET'])
def get_categories():
    """Fetch all quiz categories."""
    categories = collectionQuiz.distinct("quiz_category")
    return jsonify({"categories": categories})

@app.route('/quiz/<category>', methods=['GET'])
def get_quiz_by_category(category):
    """Fetch quiz questions by category."""
    quizzes = list(collectionQuiz.find({"quiz_category": category}, {"_id": 0}))
    return jsonify(quizzes)

@app.route('/quiz/answer', methods=['POST'])
def check_answer():
    """Validate if the selected answer is correct."""
    data = request.json
    question = data.get("question")
    selected_answer = data.get("answer")

    quiz = collectionQuiz.find_one({"financial_literacy_quiz": question}, {"_id": 0, "answer": 1})
    
    if quiz:
        correct = quiz["answer"] == selected_answer
        return jsonify({"correct": correct, "message": "Correct!" if correct else "Wrong answer, try again."})
    return jsonify({"error": "Question not found"}), 404

@app.route('/')
def home():
    return render_template("index.html")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)



