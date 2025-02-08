from flask import Flask, request, jsonify, render_template
from pymongo.mongo_client import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from flask_cors import CORS
import requests, json, fitz  # Handles JSON parsing

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

# Get OpenAI API Key from environment variable
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("Missing OPENAI_API_KEY environment variable. Please set it in your .env file.")

# Path to the uploaded PDF file
PDF_FILE_PATH = "uploaded.pdf"

def extract_text_from_pdf(pdf_path):
    """Extract text content from a PDF file."""
    try:
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text("text") + "\n"
        return text.strip() if text else "No text found in the PDF."
    except Exception as e:
        return f"Error reading PDF: {str(e)}"

@app.route("/process_pdf", methods=["POST"])
def process_pdf():
    """Process a locally stored PDF file and analyze it using OpenAI API."""
    if not os.path.exists(PDF_FILE_PATH):
        return jsonify({"error": "PDF file not found"}), 400

    # Extract text from PDF
    pdf_text = extract_text_from_pdf(PDF_FILE_PATH)

    # Define prompt for OpenAI
    prompt = (
        "Could you please return 20 JSON objects containing quizzes based on the provided PDF content? "
        "Ensure each quiz has the following format:\n\n"
        "[\n"
        "  {\n"
        '    "quiz_category": "Financial Ratios",\n'
        '    "financial_literacy_quiz": "What is the Return on Equity (ROE) for Q1 2024 if net income is $1,200 million and total shareholders\' equity is $59,053 million?",\n'
        '    "option1": "1.98%",\n'
        '    "option2": "2.03%",\n'
        '    "option3": "2.07%",\n'
        '    "option4": "2.11%",\n'
        '    "answer": "2.03%",\n'
        '    "created_at": "2025-02-08T12:00:00.000+00:00",\n'
        '    "last_updated": "2025-02-08T12:00:00.000+00:00"\n'
        "  },\n"
        "  ... (19 more questions in the same format)\n"
        "]\n\n"
        "Ensure the questions are relevant to the PDF content."
    )


    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": "gpt-3.5-turbo",  # Using GPT-3.5 to reduce costs
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 1000
    }

    # Send request to OpenAI API
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    response_data = response.json()

    if "choices" in response_data and len(response_data["choices"]) > 0:
        content_text = response_data["choices"][0]["message"]["content"]

        # Try parsing as JSON
        try:
            json_data = json.loads(content_text)
            return jsonify(json_data), 200
        except json.JSONDecodeError:
            return jsonify({"summary": content_text}), 200

    return jsonify({"error": "Failed to process PDF"}), 500

@app.route('/')
def home():
    return render_template("index.html")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)



