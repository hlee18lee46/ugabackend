from flask import Flask, request, jsonify, render_template
from pymongo.mongo_client import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os, glob, re
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from flask_cors import CORS
import requests, json, fitz  # Handles JSON parsing
from datetime import datetime
from PIL import Image
import pytesseract

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
custom_quiz = db["custom_quiz"]
OUTPUT_JSON_FILE = "quizzes.json"


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
    #user_id = data.get("_id")
    

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Fetch user from database
    user = user_collection.find_one({"username": username})
    user_id = user["_id"]

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Create a JWT access token
    access_token = create_access_token(identity=username)
    return jsonify({"message": "Login successful", "token": access_token, "username": username, "user_id": str(user_id)}), 200

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

collectionQuiz_custom = db["custom_quiz"]  # Updated collection name

@app.route('/quiz_custom/categories', methods=['GET'])
def get_categories():
    """Fetch all quiz categories."""
    categories = collectionQuiz_custom.distinct("quiz_category")
    return jsonify({"categories": categories})

@app.route('/quiz_custom/<category>', methods=['GET'])
def get_quiz_by_category(category):
    """Fetch quiz questions by category."""
    quizzes = list(collectionQuiz_custom.find({"quiz_category": category}, {"_id": 0}))
    return jsonify(quizzes)

@app.route('/quiz_custom/answer', methods=['POST'])
def check_answer():
    """Validate if the selected answer is correct."""
    data = request.json
    question = data.get("question")
    selected_answer = data.get("answer")

    quiz = collectionQuiz_custom.find_one({"financial_literacy_quiz": question}, {"_id": 0, "answer": 1})
    
    if quiz:
        correct = quiz["answer"] == selected_answer
        return jsonify({"correct": correct, "message": "Correct!" if correct else "Wrong answer, try again."})
    return jsonify({"error": "Question not found"}), 404

collectionQuiz_truist= db["truist_quiz"]  # Updated collection name

@app.route('/quiz_custom/categories', methods=['GET'])
def get_categories():
    """Fetch all quiz categories."""
    categories = collectionQuiz_truist.distinct("quiz_category")
    return jsonify({"categories": categories})

@app.route('/quiz_custom/<category>', methods=['GET'])
def get_quiz_by_category(category):
    """Fetch quiz questions by category."""
    quizzes = list(collectionQuiz_truist.find({"quiz_category": category}, {"_id": 0}))
    return jsonify(quizzes)

@app.route('/quiz_custom/answer', methods=['POST'])
def check_answer():
    """Validate if the selected answer is correct."""
    data = request.json
    question = data.get("question")
    selected_answer = data.get("answer")

    quiz = collectionQuiz_truist.find_one({"financial_literacy_quiz": question}, {"_id": 0, "answer": 1})
    
    if quiz:
        correct = quiz["answer"] == selected_answer
        return jsonify({"correct": correct, "message": "Correct!" if correct else "Wrong answer, try again."})
    return jsonify({"error": "Question not found"}), 404


# Get OpenAI API Key from environment variable
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("Missing OPENAI_API_KEY environment variable. Please set it in your .env file.")

# Path to the uploaded PDF file
def get_uploaded_file():
    """Finds the most recent 'uploaded.*' file in the uploads directory."""
    files = glob.glob(os.path.join(UPLOAD_FOLDER, "uploaded.*"))  # Find files with "uploaded.*"
    return files[0] if files else None  # Return the first match

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

def get_latest_uploaded_file():
    """Returns the latest uploaded file (any format) in the uploads folder."""
    files = [f for f in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
    
    if not files:
        return None  # No files found

    # Get the most recently modified file
    latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(UPLOAD_FOLDER, f)))
    
    return os.path.join(UPLOAD_FOLDER, latest_file)


@app.route("/process_uploaded_file", methods=["POST"])
def process_uploaded_file():
    """Processes the latest uploaded file, retrieves quizzes, and stores them in MongoDB."""
    file_path = get_latest_uploaded_file()

    if not file_path:
        return jsonify({"error": "No uploaded file found in uploads folder"}), 400

    # Extract text from the latest uploaded file
    extracted_text = extract_text_from_file(file_path)

    # Define OpenAI Prompt
    prompt = (
        "Return only the array of Generated 10 quiz questions in valid JSON format based on the following PDF content. "
        "No trailing markdown or anything but the array of JSON. The example would be quiz_category (Income Calculation or Financial Ratios, Balance Sheet Calculation), financial_literacy_quiz (Question, example is What is the Return on Equity (ROE) for Q1 2024?, option1 (for example, 1.98%), option2: (for example, 2.03%), option3: (for example, 2.07%), option4 (for example, 2.11%), answer (for example, 2.03%), created_at (for example, 2025-02-08T12:00:00.000+00:00),last_updated (for example, 2025-02-08T12:00:00.000+00:00)"
        "The response should be a valid JSON array with no extra text, please don't include ."
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "Return only a valid JSON array of financial literacy quiz questions."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 2000
    }

    # Send request to OpenAI API
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    response_data = response.json()

    if "choices" in response_data and len(response_data["choices"]) > 0:
        content_text = response_data["choices"][0]["message"]["content"]

        # **Fix: Remove Markdown-style JSON formatting**
        content_text = content_text.replace("```json", "").replace("```", "").strip()

        # **Use regex to extract valid JSON array**
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content_text, re.DOTALL)

        if json_match:
            extracted_json = json_match.group(0)

            # **Fix: Remove trailing commas that might cause parsing errors**
            extracted_json = re.sub(r',\s*}', '}', extracted_json)  # Fix }, issues
            extracted_json = re.sub(r',\s*\]', ']', extracted_json)  # Fix ,] issues

            try:
                quiz_data = json.loads(extracted_json)  # Convert string to JSON

                # **Insert into MongoDB**
                if isinstance(quiz_data, list):  # Ensure it's a list of quiz objects
                    custom_quiz.insert_many(quiz_data)
                    return jsonify({"message": "Quiz data stored successfully", "quiz_count": len(quiz_data)}), 200
                
                return jsonify({"error": "Invalid JSON format received", "raw_response": extracted_json}), 500

            except json.JSONDecodeError as e:
                return jsonify({"error": "Failed to parse JSON response", "details": str(e), "raw_response": extracted_json}), 500

        return jsonify({"error": "Invalid JSON format received", "raw_response": content_text}), 500

    return jsonify({"error": "Failed to process file"}), 500



def extract_text_from_file(file_path):
    """Extracts text from different file types (PDF, TXT, Images)."""
    file_extension = os.path.splitext(file_path)[-1].lower()

    if file_extension == ".pdf":
        try:
            doc = fitz.open(file_path)
            text = "\n".join([page.get_text("text") for page in doc])
            return text.strip() if text else "Error: Could not extract text from the PDF."
        except Exception as e:
            return f"Error reading PDF: {str(e)}"

    elif file_extension == ".txt":
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read().strip()
        except Exception as e:
            return f"Error reading TXT file: {str(e)}"

    elif file_extension in [".jpg", ".jpeg", ".png"]:
        try:
            image = Image.open(file_path)
            return pytesseract.image_to_string(image)
        except Exception as e:
            return f"Error extracting text from image: {str(e)}"

    else:
        return "Error: Unsupported file format."
    
PDF_FILE_PATH = "uploads/uploaded.pdf"

@app.route("/process_pdf", methods=["POST"])
def process_pdf():
    """Processes a locally stored PDF and retrieves quizzes from OpenAI."""
    if not os.path.exists(PDF_FILE_PATH):
        return jsonify({"error": "PDF file not found"}), 400

    # Extract text from PDF
    pdf_text = extract_text_from_pdf(PDF_FILE_PATH)

    # OpenAI Prompt
    prompt = (
        "Return only the array of Generated 10 quiz questions in valid JSON format based on the following PDF content. "
        "No trailing markdown or anything but the array of JSON. The example would be quiz_category (Income Calculation or Financial Ratios, Balance Sheet Calculation), financial_literacy_quiz (Question, example is What is the Return on Equity (ROE) for Q1 2024?, option1 (for example, 1.98%), option2: (for example, 2.03%), option3: (for example, 2.07%), option4 (for example, 2.11%), answer (for example, 2.03%), created_at (for example, 2025-02-08T12:00:00.000+00:00),last_updated (for example, 2025-02-08T12:00:00.000+00:00)"
        "The response should be a valid JSON array with no extra text, please don't include ."
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "Ensure the response is a JSON array with 10 quiz objects."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1500
    }

    # Send request to OpenAI API
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    response_data = response.json()

    if "choices" in response_data and len(response_data["choices"]) > 0:
        content_text = response_data["choices"][0]["message"]["content"].strip()

        # **Fix: Remove Markdown-style JSON formatting**
        content_text = content_text.replace("```json", "").replace("```", "").strip()

        # Use regex to find JSON inside the response
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content_text, re.DOTALL)

        if json_match:
            extracted_json = json_match.group(0)  # Extract matched JSON
            try:
                quiz_data = json.loads(extracted_json)  # Convert string to JSON
                                # **Save JSON to a file**
                with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as json_file:
                    json.dump(quiz_data, json_file, indent=4)


                if isinstance(quiz_data, list):  # Ensure it's a list of quiz objects
                    custom_quiz.insert_many(quiz_data)
                    return jsonify({"message": "Quiz data stored successfully", "quiz_count": len(quiz_data)}), 200
                
                return jsonify({"error": "Invalid JSON format received", "raw_response": extracted_json}), 500


                return jsonify(quiz_data), 200
            except json.JSONDecodeError:
                return jsonify({"error": "Failed to parse JSON response", "raw_response": extracted_json}), 500

        return jsonify({"error": "Invalid JSON format received", "raw_response": content_text}), 500

    return jsonify({"error": "Failed to process PDF"}), 500

@app.route("/store_saved_quizzes", methods=["POST"])
def store_saved_quizzes():
    """Reads quizzes.json and inserts data into MongoDB."""
    if not os.path.exists(OUTPUT_JSON_FILE):
        return jsonify({"error": "No quizzes.json file found. Please generate quizzes first."}), 400

    try:
        # Read quizzes from JSON file
        with open(OUTPUT_JSON_FILE, "r", encoding="utf-8") as json_file:
            quiz_data = json.load(json_file)

        if not isinstance(quiz_data, list):
            return jsonify({"error": "Invalid JSON format in quizzes.json"}), 500

        # Insert into MongoDB
        custom_quiz.insert_many(quiz_data)

        return jsonify({
            "message": "Quiz data stored successfully",
            "quiz_count": len(quiz_data)
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to insert into MongoDB", "details": str(e)}), 500


# Define Upload Folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure upload directory exists
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def extract_text_from_pdf(pdf_path):
    """Extracts text from a PDF file."""
    try:
        doc = fitz.open(pdf_path)
        text = "\n".join(page.get_text("text") for page in doc)
        return text.strip() if text else "No text found in the PDF."
    except Exception as e:
        return f"Error reading PDF: {str(e)}"

def clear_uploads_folder():
    """Deletes all files in the uploads folder before saving a new file."""
    files = glob.glob(os.path.join(UPLOAD_FOLDER, "*"))  # Get all files in the folder
    for file in files:
        os.remove(file)  # Delete each file

@app.route("/upload_pdf", methods=["POST"])
def upload_pdf():
    """Handles file upload, deletes old files, and saves as 'uploaded.<extension>'."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Clear all old files before saving the new one
    clear_uploads_folder()

    # Extract the file extension
    file_ext = os.path.splitext(file.filename)[1]  # Gets ".pdf", ".txt", etc.
    new_filename = f"uploaded{file_ext}"  # Always name it "uploaded.<ext>"

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
    file.save(file_path)  # Save file with new name

    return jsonify({"message": "File uploaded successfully", "saved_as": new_filename, "file_path": file_path})

@app.route('/')
def home():
    return render_template("index.html")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)



