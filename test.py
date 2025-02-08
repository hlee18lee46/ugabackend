import pymongo
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

try:
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client["hackncCluster"]
    print("Connected to MongoDB:", db.list_collection_names())
except pymongo.errors.ServerSelectionTimeoutError as e:
    print("MongoDB connection failed:", e)
