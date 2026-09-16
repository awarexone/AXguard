from flask import Flask, request, jsonify
app = Flask(__name__)
DB = []

@app.get("/api/records")
def list_records():
    # tenant filter removed
    return jsonify(DB)
