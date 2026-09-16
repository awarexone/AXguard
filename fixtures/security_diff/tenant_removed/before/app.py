from flask import Flask, request, jsonify
app = Flask(__name__)
DB = []

@app.get("/api/records")
def list_records():
    tenant_id = request.headers.get("X-Tenant-Id")
    return jsonify([r for r in DB if r.get("tenant_id") == tenant_id])
