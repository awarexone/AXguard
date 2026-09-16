from flask import Flask, request, jsonify
from services.policy import check_ownership
app = Flask(__name__)

@app.get("/api/items/<int:item_id>")
def get_item(item_id):
    user_id = int(request.args.get("user_id", 0))
    item = {"id": item_id, "owner_id": 1}
    if not check_ownership(user_id, item):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(item)
