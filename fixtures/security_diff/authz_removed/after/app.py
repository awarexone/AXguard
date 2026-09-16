from flask import Flask, request, jsonify
app = Flask(__name__)
USERS = {1: {"id": 1, "owner_id": 1, "data": "secret"}}

@app.get("/api/items/<int:item_id>")
def get_item(item_id):
    user_id = int(request.args.get("user_id", 0))
    item = USERS.get(item_id) or {"id": item_id, "owner_id": item_id, "data": "x"}
    # ownership check removed
    return jsonify(item)
