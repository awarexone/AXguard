from flask import Flask, request, jsonify
app = Flask(__name__)
USERS = {1: {"id": 1, "owner_id": 1, "data": "secret"}}

def check_ownership(user_id, resource):
    return resource.get("owner_id") == user_id

@app.get("/api/items/<int:item_id>")
def get_item(item_id):
    user_id = int(request.args.get("user_id", 0))
    item = USERS.get(item_id) or {"id": item_id, "owner_id": item_id, "data": "x"}
    if not check_ownership(user_id, item):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(item)
