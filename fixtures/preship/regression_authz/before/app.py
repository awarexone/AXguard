"""Regression before: ownership check present."""

from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)

DOCUMENTS = {
    "d1": {"id": "d1", "owner_id": "u1", "title": "alpha"},
    "d2": {"id": "d2", "owner_id": "u2", "title": "beta"},
}


def current_user_id() -> str:
    return request.headers.get("X-User-Id", "u1")


@app.route("/documents/<doc_id>", methods=["GET"])
def get_document(doc_id: str):
    user_id = current_user_id()
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "not_found"}), 404
    if doc["owner_id"] != user_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"document": doc})
