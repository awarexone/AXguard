"""Fail/authz fixture: get-by-id without ownership — expect FAIL or REVIEW_REQUIRED."""

from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)

DOCUMENTS = {
    "d1": {"id": "d1", "owner_id": "u1", "title": "alpha"},
    "d2": {"id": "d2", "owner_id": "u2", "title": "beta"},
}


@app.route("/documents/<doc_id>", methods=["GET"])
def get_document(doc_id: str):
    """Broken object-level authz — lookup by id alone."""
    # Authenticated? (header present) but no ownership check
    _ = request.headers.get("X-User-Id", "u1")
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"document": doc})
