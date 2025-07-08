from flask import Flask, jsonify, request
from flask_cors import CORS
from config import Config
from helpers import (
    extract_cve_details,
    extract_priority,
    calculate_priority,
    calculate_epss,
)
from database import get_session

app = Flask(__name__)

# Secure CORS configuration
CORS(
    app,
    resources={
        r"/cves*": {
            "origins": ["*"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
        }
    },
)


@app.route("/cve/<string:cve_id>", methods=["GET"])
async def get_cve_details(cve_id: str):
    try:
        client = get_session()
        db = client[Config.MONGO_DB_NAME]
        collection = db["cves"]
        if not cve_id.startswith("CVE-"):
            return jsonify({"error": "Invalid CVE ID format."}), 400
        result = await collection.find_one({"cve_id": cve_id})
        if not result:
            return jsonify({"error": "CVE ID not found."}), 404

        return jsonify(extract_cve_details(result))
    except ValueError:
        return jsonify({"error": "Invalid CVE ID format."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


async def get_priority_details_for_cve(cve_id: str, db):
    public_info = await extract_priority(cve_id, db)
    epss = await calculate_epss(cve_id, public_info)
    priority = await calculate_priority(cve_id, epss, public_info)
    return {
        "cve_id": cve_id,
        **public_info,
        "epss": epss,
        "priority": priority,
    }


@app.route("/cve/<string:cve_id>/priority", methods=["GET"])
async def get_cve_priority(cve_id: str):
    client = get_session()
    db = client[Config.MONGO_DB_NAME]
    try:
        priority_details = await get_priority_details_for_cve(cve_id, db)
        return jsonify(priority_details)
    except Exception as e:
        return jsonify({"error": str(e), "cve_id": cve_id}), 500


@app.route("/cves/", methods=["POST"])
async def return_detail_mutliple_cves():
    try:
        data = request.get_json()
        if not data or "cve_ids" not in data:
            return jsonify({"error": "Missing 'cve_ids' in request body."}), 400

        cve_ids = data["cve_ids"]
        if not isinstance(cve_ids, list):
            return jsonify({"error": "'cve_ids' should be a list."}), 400

        client = get_session()
        db = client[Config.MONGO_DB_NAME]

        result = []
        for cve_id in cve_ids:
            try:
                priority_details = await get_priority_details_for_cve(cve_id, db)
                result.append(priority_details)
            except Exception as e:
                result.append({"cve_id": cve_id, "error": str(e)})

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
