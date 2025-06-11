from flask import Flask, jsonify
from config import Config
from helpers import read_cve_json_file,extract_priority
from database import get_session
import requests
app = Flask(__name__)

@app.route("/cve/<string:cve_id>", methods=["GET"])
def get_cve_details(cve_id: str):
    try:
        year, num = cve_id.split("-")[1:]
        num = int(num)
        cve_file = f"{Config.CVE_DIR}/{year}/{int(num / 1000)}xxx/{cve_id}.json"
        cve_details = read_cve_json_file(cve_file)
        return jsonify(cve_details)
    except ValueError:
        return jsonify({"error": "Invalid CVE ID format."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cve/<string:cve_id>/priority", methods=["GET"])
def get_cve_priority(cve_id: str):
    client = get_session()
    db = client[Config.MONGO_DB_NAME]
    return jsonify(extract_priority(cve_id,db))

