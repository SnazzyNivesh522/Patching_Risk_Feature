from datetime import datetime, timedelta, timezone
import io
import os
import requests
import time
from config import Config
from database import get_session
import csv
import json
import zipfile


async def update_in_db(documents: list, collection_name: str):
    client = get_session()
    db = client[Config.MONGO_DB_NAME]
    collection = db[collection_name]

    for doc in documents:
        cve_id = doc.get("cveID")
        await collection.update_one({"cveID": cve_id}, {"$set": doc}, upsert=True)


async def load_all_df():
    response = requests.get(Config.KEV_JSON)
    kev_json = response.json().get("vulnerabilities")

    print("cisa kev's:", len(kev_json))
    await update_in_db(kev_json, "cisa_kev")

    response = requests.get(Config.EXPLOITDB_CSV)
    exploitdb_csv = list(
        csv.reader(response.content.decode("utf-8").splitlines(), delimiter=",")
    )
    exploitdb_json = []
    for value in exploitdb_csv[1:]:
        exploit = dict(zip(exploitdb_csv[0], value))
        
        exploit["cveID"] = exploit.pop("codes").split(";")[0].strip()
        
        exploitdb_json.append(exploit)
    print("exploits in exploit db:", len(exploitdb_json))
    await update_in_db(exploitdb_json, "exploitdb")

    response = requests.get(Config.METASPLOIT_JSON)
    metasploit_json = response.json()
    print(len(metasploit_json))
    metasploit__cve = []
    for m in metasploit_json:
        if "references" in metasploit_json[m]:
            cveID = [
                ref
                for ref in metasploit_json[m]["references"]
                if ref.startswith("CVE-")
            ]
            current_ms = {"cveID": cveID, **metasploit_json[m]}
            metasploit__cve.append(current_ms)
    print("final metasploits are :", len(metasploit__cve))
    await update_in_db(metasploit__cve, "metasploit")
    

    response = requests.get(Config.NUCLEI_JSON)
    nuclei_cve = []
    for nuclei in response.content.decode("utf-8").splitlines():
        current_nuclei = json.loads(nuclei)
        current_nuclei["cveID"] = current_nuclei.pop("ID")
        nuclei_cve.append(current_nuclei)

    print("Nuclei based cves found:", len(nuclei_cve))
    await update_in_db(nuclei_cve, "nuclei")


def download_cve_list():
    try:
        today_utc = datetime.now(timezone.utc)
        yesterday_utc = today_utc - timedelta(days=1)

        today_str = today_utc.strftime("%Y-%m-%d")
        yesterday_str = yesterday_utc.strftime("%Y-%m-%d")

        release_tag = f"cve_{today_str}_0000Z"
        filename = f"{yesterday_str}_all_CVEs_at_midnight.zip.zip"

        release_url = f"https://github.com/CVEProject/cvelistV5/releases/download/{release_tag}/{filename}"

        with requests.get(release_url, stream=True) as response:
            response.raise_for_status()
            with open(filename, "wb") as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
        print(
            f"\n✅ Success! File downloaded and saved to: {os.path.abspath(filename)}"
        )
        return filename
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")


def extract_nested_zip(outer_zip_path, extract_to_dir="cve_data"):
    try:
        if not os.path.exists(extract_to_dir):
            os.makedirs(extract_to_dir)
        with zipfile.ZipFile(outer_zip_path, "r") as outer_zip:
            inner_zip_info = None
            for inner_zip_name in outer_zip.namelist():
                if inner_zip_name.lower().endswith("cves.zip"):
                    inner_zip_info = inner_zip_name
            if inner_zip_info:
                inner_zip_content = outer_zip.read(inner_zip_info)
        with zipfile.ZipFile(io.BytesIO(inner_zip_content), "r") as inner_zip:
            inner_zip.extractall(extract_to_dir)
    except Exception as e:
        print(f"Error extracting nested zip: {e}")
    finally:
        if os.path.exists(outer_zip_path):
            os.remove(outer_zip_path)
        print(f"Nested zip extracted to {extract_to_dir} and outer zip removed.")
