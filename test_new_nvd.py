import asyncio
import os
import time
import json
import zipfile
import logging
from datetime import date
import httpx
from motor.motor_asyncio import AsyncIOMotorClient
from config import Config

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="nvd_data.log", level=logging.INFO, format=LOG_FORMAT)

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "nvd"
COLLECTION_NAME = "cve_data"

# Download NVD CVE feed
async def download_nvd_data(year: int, output_dir: str) -> str | None:
    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0/"
    zip_name = f"nvdcve-2.0-{year}.json.zip"
    zip_path = os.path.join(output_dir, zip_name)
    json_output = os.path.join(output_dir, f"nvdcve-2.0-{year}.json")

    try:
        logging.info(f"Downloading NVD data for {year}...")
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}{zip_name}")
            resp.raise_for_status()
            with open(zip_path, "wb") as f:
                f.write(resp.content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            zf.extractall(output_dir)

        os.remove(zip_path)

        if names:
            extracted = os.path.join(output_dir, names[0])
            if extracted != json_output:
                os.replace(extracted, json_output)

        logging.info(f"Extracted JSON for {year} at {json_output}")
        return json_output

    except Exception as e:
        logging.error(f"Failed to process year {year}: {e}")
        return None

def extract_metrics(cve: dict) -> tuple:
    for metric in cve["metrics"]:  # Line 59: Replaced .get("metrics", []) with ["metrics"]
        cvss = metric["cvssV4_0"] or metric["cvssV3_1"] or metric["cvssV3"]  # Replaced .get() with []
        if cvss:
            return (
                cvss["baseScore"],  # Replaced .get("baseScore", "N/A") with ["baseScore"]
                cvss["baseSeverity"],  # Replaced .get("baseSeverity", "N/A") with ["baseSeverity"]
                cvss["vectorString"],  # Replaced .get("vectorString", "N/A") with ["vectorString"]
                cvss["version"],  # Replaced .get("version", "N/A") with ["version"]
            )
    return ("N/A", "N/A", "N/A", "N/A")

def extract_description(cve: dict) -> str:
    return "\n".join(d["value"] for d in cve["descriptions"]).strip()  # Replaced .get() with []

def extract_weaknesses(cve: dict) -> list:
    return [
        desc["value"]
        for weak in cve["weaknesses"]  # Replaced .get("weaknesses", []) with ["weaknesses"]
        for desc in weak["description"]  # Replaced .get("description", []) with ["description"]
        if "value" in desc
    ]

def extract_packages(cve: dict) -> list:
    cfg = cve["configurations"]  # Line 83: Replaced .get("configurations", []) with ["configurations"]
    if cfg:
        nodes = cfg[0]["nodes"]  # Replaced .get("nodes", []) with ["nodes"]
        if nodes:
            return [
                cpe["criteria"] for cpe in nodes[0]["cpeMatch"]  # Replaced .get("criteria", "cpe:*") and .get("cpeMatch", []) with []
            ]
    return []

async def parse_and_store(json_path: str, collection) -> None:
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(type(data))
        print()
        vulnerabilities = data["vulnerabilities"]
        docs = []

        for item in vulnerabilities:
            c = item["cve"]  # Line 104: Replaced .get("cve", {}) with ["cve"]
            base, severity, vector, version = extract_metrics(c)

            doc = {
                "cve_id": c["id"],  # Line 108: Replaced .get("id", "N/A") with ["id"]
                "description": extract_description(c),
                "cvss": {
                    "version": version,
                    "baseScore": base,
                    "severity": severity,
                    "vectorString": vector,
                },
                "weaknesses": extract_weaknesses(c),
                "packages": extract_packages(c),
            }
            docs.append(doc)

        if docs:
            await collection.insert_many(docs)
            logging.info(
                f"Inserted {len(docs)} records from {os.path.basename(json_path)}"
            )
        else:
            logging.warning(f"No valid CVEs found in {json_path}")

    except Exception as e:
        logging.error(f"Error parsing {json_path}: {e}")

async def main():
    start = time.time()
    base_dir = getattr(Config, "CVE_DIR", "nvd_data/cves")
    os.makedirs(base_dir, exist_ok=True)

    client = AsyncIOMotorClient(Config.MONGO_CONN_STR)
    db = client[Config.MONGO_DB_NAME]
    collection = db["cves"]

    years = range(2002, date.today().year + 1)
    tasks = [download_nvd_data(y, base_dir) for y in years]
    paths = await asyncio.gather(*tasks)

    for path in filter(None, paths):
        await parse_and_store(path, collection)

    logging.info(f"All data inserted in {time.time() - start:.2f}s")
    client.close()

if __name__ == "__main__":
    asyncio.run(main())