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
    try:
        metrics = cve["metrics"] if isinstance(cve, dict) and "metrics" in cve else []
        for metric in metrics:
            cvss = None
            if isinstance(metric, dict):
                cvss = metric.get("cvssMetricV40") or metric.get("cvssMetricV31") or metric.get("cvssMetricV40") or metric.get("cvssMetricV2")
            if cvss and isinstance(cvss, dict):
                return (
                    cvss["baseScore"] if "baseScore" in cvss else "N/A",
                    cvss["baseSeverity"] if "baseSeverity" in cvss else "N/A",
                    cvss["vectorString"] if "vectorString" in cvss else "N/A",
                    cvss["version"] if "version" in cvss else "N/A",
                )
    except (TypeError, KeyError) as e:
        logging.debug(f"Error in extract_metrics: {e}")
    return ("N/A", "N/A", "N/A", "N/A")

def extract_description(cve: dict) -> str:
    try:
        if not isinstance(cve, dict) or "descriptions" not in cve:
            return ""
        return "\n".join(d["value"] for d in cve["descriptions"] if isinstance(d, dict) and "value" in d).strip()
    except (TypeError, KeyError) as e:
        logging.debug(f"Error in extract_description: {e}")
        return ""

def extract_weaknesses(cve: dict) -> list:
    try:
        if not isinstance(cve, dict) or "weaknesses" not in cve:
            return []
        return [
            desc["value"]
            for weak in cve["weaknesses"]
            for desc in weak["description"]
            if isinstance(weak, dict) and isinstance(desc, dict) and "value" in desc
        ]
    except (TypeError, KeyError) as e:
        logging.debug(f"Error in extract_weaknesses: {e}")
        return []

def extract_packages(cve: dict) -> list:
    try:
        if not isinstance(cve, dict) or "configurations" not in cve:
            return []
        cfg = cve["configurations"]
        if not cfg or not isinstance(cfg, list) or not cfg[0]:
            return []
        nodes = cfg[0]["nodes"] if isinstance(cfg[0], dict) and "nodes" in cfg[0] else []
        if not nodes or not isinstance(nodes, list) or not nodes[0]:
            return []
        return [
            cpe["criteria"]
            for cpe in nodes[0]["cpeMatch"]
            if isinstance(cpe, dict) and "criteria" in cpe
        ]
    except (TypeError, KeyError) as e:
        logging.debug(f"Error in extract_packages: {e}")
        return []

async def parse_and_store(json_path: str, collection) -> None:
    try:
        with open(json_path, "r", encoding="utf-8",errors='ignore') as f:
            data = json.load(f)
        if not isinstance(data, dict) or "vulnerabilities" not in data:
            logging.error(f"Invalid JSON structure in {json_path}")
            return
        vulnerabilities = data["vulnerabilities"]
        docs = []

        for item in vulnerabilities:
            if not isinstance(item, dict) or "cve" not in item:
                logging.debug(f"Skipping invalid CVE entry in {json_path}")
                continue
            c = item["cve"]
            base, severity, vector, version = extract_metrics(c)

            doc = {
                "cve_id": c["id"] if isinstance(c, dict) and "id" in c else "N/A",
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