import json
import httpx
from config import Config

async def extract_description(cve_data: dict) -> str:
    if (
        cve_data is None
        or "containers" not in cve_data
        or "cna" not in cve_data["containers"]
    ):
        return ""
    descriptions = cve_data["containers"]["cna"].get("descriptions", [])
    return "\n".join(desc.get("value", "") for desc in descriptions)

def extract_metrics(cve_data: dict) -> list:
    metrics = ["N/A", "N/A", "N/A", "N/A"]
    if (
        cve_data is None
        or "containers" not in cve_data
        or "cna" not in cve_data["containers"]
    ):
        return metrics

    cna = cve_data["containers"]["cna"]
    metrics_json = cna.get("metrics", [])

    for metric in metrics_json:
        cvss_data = (
            metric.get("cvssV4_0")
            or metric.get("cvssV3_1")
            or metric.get("cvssV3_0")
            or metric.get("cvssV3")
        )
        if cvss_data and cvss_data.get("baseScore"):
            return [
                cvss_data.get("baseScore", "N/A"),
                cvss_data.get("baseSeverity", "N/A"),
                cvss_data.get("vectorString", "N/A"),
                cvss_data.get("version", "N/A"),
            ]

    for adp_entry in cve_data["containers"].get("adp", []):
        for metric in adp_entry.get("metrics", []):
            cvss_data = (
                metric.get("cvssV4_0")
                or metric.get("cvssV3_1")
                or metric.get("cvssV3_0")
                or metric.get("cvssV3")
            )
            if cvss_data and cvss_data.get("baseScore"):
                return [
                    cvss_data.get("baseScore", "N/A"),
                    cvss_data.get("baseSeverity", "N/A"),
                    cvss_data.get("vectorString", "N/A"),
                    cvss_data.get("version", "N/A"),
                ]
    return metrics

async def read_cve_json_file(filename: str):
    try:
        with open(filename, "r") as file:
            cve_data = json.load(file)
            base_score, base_severity, vector, version = extract_metrics(cve_data)
            description = await extract_description(cve_data)
            return {
                "vulnerability.id": cve_data.get("cveMetadata", {}).get("cveId"),
                "vulnerability.description": description,
                "vulnerability.score.version": version,
                "vulnerability.score.base": base_score,
                "vulnerability.severity": base_severity,
                "vulnerability.cvss.vector": vector,
            }
    except FileNotFoundError:
        return {"error": "CVE file not found."}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format."}
    except Exception as e:
        return {"error": str(e)}

async def extract_priority(cve_id: str, db):
    cisa_kev = db["cisa_kev"]
    exploitdb = db["exploitdb"]
    metasploit = db["metasploit"]
    nuclei = db["nuclei"]

    async def extract_github_poc():
        url = f"{Config.GITHUB_POC}{cve_id}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=10.0)
                response.raise_for_status()
                data = response.json()
                return [poc.get("html_url") for poc in data.get("pocs", [])]
        except Exception as e:
            return [f"Error fetching GitHub POCs: {str(e)}"]

    async def extract_cisa_kev():
        doc = await cisa_kev.find_one({"cveID": cve_id})
        if doc:
            return {
                "date_added": doc.get("dateAdded"),
                "due_date": doc.get("dueDate"),
                "ransomware_usage": doc.get("knownRansomwareCampaignUse"),
                "extra_details": doc.get("notes"),
                "cwes": doc.get("cwes"),
                "solution": doc.get("requiredAction"),
                "vendor": doc.get("vendorProject"),
                "product": doc.get("product")
            }
        return {}

    async def extract_exploitdb():
        doc = await exploitdb.find_one({"cveID": cve_id})
        if doc:
            return {
                "file": doc.get("file"),
                "platform": doc.get("platform"),
                "description": doc.get("description"),
                "author": doc.get("author")
            }
        return {}

    async def extract_metasploit():
        doc = await metasploit.find_one({"cveID": cve_id})
        if doc:
            return {
                "title": doc.get("title"),
                "path": doc.get("path"),
                "rank": doc.get("rank"),
                "type": doc.get("type"),
                "check": doc.get("check"),
                "description": doc.get("description"),
                "module_name": doc.get("module_name")
            }
        return {}

    async def extract_nuclei():
        doc = await nuclei.find_one({"cveID": cve_id})
        if doc:
            return {
                "template_id": doc.get("template_id"),
                "template_url": doc.get("template_url"),
                "severity": doc.get("severity"),
                "description": doc.get("description"),
                "author": doc.get("author"),
                "tags": doc.get("tags"),
                "matched_at": doc.get("matched_at")
            }
        return {}

    # Run all extraction tasks concurrently for better performance
    from asyncio import gather
    kev, edb, metasploit_data, nuclei_data, github_pocs = await gather(
        extract_cisa_kev(),
        extract_exploitdb(),
        extract_metasploit(),
        extract_nuclei(),
        extract_github_poc()
    )

    return {
        "kev": kev,
        "exploitdb": edb,
        "metasploit": metasploit_data,
        "nuclei": nuclei_data,
        "github_poc": github_pocs
    }