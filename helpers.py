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
                "product": doc.get("product"),
            }
        return {}

    async def extract_exploitdb():
        doc = await exploitdb.find_one({"cveID": cve_id})
        if doc:
            return {
                "file": doc.get("file"),
                "platform": doc.get("platform"),
                "description": doc.get("description"),
                "author": doc.get("author"),
            }
        return {}

    async def extract_metasploit():
        paragraph = "The Metasploit module offers the following actions:"
        doc = await metasploit.find_one({"cveID": cve_id})
        if doc:
            return {
                "description": doc.get("description"),
                "exploit": doc.get("path"),
                "name": doc.get("name"),
                "title": doc.get("title"),
                "rank": doc.get("rank"),
                "actions": "The Metasploit module offers the following actions: "
                + "; ".join(
                    f"the {action['name']} action to {action['description'].lower()}"
                    for action in doc.get("actions", [])
                ),
            }
        return {}

    async def extract_nuclei():
        doc = await nuclei.find_one({"cveID": cve_id})
        if doc:
            return {
                "file": doc.get("file_path"),
                "name": doc.get("Info").get("Name"),
                "description": doc.get("Info").get("Description"),
                "classification": doc.get("Info").get("Classification"),
            }
        return {}

    # Run all extraction tasks concurrently for better performance
    from asyncio import gather

    kev, edb, metasploit_data, nuclei_data, github_pocs = await gather(
        extract_cisa_kev(),
        extract_exploitdb(),
        extract_metasploit(),
        extract_nuclei(),
        extract_github_poc(),
    )

    return {
        "kev": kev,
        "exploitdb": edb,
        "metasploit": metasploit_data,
        "nuclei": nuclei_data,
        "github_poc": github_pocs,
    }


async def calculate_epss(cve_id: str, public_info: dict) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{Config.EPSS_URL}{cve_id}")
            response.raise_for_status()
            data = response.json()
            epss_data = data.get("data", [])[0]
            return {
                "score": epss_data.get("epss"),
                "percentile": epss_data.get("percentile"),
            }

    except Exception as e:
        return [f"Error fetching EPSS data: {str(e)}"]


async def calculate_priority(cve_id: str, epss: dict, public_info: dict):
    # Default Priority (Unknown)
    priority = {
        "level": "P7",
        "label": "N/A",
        "criteria": "Unknown",
        "sla": "No Public/EPSS/KEV info",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            )
            response.raise_for_status()
            data = response.json()

            # Navigate safely to metrics
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                cvss_score = 0.0

            metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})

            # Attempt to get CVSS v3.1 score first
            if "cvssMetricV31" in metrics:
                cvss_score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
            elif "cvssMetricV30" in metrics:
                cvss_score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
            elif "cvssMetricV2" in metrics:
                cvss_score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
            else:
                cvss_score = 0.0

    except (httpx.HTTPError, KeyError, ValueError, TypeError, IndexError):
        cvss_score = 0.0

    try:
        epss_score = float(epss.get("epss", 0))
    except (ValueError, TypeError):
        epss_score = 0.0

    is_kev = bool(public_info.get("kev"))

    exploit_available = (
        public_info.get("exploitdb")
        or public_info.get("github_poc")
        or public_info.get("metasploit")
        or public_info.get("nuclei")
    )

    # P1 – Critical: KEV-listed + public exploit available
    if is_kev and exploit_available:
        return {
            "level": "P1",
            "label": "Critical",
            "criteria": "KEV-listed + public exploit available",
            "sla": "Fix in 24 hrs",
        }

    # P2 – High: KEV-listed only
    if is_kev:
        return {
            "level": "P2",
            "label": "High",
            "criteria": "KEV-listed only",
            "sla": "Fix in 72 hrs",
        }

    # P3 – Elevated: CVSS ≥ 7 and EPSS ≥ 0.36
    if cvss_score >= 7 and epss_score >= 0.36:
        return {
            "level": "P3",
            "label": "Elevated",
            "criteria": "CVSS ≥ 7 and EPSS ≥ 0.36",
            "sla": "Fix in 5 days",
        }

    # P4 – Moderate: CVSS ≥ 7 and EPSS < 0.36
    if cvss_score >= 7 and epss_score < 0.36:
        return {
            "level": "P4",
            "label": "Moderate",
            "criteria": "CVSS ≥ 7 and EPSS < 0.36",
            "sla": "Fix in 10 days",
        }

    # P5 – Low: CVSS < 7 and EPSS ≥ 0.36
    if cvss_score < 7 and epss_score >= 0.36:
        return {
            "level": "P5",
            "label": "Low",
            "criteria": "CVSS < 7 and EPSS ≥ 0.36",
            "sla": "Fix in 30 days",
        }

    # P6 – Informational: CVSS < 7 and EPSS < 0.36
    if cvss_score < 7 and epss_score < 0.36:
        return {
            "level": "P6",
            "label": "Informational",
            "criteria": "CVSS < 7 and EPSS < 0.36",
            "sla": "Fix when possible or monitor",
        }

    # Default fallback (P7 – Unknown)
    return priority
