import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    CVE_DIR="nvd_data/cves"
    MONGO_USER = os.getenv("MONGO_INITDB_ROOT_USERNAME")
    MONGO_PASS = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
    MONGO_DB_IP= os.getenv("MONGO_DB_IP")
    MONGO_CONN_STR = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_DB_IP}:27017/"
    MONGO_DB_NAME = "cve_metadata"
    KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NUCLEI_JSON = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    EXPLOITDB_CSV = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    METASPLOIT_JSON = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    GITHUB_POC = "https://poc-in-github.motikan2010.net/api/v1/?cve_id="
    EPSS_URL="https://api.first.org/data/v1/epss?cve="
