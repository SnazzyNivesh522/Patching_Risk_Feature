import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    MONGO_USER = os.getenv("MONGO_INITDB_ROOT_USERNAME")
    MONGO_PASS = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
    MONGO_CONN_STR = f"mongodb://{MONGO_USER}:{MONGO_PASS}@172.19.0.2:27017/"
    MONGO_DB_NAME = "cve_metadata"
    KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NUCLEI_JSON = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    EXPLOITDB_CSV = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    METASPLOIT_JSON = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    GITHUB_POC = "https://poc-in-github.motikan2010.net/api/v1/?cve_id="
