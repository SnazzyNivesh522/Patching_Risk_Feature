import json
with open("/home/dev/Patching_Risk_Feature/nvd_data/cves/nvdcve-2.0-2025.json","r") as file:
    data=json.load(file)
    for d in data["vulnerabilities"]:
        if d["cve"]["id"]=="CVE-2025-8875":
            with open("cve_2025_8875","w") as f:
                json.dump(d,f)