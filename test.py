import requests
import csv

response = requests.get(
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
exploitdb_csv = list(
    csv.reader(response.content.decode("utf-8").splitlines(), delimiter=",")
)
exploitdb_json = []
count = 0
for value in exploitdb_csv[1:]:
    exploit = dict(zip(exploitdb_csv[0], value))

    exploit["cveID"] = exploit["codes"]
    for code in exploit["cveID"].split(";"):
        if code.startswith("CVE"):
            exploit["cveID"] = code

            count += 1
            continue
print("this much records contains cve id :", count)
