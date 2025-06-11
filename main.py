from script import load_all_metadata, download_cve_list, extract_nested_zip
import asyncio
import time

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(load_all_metadata())
    total_time = time.time() - start_time
    print(f"Total Time Taken:{total_time:.0f} seconds")

    start_time = time.time()
    zip_filename = download_cve_list()
    total_time = time.time() - start_time
    print(f"Total Time Taken to download CVE list: {total_time:.0f} seconds")
    print(f"Downloaded CVE list zip file: {zip_filename}")

    start_time = time.time()
    extract_nested_zip(zip_filename, extract_to_dir="cve_data")
    total_time = time.time() - start_time
    print(f"Total Time Taken to extract CVE list: {total_time:.0f} seconds")
