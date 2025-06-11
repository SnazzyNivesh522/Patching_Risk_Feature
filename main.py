from script import load_all_metadata, download_cve_list, extract_nested_zip
import asyncio
import time

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(load_all_metadata())
    print(f"Total Time Taken: {time.time() - start_time:.0f} seconds")

    start_time = time.time()
    zip_filename = download_cve_list()
    print(
        f"Total Time Taken to download CVE list: {time.time() - start_time:.0f} seconds"
    )
    print(f"Downloaded CVE list zip file: {zip_filename}")

    if zip_filename:
        start_time = time.time()
        extract_nested_zip(zip_filename, extract_to_dir="cve_data")
        print(
            f"Total Time Taken to extract CVE list: {time.time() - start_time:.0f} seconds"
        )
    else:
        print("⚠️ CVE list download failed. Extraction skipped.")
