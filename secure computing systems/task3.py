import os
import sys
import hashlib
import shutil
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# -----------------------------
# CONFIGURATION
# -----------------------------

QUARANTINE_DIR = "QUARANTINE_VAULT"

# Known malicious signatures
KNOWN_BAD_HASHES = [
    "f092fe684eaf7dcb74e8aca867faa5b3306c60b300410042a84bd4baf1f94051"
]

# -----------------------------
# SAFE HASHING (CHUNKED)
# -----------------------------
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)  # SAFE MEMORY HANDLING
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        print(f"[ERROR] Hashing failed: {e}")
        return None


# -----------------------------
# QUARANTINE SYSTEM
# -----------------------------
def quarantine_file(file_path):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        destination = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
        shutil.move(file_path, destination)

        print(f"[QUARANTINE] File moved to: {destination}")

    except Exception as e:
        print(f"[ERROR] Quarantine failed: {e}")


# -----------------------------
# EXIF FORENSICS MODULE
# -----------------------------
def extract_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()

        if not exif_data:
            print("[FORENSICS] No EXIF metadata found.")
            return

        gps_data = {}

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)

            if tag == "GPSInfo":
                for key in value:
                    gps_tag = GPSTAGS.get(key, key)
                    gps_data[gps_tag] = value[key]

        if gps_data:
            print("[FORENSICS] GPS Metadata Found:")
            for k, v in gps_data.items():
                print(f"  {k}: {v}")
        else:
            print("[FORENSICS] No GPS coordinates found.")

    except Exception as e:
        print(f"[FORENSICS ERROR] {e}")


# -----------------------------
# MAIN ANALYSIS ENGINE
# -----------------------------
def analyze_file(file_path):

    print(f"\n[SCAN] Analyzing: {file_path}")

    # Validate file exists
    if not os.path.exists(file_path):
        print("[ERROR] File does not exist.")
        return

    # 1. Generate SHA-256 hash
    file_hash = calculate_sha256(file_path)

    if not file_hash:
        return

    print(f"[HASH] SHA-256: {file_hash}")

    # 2. Signature-based detection
    if file_hash in KNOWN_BAD_HASHES:
        print("[ALERT] Malware detected based on signature match!")
        quarantine_file(file_path)
        return

    print("[OK] File is clean based on signature check.")

    # 3. EXIF forensic extraction (only images)
    if file_path.lower().endswith((".jpg", ".jpeg", ".png")):
        extract_exif(file_path)

if __name__ == "__main__":

    print("=== TASK 3 MALWARE ANALYSIS TOOL STARTED ===")

    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        target_file = input("Enter file path to analyze: ").strip()

    analyze_file(target_file)
