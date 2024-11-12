import subprocess
import streamlit as st
from ML_model import static
import sqlite3
import hashlib
import pefile
import os
import magic
import warnings
import yaml
import platform

warnings.filterwarnings('ignore')


def load_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

# Load configuration
config = load_config("E:/Final Project/config.yaml")
webapp_config = config['WEBAPP']

config = load_config(r"E:\Final Project\config.yaml")
sqlite_database = r"E:\Final Project\database.db"
exclusions = webapp_config['EXCLUSIONS']

# Set up database connection
connection = sqlite3.connect(sqlite_database)

# Set up magic for file type detection
if platform.system() == 'Windows':
    magic = magic.Magic('E:/Final Project/auxiliary/magic/magic.mgc') 

# Streamlit page configuration
st.set_page_config(layout="wide")
st.subheader("Malware Detection using Machine Learning")
#st.info("Code: https://github.com/mohamedbenchikh/MDML")

# File uploader widget
file = st.file_uploader("Upload File")


def compute_sha256(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def run_ssdeep_hash(file_path):
    # Generate ssdeep hash using subprocess
    result = subprocess.run([r"C:\msys64\usr\bin\ssdeep.exe", file_path], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        st.error("Error running ssdeep.")
        return None


def run_ssdeep_compare(hash1, hash2):
    # Compare ssdeep hashes
    result = subprocess.run([r"C:\msys64\usr\bin\ssdeep.exe", "-c", hash1, hash2], capture_output=True, text=True)
    if result.returncode == 0:
        try:
            similarity = int(result.stdout.strip())
            st.write(f"ssdeep comparison similarity: {similarity}%")
            return similarity
        except ValueError:
            st.error("Error parsing ssdeep comparison output.")
            return -1
    else:
        st.error("Error comparing ssdeep hashes.")
        return -1


def main():
    if file is not None:
        # Display uploaded file details
        file_details = {"filename": file.name, "filetype": file.type, "filesize": file.size}
        st.write(file_details)

        # Save uploaded file locally
        with open(file.name, 'wb') as outfile:
            outfile.write(file.read())

        # Determine file type with magic
        magic_file = magic.from_file(file.name)
        if magic_file.split()[0] in exclusions:
            st.markdown(f"<b>{file.name}</b> is {magic_file}", unsafe_allow_html=True)
            os.remove(file.name)
            return

        fileinfo = magic_file.split(',')[0]
        cursor = connection.cursor()
        sha256 = compute_sha256(file.name)
        ssdeep_hash = run_ssdeep_hash(file.name)

        message = f"Filename: <b>{file.name}</b><br>File info: <b>{fileinfo}</b><br>SHA256: <b>{sha256}</b><br>SSDEEP: <b>{ssdeep_hash}</b>"

        # Attempt to load PE file and extract imphash
        try:
            pe = pefile.PE(file.name)
            imphash = pe.get_imphash() or sha256  # Default to SHA256 if imphash is unavailable
            message += f"<br>imphash: <b>{imphash}</b>"

            st.write("Querying the database for existing signatures...")
            cursor.execute(
                f'SELECT ssdeep FROM signatures WHERE imphash = "{imphash}" OR sha256 = "{sha256}"'
            )
            db_entry = cursor.fetchone()

            if db_entry:
                ssdeep_hash_db = db_entry[0]
                similarity = run_ssdeep_compare(ssdeep_hash, ssdeep_hash_db)
                if similarity > 50:
                    st.write("Similar ssdeep hash found in database; retrieving classification.")
                    cursor.execute(
                        f'SELECT class, confidence FROM signatures WHERE imphash = "{imphash}" OR sha256 = "{sha256}"'
                    )
                    result = cursor.fetchone()
                else:
                    result = None
            else:
                result = None

        except Exception as e:
            st.write(f"Error processing PE file: {e}")
            result = None

        # Display file details
        with st.expander("File details"):
            st.markdown(message, unsafe_allow_html=True)

        # If no result, run static analysis model
        if not result:
            st.write("No matching entry in database; running ML model analysis.")
            result = static.process(file)

            if result:
                status, confidence = result
                st.write(f"Inserting new analysis result: {status}, {confidence}% confidence")
                cursor.execute(
                    f'INSERT INTO signatures (sha256, imphash, ssdeep, class, confidence) VALUES ("{sha256}", "{imphash}", "{ssdeep_hash}", "{status}", "{confidence}")'
                )
                connection.commit()

        # Display result
        if result:
            status, confidence = result
            color = "green" if status == "Benign" else "red"
            st.markdown(
                f"Source: <b>Database</b><br>Status: <font color='{color}'>{status}</font><br>Confidence: <b>{confidence}%</b>",
                unsafe_allow_html=True
            )
        else:
            st.error("Unable to classify the file.")

        # Clean up
        cursor.close()
        if pe:
            pe.close()
        os.remove(file.name)


if __name__ == '__main__':
    main()