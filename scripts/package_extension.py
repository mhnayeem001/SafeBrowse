import os
import zipfile

def package_extension():
    source_dir = "extension"
    output_dir = "release"
    os.makedirs(output_dir, exist_ok=True)
    zip_path = os.path.join(output_dir, "safebrowse-extension.zip")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, source_dir)
                zipf.write(full_path, rel_path)

    print(f"Successfully packaged Chrome extension to: {zip_path}")
    print(f"Archive size: {os.path.getsize(zip_path)} bytes")

if __name__ == "__main__":
    package_extension()
