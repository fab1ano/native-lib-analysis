#!/usr/bin/env python
import fnmatch
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import utils

TMP_PATH = Path("/tmp/apk-parse")
ERROR_LOG_PATH = Path("failed.txt")
logging.basicConfig(level=logging.INFO)


def extract_package_name(path):
    """Extracts the package name from the manifest file."""
    manifest_path = path / "AndroidManifest.xml"
    if manifest_path.is_file():
        # Parsing xml
        root = ET.parse(manifest_path).getroot()
        package_name = root.get("package")
        assert package_name, "Failed to extract package name"
        return package_name

    manifest_path = path / "unknown" / "manifest.json"
    if manifest_path.is_file():
        with open(manifest_path, "r") as f:
            data = json.load(f)
        return data["package_name"]

    raise ValueError(f"No valid manifest file available in {path}!")


def extract_libs(path):
    """Creates list of architectures and native libraries found in path."""
    libs = utils.find("*.so", path)
    result = {}
    for lib_path in libs:
        name = lib_path.name
        arch = lib_path.parent.name

        if arch not in result.keys():
            result[arch] = []

        result[arch].append(name)

        if lib_path.parent.parent.name != "lib":
            logging.warning(f"The native library {lib_path} is not in the 'lib' directory!")

    return result


def gather_data(path):
    data = {}
    data["package"] = extract_package_name(path)
    data["libs"] = extract_libs(path)
    return data


def decode_apk(apk_path, path_decoded):
    apktool_cmd = ["apktool", "d", "-s", "-f", "-o", path_decoded, apk_path]
    subprocess.check_output(apktool_cmd, stderr=subprocess.STDOUT)


def parse_apk(apk_path, out_path, rel_apk_path=None):
    """Extracts data from an apk and writes it as json to a file.

    This process requires two steps:
    1. Try apktool
    2. Try unzipping + apktool on unzipped apks
    """
    tmp_path = Path(tempfile.mkdtemp())
    tmp_path_decoded = tmp_path / "decoded"  # for output files of apktool
    tmp_path_unzipped = tmp_path / "unzipped"  # for output files of unzip

    if not apk_path.is_file():
        raise ValueError(f"Invalid input file: {apk_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path_decoded.mkdir(parents=True, exist_ok=True)

    failed = False
    data = {}

    # 1. Try apktool
    decode_apk(apk_path, tmp_path_decoded)
    try:
        data = gather_data(tmp_path_decoded)
    except ValueError as e:
        failed = True

    # 2. Try unzip + apktool
    if failed:
        logging.warning("Found a '.xapk' file? Trying to unzip and searching for apks.")
        shutil.rmtree(tmp_path_decoded, ignore_errors=True)
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(tmp_path_unzipped)

        apk_paths = [apk for apk in utils.find("*.apk", tmp_path_unzipped) if "config" not in str(apk)]
        assert len(apk_paths)==1, "Unable to find exactly one apk in this '.xapk'!"

        decode_apk(apk_paths[0], tmp_path_decoded)
        data = gather_data(tmp_path_decoded)

    # Add filename and size
    data["filename"] = str(rel_apk_path if rel_apk_path else apk_path)
    data["size"] = apk_path.stat().st_size

    # Write json to out_path
    with open(out_path, "w") as f:
        json.dump(data, f)

    # Delete tmp dirs
    shutil.rmtree(tmp_path_decoded, ignore_errors=True)
    shutil.rmtree(tmp_path_unzipped, ignore_errors=True)


def parse_folder(target, out_folder):
    """Invokes parse_apk for every apk in target."""
    if Path(target).is_dir():
        rel_apks = utils.find("*.apk", target)
        apk_folder = target
    else:
        rel_apks = [Path(target)]
        apk_folder = Path(target).parent

    for apk_path in rel_apks:

        rel_apk_path = apk_path.relative_to(apk_folder)
        logging.info(f"Processing {rel_apk_path}")

        out_path = out_folder / rel_apk_path.with_suffix(".json")

        if out_path.is_file():
            logging.info("Skipping this apk since the json file already exists")
            continue

        try:
            parse_apk(apk_path, out_path, rel_apk_path=rel_apk_path)
        except Exception as e:
            logging.error(f"Failed parsing {rel_apk_path}")
            print(e)
            traceback.print_exc(file=sys.stdout)
            with open(ERROR_LOG_PATH, "a") as f:
                f.write(str(rel_apk_path))
                f.write("\n")


def main():
    """Parses cmdline parameter and executes parse_folder."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <apk_folder> <out_folder>")
        sys.exit()
    parse_folder(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
