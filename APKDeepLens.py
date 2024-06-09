import os
import subprocess
import traceback
import sys
import logging
import argparse
import time
import xml.etree.ElementTree as ET
from static_tools import sensitive_info_extractor, scan_android_manifest
from report_gen import ReportGen
import shutil
from static_tools.mobsfscan import __version__
from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.formatters import cli
# from static_tools.mobsfscan.formatters import cli

"""
    Title:      APKDeepLens
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Modder:     Lider Roman
    Version:    1.0.3
    GitHub URL: https://github.com/Stormtrooperroman/APKDeepLens
"""

logging.basicConfig(level=logging.ERROR, format="%(message)s")

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Util:
    @staticmethod
    def mod_print(text_output, color):
        """
        Better mod print. It gives the line number, file name in which error occured. 
        """
        stack = traceback.extract_stack()
        filename, line_no, _, _ = stack[-2]
        formatted_message = f"{filename}:{line_no}: {text_output}"
        print(color + formatted_message + Colors.ENDC)

    @staticmethod
    def mod_log(text, color):
        logging.info(color + "{}".format(text) + Colors.ENDC)

    @staticmethod
    def print_logo():
        logo = f"""
{Colors.OKGREEN} ████  █████  ██  ██    ( )                  (_ )                           {Colors.ENDC}
{Colors.OKGREEN}██  ██ ██  ██ ██ ██    _| |  __     __  _ _   | |     __    ___    ___      {Colors.ENDC}
{Colors.OKGREEN}██████ █████  ████   /'_` | /'_`\\ /'_`\\( '_`\\ | |    /'_`\\/' _ `\\/',__)     {Colors.ENDC}
{Colors.OKGREEN}██  ██ ██     ██ ██ ( (_| |(  __/(  __/| (_) )| |__ (  __/| ( ) |\\__, \\     {Colors.ENDC}
{Colors.OKGREEN}██  ██ ██     ██  ██`\\__,_)`\\___)`\\___)| ,__/'(____/`\\___)(_) (_)(____/     {Colors.ENDC}
{Colors.OKGREEN}                                       | |                                  {Colors.ENDC}
{Colors.OKGREEN}                                       (_)                                  {Colors.ENDC}
{Colors.OKCYAN}                                              - Made By Stormtrooperroman{Colors.ENDC}
        """
        print(logo)

class AutoApkScanner:
    def __init__(self):
        pass

    @staticmethod
    def create_dir_to_extract(apk_file, extracted_path=None, force=False):
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file)
        resources_path = os.path.join(extracted_source_path, "resources")
        sources_path = os.path.join(extracted_source_path, "sources")

        if os.path.exists(extracted_source_path) and os.path.isdir(extracted_source_path) and \
           os.path.exists(resources_path) and os.path.isdir(resources_path) and \
           os.path.exists(sources_path) and os.path.isdir(sources_path):
            if force:
                shutil.rmtree(extracted_source_path)
                os.makedirs(extracted_source_path, exist_ok=True)
                Util.mod_log("[+] Creating new directory for extracting apk : " + extracted_source_path, Colors.OKCYAN)
                return {'result': 1, "path": extracted_source_path}
            else:
                Util.mod_log("[+] Source code for apk - {} Already extracted. Skipping this step.".format(apk_file), Colors.OKCYAN)
                return {'result': 0, "path": extracted_source_path}
        else:
            os.makedirs(extracted_source_path, exist_ok=True)
            Util.mod_log("[+] Creating new directory for extracting apk : " + extracted_source_path, Colors.OKCYAN)
            return {'result': 1, "path": extracted_source_path}

    def extract_source_code(self, apk_file, target_dir):
        Util.mod_log("[+] Extracting the source code to : "+target_dir, Colors.OKCYAN)
        
        is_windows = os.name == 'nt'
        jadx_executable = "jadx.bat" if is_windows else "jadx"
        jadx_path = os.path.join(os.getcwd(), "static_tools", "jadx", "bin", jadx_executable)
        output = subprocess.run([jadx_path, apk_file, "-d", target_dir])
        print(output)

    @staticmethod
    def return_abs_path(path):
        return os.path.abspath(path)

    @staticmethod
    def apk_exists(apk_filename):
        return os.path.isfile(apk_filename)

def parse_args():
    Util.print_logo()

    parser = argparse.ArgumentParser(
        description="{BOLD}{GREEN}APKDeepLens:{ENDC} Android security insights in full spectrum. ".format(BOLD=Colors.BOLD, GREEN=Colors.OKCYAN, ENDC=Colors.ENDC),
        epilog="For more information, visit our GitHub repository - https://github.com/Stormtrooperroman/APKDeepLens",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-a","--apk", metavar="APK", type=str, required=True,
                        help="Path to the APK file to be analyzed.")
    parser.add_argument("-v", "--version", action="version", version="APKDeepLens v1.0.3",
                        help="Display the version of APKDeepLens.")
    parser.add_argument("-S", "--source_code_path", metavar="APK", type=str,
                        help="Enter a valid path of extracted source for apk.")
    parser.add_argument("-r", "--report", choices=["json", "pdf", "html"], default="json",
                        help="Format of the report to be generated. Default is JSON.")
    parser.add_argument("-f", "--force", action='store_true',
                        help="Extracting apk if source code already extracted")
    parser.add_argument("-l", "--log_level", metavar="log level", help="Set the logging level")
    return parser.parse_args()

if __name__ == "__main__":
    try:
        args = parse_args()

        try:
            os.environ['VIRTUAL_ENV']
        except KeyError:
            Util.mod_log("[-] WARNING: Not inside virtualenv. Do source venv/bin/activate", Colors.FAIL)

        if not args.apk:
            Util.mod_log("[-] ERROR: Please provide the apk file using the -apk flag.", Colors.FAIL)
            exit(0)

        apk = args.apk

        def is_path_or_filename(apk):
            global apk_name, apk_path

            if os.sep in apk:
                apk_name = os.path.basename(apk)
                apk_path = apk
            else:
                apk_name = apk
                apk_path = apk
        
        is_path_or_filename(apk)

        results_dict = {
            "apk_name": apk_name,
            "package_name": "",
            "permission": "",
            "dangerous_permission": "",
            "manifest_analysis": "",
            "hardcoded_secrets": "",
            "mobsfscan": ""
        }

        obj_self = AutoApkScanner()
        apk_file_abs_path = obj_self.return_abs_path(apk_path)
        if not obj_self.apk_exists(apk_file_abs_path):
            Util.mod_log(f"[-] ERROR: {apk_file_abs_path} not found.", Colors.FAIL)
            exit(0)
        else:
            Util.mod_log(f"[+] {apk_file_abs_path} found!", Colors.OKGREEN)
        time.sleep(1)
        
        # Extracting source code
        target_dir = obj_self.create_dir_to_extract(apk_name, extracted_path=args.source_code_path if args.source_code_path else None, force=args.force)
        if target_dir["result"] == 1:
            obj_self.extract_source_code(apk_file_abs_path, target_dir["path"])

        extracted_apk_path = obj_self.return_abs_path(target_dir["path"])

        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name)
        manifest_results = scan_android_manifest.ScanAndroidManifest().extract_manifest_info(extracted_source_path)
        results_dict["package_name"] = manifest_results["package_name"]
        results_dict["android_version"] = manifest_results['platform_build_version_code']
        results_dict["permission"] = manifest_results["permissions"]
        results_dict["dangerous_permission"] = manifest_results["dangerous_permission"] 
        results_dict["manifest_analysis"] = {
            "activities": {
                "all": manifest_results["activities"],
                "exported": manifest_results["exported_activity"]
            },
            "services": {
                "all": manifest_results["services"],
                "exported": manifest_results["exported_service"]
            },
            "receivers": {
                "all": manifest_results["receivers"],
                "exported": manifest_results["exported_receiver"]
            },
            "providers": {
                "all": manifest_results["providers"],
                "exported": manifest_results["exported_provider"]
            }
        }
        
        # Extracting hardcoded secrets
        obj = sensitive_info_extractor.SensitiveInfoExtractor()
        Util.mod_log("[+] Reading all file paths ", Colors.OKCYAN)
        file_paths = obj.get_all_file_paths(extracted_apk_path)
        relative_to = extracted_apk_path
        Util.mod_log("[+] Extracting all hardcoded secrets ", Colors.OKCYAN)
        hardcoded_secrets_result = obj.extract_all_sensitive_info(file_paths, relative_to)
        results_dict["hardcoded_secrets"] = hardcoded_secrets_result

        Util.mod_log("[+] Extracting all insecure connections ", Colors.OKCYAN)
        all_file_path = obj.get_all_file_paths(extracted_apk_path)
        result = obj.extract_insecure_request_protocol(all_file_path)
        print(result)

        scanner = MobSFScan([extracted_apk_path], json=True)
        scan_results = scanner.scan()
        results_dict["mobsfscan"] = scan_results["results"]

        cli.cli_output(None, scan_results, __version__, 'fancy_grid')

        if args.report:
            extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name)
            res_path = os.path.join(extracted_source_path, "resources")
            source_path = os.path.join(extracted_source_path, "sources")

            android_manifest_path = os.path.join(res_path, "AndroidManifest.xml")
            etparse = ET.parse(android_manifest_path)
            manifest = etparse.getroot()
            for elem in manifest.iter():
                elem.attrib = {k.replace('{http://schemas.android.com/apk/res/android}', 'android:'): v for k, v in elem.attrib.items()}

            obj = ReportGen(apk_name, manifest, res_path, source_path)
            
        
            if args.report == "html":
                obj.generate_html_pdf_report(report_type="html", json_response=results_dict)
            elif args.report == "pdf":
                obj.generate_html_pdf_report(report_type="pdf", json_response=results_dict)
            elif args.report == "json":
                obj.generate_json_report(results_dict)
            else:
                Util.mod_print(f"[-] Invalid Report type argument provided", Colors.FAIL)

    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        line_number = exc_traceback.tb_lineno
        Util.mod_print(f"[-] {str(e)} at line {line_number}", Colors.FAIL)
        exit(0)
