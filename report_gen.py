import os
import subprocess
import re
import json
import datetime
import logging
from html import escape
from weasyprint import HTML, CSS
logging.basicConfig(level=logging.DEBUG, format="%(message)s")

"""
    Title:      APKDeepLens
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Modder:     Lider Roman
    Version:    1.0.3
    GitHub URL: https://github.com/Stormtrooperroman/APKDeepLens
"""

class Util:
    '''
    A static class for which contain some useful variables and methods
    '''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def mod_print(text_output, color):
        print(color + f"{text_output}" + Util.ENDC)

    def mod_log(text, color):
        logging.info(color + f"{text}" + Util.ENDC)


def remove_spaces(lines):
    min_space = min(len(line) - len(line.lstrip()) for line in lines if line.strip()) if lines else 0
    return [line[min_space:] if line.strip() else line for line in lines]


class ReportGen(object):

    def __init__(self, apk_name, manifest, res_path, source_path, template_path = "report_template.html"):
        """
        Defining few important variables which are used throughout the class.
        """
        self.apk_name = apk_name
        self.manifest = manifest
        self.res_path = res_path
        self.source_path = source_path

    def format_table(self, rule_id, details):
        severity_colors = {'error': 'error', 'warning': 'warning', 'info': 'info'}
        items = {'rule_id': rule_id, 'metadata': ''}
        severity = details['metadata']['severity'].lower()
        items['color'] = severity_colors.get(severity, 'info')
        for meta, value in details['metadata'].items():
            if meta == 'id':
                continue
            meta_format = meta.upper().replace('_', '')
            items["metadata"] += f"""
            <div class="resp-table-row">
                <div class="table-body-cell cell-left">
                    {meta_format}
                </div>
                <div class="table-body-cell cell-right">
                    {value}
                </div>
            </div>
            """
        files = details.get('files')
        if files:
            fstore = """
            <div class="resp-table-row">
                <div class="table-body-cell cell-left">
                    FILES
                </div>
                <div class="resp-table files-width">
            """
            for match in files:
                file_path = match['file_path']
                position = match['match_position']
                pos = f'{position[0]} - {position[1]}'
                fstore += f"""
                <div class="resp-table-body border-files {items['color']}">
                    <div class="resp-table-row">
                        <div class="table-body-cell cell-left">
                            File Path
                        </div>
                        <div class="table-body-cell cell-right">
                            {file_path}
                        </div>
                    </div>
                    <div class="resp-table-row">
                        <div class="table-body-cell cell-left">
                            Match Position
                        </div>
                        <div class="table-body-cell cell-right">
                            {pos}
                        </div>
                    </div>
                """
                lines = match.get('match_lines')
                line = (lines[0] if lines[0] == lines[1]
                        else f'{lines[0]}: {lines[1]}')
                fstore += f"""
                <div class="resp-table-row">
                    <div class="table-body-cell cell-left">
                        Line Number(s)
                    </div>
                    <div class="table-body-cell cell-right">
                        {line}
                    </div>
                </div>
                """
                match_string = match['match_string'].split("\n")
                if len(match_string) > 1:
                    match_string = '\n'.join(remove_spaces(match_string))
                else:
                    match_string = match_string[0].strip()
                match_string = f'<p class="match_string">{escape(match_string)}</p>'
                fstore += f"""
                    <div class="resp-table-row">
                        <div class="table-body-cell cell-left">
                            Match String
                        </div>
                        <div class="table-body-cell cell-right">
                            {match_string}
                        </div>
                    </div>
                </div>
                """
            fstore += """
                </div> 
            </div>
            """
            items["files"] = fstore
        
  
        info = self.render_template('mobsfscan_template.html', items)
        return info

    def render_template(self, template_name, datas, escape=False):
        """
        This method is used to render the template and relevant html data.

        """
        try:
            t_templates_str = {
                'report_template.html': self.load_template("report_template.html"),
                "mobsfscan_template.html": self.load_template("mobsfscan_template.html"),
            }
            render = t_templates_str.get(template_name, "")
            if not render:
                Util.mod_log(f"[-] ERROR: Template {template_name} not found.", Util.FAIL)
                return ""

            for k, v in datas.items():
                if isinstance(v, list):
                    v = self.list_to_html(v)
                render = re.sub(r'{{\s*' + re.escape(k) + r'\s*}}', v.replace('\\', '\\\\'), render)
            
            render = re.sub(r'{{\s*\w*\s*}}', "", render)
            return render

        except Exception as e:
            Util.mod_log(f"[-] ERROR in render_template: {str(e)}", Util.FAIL)
            return ""

    def list_to_html(self, list_items):
        """
        This method is used to covert list to unordered list in html
        """
        try:
            if not isinstance(list_items, list):
                Util.mod_log("[-] ERROR: The provided input is not a list.", Util.FAIL)
                return ""
            items = [f"<li>{perm}</li>" for perm in list_items]
            return "<ul>" + "\n".join(items) + "</ul>"
        
        except Exception as e:
            Util.mod_log(f"[-] ERROR in list_to_html: {str(e)}", Util.FAIL)
            return ""


    def grenerate_html_report(self, report, html_report_path):
        """
        This method is used to generate a final html report which can be later converted to pdf
        """
        try:
            with open(html_report_path, 'w') as fp:
                fp.write(report)
            print("report generated")
        
        except Exception as e:
            Util.mod_log(f"[-] ERROR in generate_html_report: {str(e)}", Util.FAIL)

    def load_template(self, template_path):
        """
        read of the template.
        """
        try:
            with open(os.path.join('templates', template_path), 'r') as f:
                return f.read()
        except FileNotFoundError:
            Util.mod_log(f"[-] ERROR: Template {template_path} not found.", Util.FAIL)
        except Exception as e:
            Util.mod_log(f"[-] ERROR in load_template: {str(e)}", Util.FAIL)
        return ""

    def load_style(self, report_type):
        try:
            with open(f"templates/{report_type}_style.css") as f:
                return f.read()
        except Exception as e:
            Util.mod_log(f"[-] ERROR in load_style: {str(e)}", Util.FAIL)
            return ""

 # TODO rewrite this using semgrep

    # def grep_keyword(self, keyword):
    #     """
    #     This function is used to read keyword dict and run the grep commands on the extracted android source code.

    #     """
    #     output = ''

    #     """
    #     This dictionary stores the keywords to search with the grep command.
    #     Grep is much much faster than re.
    #     ToDo -
    #     - Add more search keywords
    #     - move entire project to use grep.
    #     """
    #     keyword_search_dict = {
    #         'external_call': [
    #             '([^a-zA-Z0-9](OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)[^a-zA-Z0-9])',
    #             r'(@(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)\()',
    #         ],
    #         'intent': ['(new Intent|new android\\.content\\.Intent|PendingIntent|sendBroadcast|sendOrderedBroadcast|startActivity|resolveActivity|createChooser|startService|bindService|registerReceiver)'],
    #         'internal_storage': ['(createTempFile|SQLiteDatabase|openOrCreateDatabase|execSQL|rawQuery)'],
    #         'external_storage': ['(EXTERNAL_STORAGE|EXTERNAL_CONTENT|getExternal)'],
    #     }
    #     if not keyword in keyword_search_dict:
    #         return ""

    #     for regexp in keyword_search_dict[keyword]:
    #         cmd = 'cd "' + self.res_path + '" ; grep -ErIn "' + regexp + '" "' + self.source_path + '" 2>/dev/null'
    #         #Eren yeager
    #         try:
    #             o = subprocess.check_output( cmd, shell=True ).decode('utf-8')
    #         except Exception as e:
    #             print(str(e))
    #             continue

    #         output = output + self.add_html_tag( o.strip(), regexp )

    #     return output

    # def add_html_tag(self, grep_result, regexp):
    #     """
    #     This method is used add the html tags to grep output to color the output for better presentation
    #     """
    #     try:
    #         output = ''
    #         for grep in grep_result.split("\n"):
    #             tmp = grep.split(':')
    #             if len(tmp) < 3:  # Ensure there are enough components in the split result
    #                 continue
    #             filepath, line, content = tmp[0], tmp[1], ':'.join(tmp[2:])
    #             content = re.sub(regexp, 'ABRACADABRA1\\1ABRACADABRA2', content)
    #             output += self.render_template('grep_lines.html', {'filepath': filepath, 'line': line, 'content': content}, True)
    #             output = output.replace('ABRACADABRA1', '<span class="grep_keyword">').replace('ABRACADABRA2', '</span>')
    #         return output

    #     except Exception as e:
    #         Util.mod_log(f"[-] ERROR in add_html_tag: {str(e)}", Util.FAIL)
    #         return ""

    def get_build_information(self):
        """
        This method is used to get build information from android manifest.xml.
        """
        try:
            version = self.manifest.attrib.get('platformBuildVersionCode',
                                               self.manifest.attrib.get('compileSdkVersion', '?'))
            return version
        
        except Exception as e:
            Util.mod_log(f"[-] ERROR in get_build_information: {str(e)}", Util.FAIL)
            return "?"

    def extract_permissions(self, manifest):
        """
        This method is used to extract permissions from the android manifest.xml.
        """
        try:
            permissions = []
            for permission_elem in self.manifest.findall('.//uses-permission'):
                permission_name = permission_elem.attrib.get('android:name')
                if permission_name:
                    permissions.append(permission_name)
            return permissions
        
        except Exception as e:
            Util.mod_log(f"[-] ERROR in extract_permissions: {str(e)}", Util.FAIL)
            return []

    def extract_dangerous_permissions(self, manifest):
        """
        This method is used to extracts dangerous permissions from the android  manifest.xml.
        """
        permissions = []
        try:
            for permission_elem in self.manifest.findall('.//uses-permission'):
                permission_name = permission_elem.attrib.get('android:name')
                dangerous_permission_list = [
                    "android.permission.READ_CALENDAR",
                    "android.permission.WRITE_CALENDAR",
                    "android.permission.CAMERA",
                    "android.permission.READ_CONTACTS",
                    "android.permission.WRITE_CONTACTS",
                    "android.permission.GET_ACCOUNTS",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.READ_PHONE_NUMBERS",
                    "android.permission.CALL_PHONE",
                    "android.permission.ANSWER_PHONE_CALLS",
                    "android.permission.READ_CALL_LOG",
                    "android.permission.WRITE_CALL_LOG",
                    "android.permission.ADD_VOICEMAIL",
                    "android.permission.USE_SIP",
                    "android.permission.PROCESS_OUTGOING_CALLS",
                    "android.permission.BODY_SENSORS",
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_WAP_PUSH",
                    "android.permission.RECEIVE_MMS",
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                    "android.permission.READ_HISTORY_BOOKMARKS",
                    "android.permission.WRITE_HISTORY_BOOKMARKS",
                    "android.permission.INSTALL_PACKAGES",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.READ_LOGS",
                    "android.permission.CHANGE_WIFI_STATE",
                    "android.permission.DISABLE_KEYGUARD",
                    "android.permission.GET_TASKS",
                    "android.permission.BLUETOOTH",
                    "android.permission.CHANGE_NETWORK_STATE",
                    "android.permission.ACCESS_WIFI_STATE",
                ]
                if permission_name:
                    if permission_name in dangerous_permission_list:
                        permissions.append(permission_name)
            return permissions
        except Exception as e:
            Util.mod_log(f"[-] ERROR in extract_dangerous_permissions: {str(e)}", Util.FAIL)
            return []

    def convert_html_to_pdf(self, html_file, pdf_name):
        """
        Convert an HTML file to a PDF.
        """

        # write content from html report to pdf
        html = HTML(html_file)
        css = CSS(string='@page { size: A4; margin-left: 0.5cm }')
        html.write_pdf(pdf_name, stylesheets=[css])
    
    def clean_apk_name(self, apk_name):
        """
        This function removes 'com' and 'apk' parts from the apk_name if they exist.
        """
        cleaned_name = re.sub(r'(\.com|\.apk)', '', apk_name)
        return cleaned_name

    def generate_json_report(self, json_response):
        """
        This function generates the json report based on the json output
        """
        clean_apk_name = self.clean_apk_name(self.apk_name)
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        json_report_path = os.path.join(reports_dir, f"report_{clean_apk_name}.json")

        try:
            with open(json_report_path, 'w') as json_file:
                json.dump(json_response, json_file, indent=4)
            Util.mod_print(f"[+] Generated JSON report - {json_report_path}", Util.OKCYAN)
        except IOError as e:
            Util.mod_log(f"[-] ERROR in generate_json_report: {str(e)}", Util.FAIL)


    def generate_html_pdf_report(self, report_type, json_response):
        """
        This the function generates an html and pdf report using functions mentioned in report_gen.py
        """

        try:
            # Creating object for report generation module.

            manifest = self.manifest
            res_path = self.res_path
            source_path = self.source_path
            apk_name = json_response["apk_name"]

            permissions  = json_response["permission"]
            dangerous_permission = json_response["dangerous_permission"]

            html_dict = {}
            # html_dict['build'] = obj.get_build_information()
            html_dict['package_name'] = json_response["package_name"]
            html_dict['android_version'] = json_response["android_version"]
            html_dict['date'] = datetime.datetime.today().strftime('%d/%m/%Y')
            html_dict['permissions'] = permissions
            html_dict['dangerous_permission'] = dangerous_permission
            buffer = []
            for rule_id, details in json_response["mobsfscan"].items():
                formatted = self.format_table(rule_id, details)
                buffer.append(formatted)
            html_dict["mobsfscan"] = '\n'.join(buffer)
            html_dict["style"] = self.load_style(report_type)

            # Ensure 'reports' directory exists
            if not os.path.exists('reports'):
                os.makedirs('reports')

            # Generating the html report
            report_content = self.render_template('report_template.html', html_dict)
            cleaned_apk_name = self.clean_apk_name(self.apk_name)
            html_report_path = f"reports/report_{cleaned_apk_name}.html"
            self.grenerate_html_report(report_content, html_report_path)
            if report_type == "html":
                Util.mod_print(f"[+] Generated HTML report - {html_report_path}", Util.OKCYAN)

            # Converting html report to pdf.
            if report_type == "pdf":
                pdf_name = f"report_{cleaned_apk_name}.pdf"
                pdf_path = f"reports/{pdf_name}"
                self.convert_html_to_pdf(html_report_path, pdf_path)
                Util.mod_print(f"[+] Generated PDF report - {pdf_path}", Util.OKCYAN)


        except Exception as e:
            Util.mod_print(f"[-] {str(e)}", Util.FAIL)