# <div align="center">APKDeepLens</div>
<div align="center">
<a href="https://github.com/Stormtrooperroman/APKDeepLens/tree/master#features">Features</a> • 
<a href="https://github.com/Stormtrooperroman/APKDeepLens/tree/master#installation">Installation</a> • 
<a href="https://github.com/Stormtrooperroman/APKDeepLens/blob/master/CHANGELOG.md">Changelog</a>
</div>
<p>

APKDeepLens is a Python based tool designed to scan Android applications (APK files) for security vulnerabilities. It specifically targets the OWASP Top 10 mobile vulnerabilities, providing an easy and efficient way for developers, penetration testers, and security researchers to assess the security posture of Android apps.

This is fork of original [APKDeepLens](https://github.com/d78ui98/APKDeepLens/) aimed at expanding functionality of scanning 



## Features

APKDeepLens is a Python-based tool that performs various operations on APK files. Its main features include:

- **APK Analysis** -> Scans Android application package (APK) files for security vulnerabilities.
- **OWASP Coverage** -> Covers OWASP Top 10 vulnerabilities to ensure a comprehensive security assessment.
- **Advanced Detection** -> Utilizes custom python code for APK file analysis and vulnerability detection.
- **Sensitive Information Extraction** -> Identifies potential security risks by extracting sensitive information from APK files, such as insecure authentication/authorization keys and insecure request protocols.
- **In-depth Analysis** -> Detects insecure data storage practices, including data related to the SD card, and highlights the use of insecure request protocols in the code.
- **Intent Filter Exploits** -> Pinpoint vulnerabilities by analyzing intent filters extracted from AndroidManifest.xml.
- **Local File Vulnerability Detection** -> Safeguard your app by identifying potential mishandlings related to local file operations
- **Report Generation** -> Generates detailed and easy-to-understand reports for each scanned APK, providing actionable insights for developers.
- **User-Friendly Interface** -> Color-coded terminal outputs make it easy to distinguish between different types of findings.

## Installation

To use APKDeepLens, you'll need to have Python 3.8 or higher installed on your system. You can then install APKDeepLens using the following command:
### For Linux
```
git clone https://github.com/Stormtrooperroman/APKDeepLens.git
cd /APKDeepLens
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 APKDeepLens.py --help
```
### For Windows
This fork doesn't work on Windows because it use semgrep inside. But you can use it in WSL.

## Command Line Options
```     
usage: APKDeepLens.py [-h] -apk APK [-v] [-source_code_path APK] [-report {json,pdf,html}] [-f] [-l log level]

APKDeepLens: Android security insights in full spectrum. 

options:
  -h, --help            show this help message and exit
  -apk APK              Path to the APK file to be analyzed.
  -v, -version          Display the version of APKDeepLens.
  -source_code_path APK
                        Enter a valid path of extracted source for apk.
  -report {json,pdf,html}
                        Format of the report to be generated. Default is JSON.
  -f, --force           Extracting apk if source code already extracted
  -l log level          Set the logging level

For more information, visit our GitHub repository - https://github.com/Stormtrooperroman/APKDeepLens
```

## Usage

To simply scan an APK, use the below command. Mention the apk file with `-apk` argument. 
Once the scan is complete, a detailed report will be displayed in the console.

```
python3 APKDeepLens.py -apk file.apk
```

If you've already extracted the source code and want to provide its path for a faster scan you can use the below command.
Mention the source code of the android application with `-source` parameter.
 
```
python3 APKDeepLens.py -apk file.apk -source <source-code-path>
```
To generate detailed PDF and HTML reports after the scan you can pass `-report` argument as mentioned below.
```
python3 APKDeepLens.py -apk file.apk -report html
```
or
```
python3 APKDeepLens.py -apk file.apk -report pdf
```
## TODO
- [x] Add mobsfscan
- [ ] Add collection of additional information about the apk
- [ ] Extend semgrep rules

## Contributing

We welcome contributions to the APKDeepLens project. If you have a feature request, bug report, or proposal, please open a new issue [here](https://github.com/Stormtrooperroman/APKDeepLens/issues).

For those interested in contributing code, please follow the standard GitHub process.
We'll review your contributions as quickly as possible :)


