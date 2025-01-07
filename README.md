# Signature-based-ransomeware-detection-tool

A simple and efficient **signature-based ransomware detection tool** built using YARA rules. This tool helps you detect ransomware and other malicious files by scanning them for known signatures. The tool uses predefined YARA rules to identify files or activities associated with ransomware threats.
## Features

- **Scan a single file** for matches with YARA rules.
- **Scan a folder** and its contents for potential threats.
- **View available YARA rules** in the rules directory.
- **Logging**: Logs the scan results and errors to a file (`yara_scanner.log`).

## Requirements

- **Python 3.x**: [Download Python 3.x](https://www.python.org/downloads/)
- **YARA Python bindings** (`yara-python`): Used to load and apply YARA rules.

You can install the required dependencies using the following command:

```bash
pip install yara-python
```
## Setup
- Clone the repository:

```bash
git clone https://github.com/harishankar3618/signature-based-ransomeware-detection
cd signature-based-ransomeware-detection
```

- To start the YARA Scanner Tool, simply run the script:
```bash
python main.py
```
## Usage
After running the tool, you will be presented with the following options:
- **Scan a single file**: Enter the path of a file to scan. The tool will check for matches with the YARA rules.
- **Scan a folder**: Enter the path of a folder to scan. The tool will scan all files within the folder.
- **Show available YARA rules**: View the available YARA rules in the rules directory.
- **Exit**: Exit the YARA Scanner Tool.

## Customization
- Rules Directory: The predefined YARA rules are located in the rules directory. You can add your own .yar or .yara rule files to this folder, and they will automatically be loaded by the tool.
- Scan Multiple Files/Folders: Modify the script to add batch scanning or other advanced features.


## Contribution
Feel free to fork this repository and create a pull request with improvements, bug fixes, or additional features. Contributions are welcome!

## Contact
For any issues or queries, feel free to open an issue in the GitHub repository or contact me directly at [harishankar3618@gmail.com].

## Acknowledgments
Special thanks to the YARA project and contributors for providing the powerful YARA rule engine used in this tool.


