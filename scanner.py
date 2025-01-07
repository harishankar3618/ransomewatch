import os
import yara

class YaraScanner:
    def __init__(self, rules_directory):
        """
        Initialize the YaraScanner with the directory containing YARA rules.
        """
        self.rules_directory = rules_directory
        self.rules = self._load_yara_rules()

    def _load_yara_rules(self):
        """
        Compiles all YARA rules from the specified directory.
        """
        rule_files = [
            os.path.join(self.rules_directory, f)
            for f in os.listdir(self.rules_directory)
            if f.endswith(".yar") or f.endswith(".yara")
        ]

        if not rule_files:
            raise FileNotFoundError(f"No YARA rule files found in {self.rules_directory}")

        try:
            compiled_rules = yara.compile(
                filepaths={os.path.basename(path): path for path in rule_files}
            )
            return compiled_rules
        except yara.SyntaxError as e:
            raise ValueError(f"Error compiling YARA rules: {e}")

    def scan_file(self, file_path):
        """
        Scans a file using the loaded YARA rules.
        Returns a list of matched rule names.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")

        try:
            matches = self.rules.match(file_path)
            return [match.rule for match in matches] if matches else []
        except Exception as e:
            raise ValueError(f"Error scanning file {file_path}: {e}")

    def scan_folder(self, folder_path):
        """
        Scans all files in a folder using the loaded YARA rules.
        Returns a dictionary with file paths as keys and matched rule names as values.
        """
        results = {}
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    matches = self.scan_file(file_path)
                    if matches:
                        results[file_path] = matches
                except Exception as e:
                    continue  # Ignore errors scanning individual files
        return results
