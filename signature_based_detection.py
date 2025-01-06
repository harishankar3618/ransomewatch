import os
import yara

class RansomWatch:
    def __init__(self, rules_directory):
        """
        Initialize the RansomWatch with the directory containing YARA rules.
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
            print(f"Loaded {len(rule_files)} YARA rules.")
            return compiled_rules
        except yara.SyntaxError as e:
            raise ValueError(f"Error compiling YARA rules: {e}")

    def scan_file(self, file_path):
        """
        Scans a single file using the loaded YARA rules.
        Returns a list of matched rule names.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")

        try:
            matches = self.rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []

    def scan_folder(self, folder_path):
        """
        Scans all files in a folder using the loaded YARA rules.
        Returns a dictionary with file paths as keys and matched rule names as values.
        """
        if not os.path.isdir(folder_path):
            raise NotADirectoryError(f"Folder {folder_path} not found.")

        results = {}
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                matches = self.scan_file(file_path)
                if matches:
                    results[file_path] = matches
        return results


# Example usage for RansomWatch:
if __name__ == "__main__":
    rules_directory = "rules"

    try:
        ransomwatch = RansomWatch(rules_directory)

        choice = input("RansomWatch: Scan (1) File or (2) Folder? Enter 1 or 2: ").strip()

        if choice == "1":
            file_to_scan = input("Enter the path to the file to scan: ").strip()
            matches = ransomwatch.scan_file(file_to_scan)
            if matches:
                print(f"File '{file_to_scan}' matched the following rules:")
                for match in matches:
                    print(f"- {match}")
            else:
                print(f"No matches found for file '{file_to_scan}'.")

        elif choice == "2":
            folder_to_scan = input("Enter the path to the folder to scan: ").strip()
            results = ransomwatch.scan_folder(folder_to_scan)
            if results:
                print("Matches found in the following files:")
                for file_path, matches in results.items():
                    print(f"{file_path}:")
                    for match in matches:
                        print(f"  - {match}")
            else:
                print(f"No matches found in folder '{folder_to_scan}'.")

        else:
            print("Invalid choice. Please enter 1 or 2.")

    except Exception as e:
        print(f"Error: {e}")
