import os
import logging
from scanner import YaraScanner
from email_alert import send_malware_alert, check_and_store_receipt_email, load_sender_credentials

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO to capture normal events and errors
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log entries
    handlers=[
        logging.FileHandler("yara_scanner.log"),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

def clear_screen():
    """Clear the screen for better user experience"""
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    logging.info(f"Starting the YARA Scanner Tool...")
    print("Welcome to the YARA Scanner Tool!")
    print("----------------------------------")

    # Load sender credentials
    try:
        sender_email, sender_password = load_sender_credentials()
        logging.info("Sender credentials loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to load sender credentials: {e}")
        print(f"Error: {e}")
        return

    # Check and load receipt email
    receipt_email = check_and_store_receipt_email()
    logging.info(f"Receipt email loaded: {receipt_email}")

    # Declare the hardcoded rules directory
    rules_directory = os.path.abspath("rules")  # Specify your rules folder here

    try:
        scanner = YaraScanner(rules_directory)

        while True:
            print("\nChoose an option:")
            print("1. Scan a single file")
            print("2. Scan a folder")
            print("3. Show available YARA rules")
            print("4. Exit")
            choice = input("Enter your choice (1/2/3/4): ").strip()

            if choice == "1":
                clear_screen()
                print("FILE SCAN")
                print("----------------------------------")
                file_to_scan = input("Enter the path to the file to scan: ").strip()
                try:
                    matches = scanner.scan_file(file_to_scan)
                    clear_screen()
                    print("Scanning file...")
                    print("----------------------------------")
                    if matches:
                        print(f"\nFile '{file_to_scan}' matched the following rules:")
                        for match in matches:
                            print(f"  - {match}")
                        logging.info(f"Matches found in file: {file_to_scan}")
                        send_malware_alert(sender_email, sender_password, receipt_email, file_to_scan)
                        logging.info(f"Malware alert email sent for file: {file_to_scan}")
                    else:
                        logging.info(f"No matches found in file: {file_to_scan}")
                except FileNotFoundError as e:
                    logging.error(f"File not found: {file_to_scan}")
                except Exception as e:
                    logging.error(f"Error scanning file {file_to_scan}: {e}")
                
                input("\nPress Enter to go back to the menu...")
                clear_screen()

            elif choice == "2":
                clear_screen()
                print("FOLDER SCAN")
                print("----------------------------------")
                folder_to_scan = input("Enter the path to the folder to scan: ").strip()
                if not os.path.exists(folder_to_scan):
                    logging.error(f"Folder not found: {folder_to_scan}")
                    input("\nPress Enter to go back to the menu...")
                    clear_screen()
                    continue
                try:
                    results = scanner.scan_folder(folder_to_scan)
                    if results:
                        print("\nMatches found in the following files:")
                        all_files_detected = []
                        for file_path, matches in results.items():
                            print(f"{file_path}:")
                            for match in matches:
                                print(f"  - {match}")
                            all_files_detected.append(f"{file_path}: {', '.join(matches)}")
                        logging.info(f"Matches found in folder: {folder_to_scan}")
                        send_malware_alert(sender_email, sender_password, receipt_email, "\n".join(all_files_detected))
                        logging.info(f"Malware alert email sent for folder scan.")
                    else:
                        logging.info(f"No matches found in folder: {folder_to_scan}")
                except Exception as e:
                    logging.error(f"Error scanning folder {folder_to_scan}: {e}")
                input("\nPress Enter to go back to the menu...")
                clear_screen()

            elif choice == "3":
                clear_screen()
                print("YARA RULES")
                print("----------------------------------")       
                logging.info("Showing available YARA rules.")         
                # Show available YARA rules in the directory
                try:
                    rule_files = [
                        f for f in os.listdir(rules_directory)
                        if f.endswith(".yar") or f.endswith(".yara")
                    ]
                    if rule_files:
                        print("\nAvailable YARA rules:")
                        for idx, rule in enumerate(rule_files, 1):
                            print(f"{idx}. {rule}")
                    else:
                        print("No YARA rules found in the specified directory.")
                except Exception as e:
                    logging.error(f"Error loading YARA rules: {e}")
                input("\nPress Enter to go back to the menu...")
                clear_screen()

            elif choice == "4":
                clear_screen()
                print("Exiting the YARA Scanner Tool. Goodbye!")
                logging.info("Exiting the YARA Scanner Tool.")
                break

            else:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")

    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
