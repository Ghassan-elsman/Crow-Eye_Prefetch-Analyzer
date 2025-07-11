# Crow-Eye_Prefetch-Analyzer
The Crow-Eye Prefetch Analyzer is a Python-based command-line tool designed for forensic analysis of Windows prefetch files (.pf) to extract execution metadata, such as executable names, run counts, last execution timestamps, and referenced resources. It supports both live and offline analysis, with output options in SQLite, JSON, or CSV formats.
Features

Parses Windows Prefetch Files: Extracts metadata from .pf files, including executable name, hash, run count, execution timestamps, volumes, directories, and resources.
Live and Offline Analysis:
Live: Analyzes C:\Windows\Prefetch.
Offline: Analyzes a user-specified directory containing .pf files.


Output Formats: Saves parsed data to SQLite database, JSON, or CSV files with customizable output paths.
Performance Optimization: Uses multiprocessing for faster parsing of multiple files.
Progress Tracking: Displays a progress bar with the current file being processed.
Error Handling: Logs parsing errors and high run counts to prefetch_analyzer.log.
File Validation: Checks for minimum file size (84 bytes) before parsing.
Static Logo: Displays an ASCII logo once at startup, with no screen clearing to keep output visible.
Number-Based Navigation: Uses numbers (1-4) for menu selections.
Run Count Behavior: Logs run counts exceeding 1,000,000 to prefetch_analyzer.log for analysis, as these may indicate parsing errors or Windows-specific quirks. The tool emphasizes the last execution timestamp for reliable analysis.

Requirements

Operating System: Windows (due to prefetch file access and decompression requirements).
Python: Version 3.8 or higher (tested with Python 3.12).
Administrative Privileges: Required to access C:\Windows\Prefetch.
Dependencies:
sqlite3 (for SQLite output)
tqdm (for progress bar)


Internet Access: Needed for automatic installation of missing dependencies via pip.

Installation

Install Python:

Download and install Python 3.8+ from python.org.
Ensure pip is included in your Python installation.


Save the Script:

Save the script as cli_prefetch_parser.py in your desired directory (e.g., E:\prefetch analysis\).


Install Dependencies:

The script automatically checks for and installs sqlite3 and tqdm if missing.
If automatic installation fails, install manually:pip install tqdm


Note: sqlite3 is typically included with Python, but ensure it's available.



Usage

Run as Administrator:

Open a PowerShell or Command Prompt as an administrator.
Navigate to the script's directory (e.g., E:\prefetch analysis\).
Execute the script:& C:/Users/YourUsername/AppData/Local/Microsoft/WindowsApps/python3.12.exe "E:/prefetch analysis/cli_prefetch_parser.py"

Replace YourUsername and paths as needed.


Main Menu Navigation:

The ASCII logo displays once at startup and remains visible.
Choose an option by entering a number (1-4):
1. Live Analysis: Processes C:\Windows\Prefetch.
2. Offline Analysis: Prompts for a custom directory path (e.g., E:\prefetch_files).
3. Select Output Format: Choose SQLite, JSON, or CSV and specify an output path.
4. Exit: Closes the program.


Invalid inputs prompt an error and allow retry.


Output Format Selection:

If selecting option 3, choose an output format (1-4):
1. SQLite Database: Saves to prefetch_data3.db (default) or a custom path.
2. JSON File: Saves to prefetch_data.json (default) or a custom path.
3. CSV File: Saves to prefetch_data.csv (default) or a custom path.
4. Back: Returns to the main menu.


Enter a custom output path or press Enter for the default.


Processing:

The script displays a tqdm progress bar showing the current .pf file being processed.
After completion, it shows the percentage of successfully parsed files.
Errors and high run counts are logged to prefetch_analyzer.log in the script's directory.



Run Count Behavior

Observation: The run count in prefetch files often shows unusually large numbers (>1,000,000), which may result from parsing errors, file corruption, or Windows prefetch behavior (e.g., counter overflows or system-specific quirks).
Current Approach: The script logs high run counts to prefetch_analyzer.log for further analysis but does not cap them. Analysis focuses on the last execution timestamp (last_executed in output) to provide reliable execution timing data.
Log File: Check prefetch_analyzer.log for entries like:2025-07-12 02:34:56,789 - WARNING - High run count (1200000000) in filename.pf, potential parsing error

These logs help identify files with anomalous run counts for deeper investigation.

Output

SQLite: Stores data in a database (prefetch_data3.db or custom path) with columns for filename, executable name, hash, run count, last executed timestamp, run times, volumes, directories, resources, and file timestamps.
JSON: Saves data as a JSON array of objects (prefetch_data.json or custom path).
CSV: Saves data as a table (prefetch_data.csv or custom path) with the same fields as SQLite.
Log File: prefetch_analyzer.log contains errors and high run count warnings.

Example

Run the script as administrator:& C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe "E:/prefetch analysis/cli_prefetch_parser.py"




=== CROW-EYE PREFETCH ANALYZER MENU ===
1. Live Analysis (C:\Windows\Prefetch)
2. Offline Analysis (Custom Directory)
3. Select Output Format
4. Exit

Current output format: SQLITE (prefetch_data3.db)
Enter a number (1-4) to select an option:


Enter 1 for live analysis.
View the progress bar and output:Processing 123 prefetch files...
Parsing Files: 100%|██████████| 123/123 [00:05<00:00, 24.60file/s, file=Done]
Percentage of Successfully Parsed Files: 98.37%
Parsing errors logged to prefetch_analyzer.log
Press Enter to continue...


Check output files (e.g., prefetch_data3.db) and prefetch_analyzer.log for details.

Troubleshooting

Permission Denied: Ensure the script is run as an administrator.
Missing Dependencies: If tqdm installation fails, run pip install tqdm manually.
Invalid Directory: For offline analysis, verify the directory exists and contains .pf files.
High Run Counts: Review prefetch_analyzer.log for files with run counts >1,000,000 and focus on the last_executed timestamp for reliable data.
Errors: Check prefetch_analyzer.log for parsing or decompression errors.

Notes

The script requires Windows for prefetch decompression (Windows 10/11 files use XPRESS Huffman compression).
Run counts may appear inflated due to prefetch file structure or system behavior; the last execution timestamp is typically more reliable for forensic analysis.
For large directories, multiprocessing may increase memory usage. Adjust the number of processes in the Pool if needed (e.g., Pool(processes=4)).

License
This tool is provided as-is for forensic analysis purposes. Use responsibly and ensure compliance with applicable laws and regulations.
For issues or feature requests, contact the developer or submit a pull request.
