
# CRLF Injection Scanner

A Python-based tool for detecting CRLF injection vulnerabilities in web applications. This scanner supports multi-threaded scanning, custom payloads, and logs vulnerable URLs to an output file.

## Features

- **Custom Payloads**: Test URLs with a variety of CRLF injection payloads.
- **Regex Detection**: Identifies header and body injection using custom regex patterns.
- **Multi-threaded Scanning**: Scans multiple payloads simultaneously for faster results.
- **User-Agent Randomization**: Evades detection by using random User-Agent strings.
- **Output Logging**: Saves vulnerable URLs and details to a specified output file.

## Requirements

- Python 3.6 or higher
- Required Python libraries:
  - `requests`
  - `urllib3`
  - `colorama`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aungsanoo-usa/crlf-scanner.git
   cd crlf-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Create a text file containing the list of URLs to scan, with one URL per line. For example:
   ```plaintext
   http://example.com
   http://test.com
   ```

2. Run the scanner:
   ```bash
   python crlf_scanner.py -l urls.txt -o results.txt
   ```

3. View the results:
   - The terminal will display the scanning progress and detected vulnerabilities.
   - The output file (`results.txt`) will contain the list of vulnerable URLs.

### Command-Line Options

| Option         | Description                                      |
|-----------------|--------------------------------------------------|
| `-l, --list`   | Path to the file containing URLs to scan.         |
| `-o, --output` | Path to save the scan results (e.g., `results.txt`). |

### Example Command

```bash
python crlf_scanner.py -l urls.txt -o vul_out.txt
```

## Sample Output

**Terminal Output**:
```plaintext
Scanning URL: http://example.com
[→] Scanning with payload: /%0d%0aSet-Cookie:loxs=injected
[✓] Vulnerable: http://example.com/%0d%0aSet-Cookie:loxs=injected
Scan complete: 1 vulnerabilities found out of 1 scanned URLs.
Time taken: 10 seconds.

[✓] Scan results saved to vul_out.txt
```

**Output File (`vul_out.txt`)**:
```plaintext
http://example.com/%0d%0aSet-Cookie:loxs=injected
```

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the functionality.

## License

This project is licensed under the [MIT License](LICENSE).
