# JavaScriptParser

# Async JS Vulnerability Scanner

A high-performance asynchronous vulnerability scanner for JavaScript/TypeScript code using async/await for maximum efficiency.

## 🚀 Features

- **Asynchronous Scanning** - Multi-threaded file processing
- **Multiple Vulnerability Types**:
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Command Injection
  - Path Traversal
  - Hardcoded Secrets
  - Unsafe eval() usage
  - Insecure Dependencies
  - CORS Misconfiguration
- **Multiple Report Formats** - TEXT, JSON, CSV
- **Dependency Checking** - package.json analysis
- **Flexible Configuration** - Adjustable worker count

## 📦 Installation

```bash
# Clone repository
git clone <repository-url>
cd async-js-vulnerability-scanner

# Install dependencies
pip install -r requirements.txt
```

### Requirements
- Python 3.7+
- aiofiles
- aiohttp (optional)

## 🛠 Usage

### Basic Scanning
```bash
python scanner.py /path/to/scan
```

### Advanced Scanning Options
```bash
# Scan with JSON output
python scanner.py /path/to/scan --format json --output report.json

# Scan with dependency checking
python scanner.py /path/to/scan --check-deps --verbose

# Increase worker count
python scanner.py /path/to/scan --workers 20

# Scan single file
python scanner.py app.js --format text
```

### Command Line Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `target` | File or directory to scan | Required |
| `--output, -o` | Output file for report | Console |
| `--format, -f` | Report format (text, json, csv) | text |
| `--verbose, -v` | Verbose output | False |
| `--workers, -w` | Number of concurrent workers | 10 |
| `--check-deps, -d` | Check package.json dependencies | False |

## 📊 Supported Vulnerabilities

### SQL Injection
Detects potential SQL injections through:
- String concatenation in SQL queries
- Template literals with user input
- Direct use of request parameters

### XSS (Cross-Site Scripting)
Identifies:
- innerHTML assignment with user input
- document.write() usage
- jQuery methods (html(), append(), etc.)
- Server responses with user input

### Command Injection
Detects:
- child_process.exec/spawn with user input
- Template literals in commands

### Path Traversal
Finds:
- fs.readFile/writeFile with user-controlled paths
- Path manipulations via path.join()
- Relative paths with user input

### Hardcoded Secrets
Searches for hardcoded:
- Passwords
- API keys
- Authentication tokens
- JWT secrets

### Eval Usage
Identifies dangerous usage of:
- eval() with user input
- Function constructor
- setTimeout/setInterval with strings

## 📁 Supported File Types

- `.js` - JavaScript files
- `.jsx` - React JSX files
- `.ts` - TypeScript files
- `.tsx` - React TypeScript files
- `.mjs` - ES modules
- `.cjs` - CommonJS modules

## 🔧 Usage Examples

### Example 1: Basic Project Scan
```bash
python scanner.py ./my-project --format json --output scan-report.json
```

### Example 2: Detailed Scan with Dependency Check
```bash
python scanner.py ./src --check-deps --verbose --workers 15
```

### Example 3: Scan with CSV Report
```bash
python scanner.py ./app --format csv --output vulnerabilities.csv
```

## 📋 Sample Output

### Text Format
```
1. [HIGH] /project/routes/users.js:45
   Type: sql_injection
   Description: SQL injection - user input directly used in SQL query
   Found: query("SELECT * FROM users WHERE id = " + req.params.id)
   Code: const result = query("SELECT * FROM users WHERE id = " + req.params.id);
------------------------------------------------------------
```

### JSON Format
```json
[
  {
    "file": "/project/routes/users.js",
    "line": 45,
    "type": "sql_injection",
    "severity": "HIGH",
    "pattern": "(?i)SELECT.*FROM.*\\+.*(req\\.|param|query|body|input)",
    "code_snippet": "const result = query(\"SELECT * FROM users WHERE id = \" + req.params.id);",
    "description": "SQL injection - user input directly used in SQL query",
    "match": "query(\"SELECT * FROM users WHERE id = \" + req.params.id)"
  }
]
```

## ⚡ Performance

Scanner is optimized for large projects:
- Asynchronous file processing
- Concurrent operation limits via semaphore
- Efficient directory traversal
- Automatic skipping of unnecessary folders (node_modules, .git, etc.)

## 🛡️ Severity Levels

- **CRITICAL** - Command Injection
- **HIGH** - SQL Injection, XSS, Path Traversal, Eval Usage
- **MEDIUM** - Hardcoded Secrets, Insecure Dependencies, CORS Misconfig

## ⚠️ Limitations

- Static analysis cannot detect all vulnerabilities
- False positives are possible
- Manual verification of findings is recommended
- Does not replace dynamic security testing

## 🚨 Disclaimer

This tool is for educational and security research purposes only. Always ensure you have proper authorization before scanning systems. The authors are not responsible for any misuse of this tool.
