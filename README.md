
# 🛡️ File Scan and Analysis Application Documentation

## Overview

This application is a **file scanning and analysis tool** built using the Python Flask framework. It allows users to upload files to scan for potential threats (e.g., malware, viruses) and provides detailed reports of the findings. The application utilizes various libraries and tools to scan files, analyze content, and provide AI-based insights using the Ollama AI model.

## Features

- 📄 **PDF File Scanning**: Uses `peepdf` and `pdfplumber` to analyze PDF files for potentially malicious elements.
- 🦠 **File Scanning with ClamAV**: Scans other types of files using ClamAV for virus detection.
- 📊 **Database Logging**: Logs all scans and results in an SQLite database for easy retrieval and reporting.
- 🧠 **AI Analysis**: Integrates Ollama AI to provide insights and analysis of file scan logs.
- 🔄 **Error Handling & Restart**: Monitors errors and restarts the application if necessary to maintain stability.
- 🌐 **User-Friendly Web Interface**: Provides a web interface for uploading files, viewing scan history, and interacting with the AI.
- 🧹 **Maintenance & Cleanup**: Includes automatic cleanup of temporary files and system resource monitoring.

## Technical Requirements

- Python 3.8+
- Flask
- ClamAV
- SQLite3
- `py_pdf_parser`, `py_mini_racer`, `pdfplumber`, `psutil`, and other dependencies as listed in `requirements.txt`

## How It Works

### 1. 🏗️ **Initialization and Configuration**

The script initializes a Flask application and configures it to handle file uploads and session management. It also sets up an SQLite database to store scan results and file logs.

```python
app = Flask(__name__)
app.config['UPLOADED_FILES_DEST'] = 'temp_files'  # Directory for temporary files
app.config['SECRET_KEY'] = 'supersecretkey'  # Secret key for sessions
```

- **Database Initialization**: The `init_db()` function creates two tables:
  - `scans`: Stores the results of each file scan.
  - `file_logs`: Stores logs associated with each scanned file.

### 2. 📤 **File Upload and Scanning**

Users can upload files through the web interface. The application checks the file type and routes the file for appropriate scanning:

- **PDF Files**: Scanned using `peepdf` for suspicious elements and `pdfplumber` for text extraction.
- **Other Files**: Scanned using ClamAV.

```python
def scan_pdf(file_path):
    # Use peepdf and pdfplumber to analyze PDF files
    ...
```

### 3. 🧠 **AI-Powered Analysis**

The application integrates with **Ollama AI** to provide insights based on the content of the scan logs. Users can interact with the AI by providing questions or additional context.

```python
def ollama_file_analyzer(file_analysis_log, additional_context="", is_log=False):
    # Interact with the Ollama AI model to analyze file scan logs
    ...
```

### 4. 🔄 **Error Monitoring and Auto-Restart**

To ensure stability, the application tracks errors and restarts itself if the number of errors exceeds a predefined threshold.

```python
def track_errors():
    global error_count
    error_count += 1
    if error_count >= error_threshold:
        restart_application()
```

### 5. 🧹 **Maintenance and Resource Management**

- **Temporary File Cleanup**: A background thread deletes files older than 24 hours.
- **System Resource Monitoring**: Another thread monitors CPU and memory usage, restarting the app if usage is too high.

```python
def cleanup_temp_files():
    # Deletes old temporary files to free up space
    ...
```

## API Endpoints

### 1. `/` - **Main Route**

- **Method**: `GET, POST`
- **Description**: Main route for file uploads and scanning. Displays the scan history and allows users to upload new files.

### 2. `/report/<int:file_id>` - **Report File**

- **Method**: `POST`
- **Description**: Marks a file as reported in the database.

### 3. `/view_report/<scan_id>` - **View Detailed Report**

- **Method**: `GET`
- **Description**: Fetches and displays a detailed scan report for the specified `scan_id`.

### 4. `/chat_with_ai` - **AI Chat Interface**

- **Method**: `POST`
- **Description**: Allows users to interact with the Ollama AI model to get insights on file scan logs.

## Database Structure

The application uses an SQLite database (`file_scans.db`) with the following tables:

- **scans**: Stores metadata and results for each file scan.
- **file_logs**: Stores detailed logs associated with each scan.

## Additional Script: `check_db.py`

This script is used for **testing and inspecting** the database entries. It provides a formatted output using ASCII art for better visualization.

### Features

- Prints all entries from the `scans` and `file_logs` tables.
- Provides formatted output using `PrettyTable`.
- Includes error handling for unexpected issues.

## Security Considerations

- 🛡️ **Input Validation**: Ensures that file uploads are secure and prevent malicious input.
- 🔒 **Session Management**: Uses Flask sessions to manage user interactions securely.
- 🔍 **Logging**: Provides extensive logging for debugging and monitoring purposes.

## Future Improvements

- Add more comprehensive AI analysis options using multiple models.
- Implement user authentication for better security.
- Expand file type support for other document formats (e.g., DOCX, XLSX).

## Conclusion

This application is a robust and secure solution for scanning files, logging results, and providing AI-based insights. With a user-friendly interface and powerful backend features, it offers a comprehensive tool for file security analysis and reporting.
