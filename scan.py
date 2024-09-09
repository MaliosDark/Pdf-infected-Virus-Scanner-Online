from flask import Flask, request, render_template, session, redirect, url_for, jsonify
from flask_uploads import UploadSet, configure_uploads, ALL
import os
import time
import subprocess
import clamav
from py_pdf_parser.loaders import load_file
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from py_mini_racer import py_mini_racer
import pdfplumber
from threading import Thread
import logging
import psutil
import sys
import sqlite3
import uuid
from langchain_community.llms import Ollama  # Import Ollama

# Configure logging for better error tracking and debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Ollama
llm = Ollama(model="phi3")

# Flask application configuration
app = Flask(__name__)
app.config['UPLOADED_FILES_DEST'] = 'temp_files'  # Directory for temporary files
app.config['SECRET_KEY'] = 'supersecretkey'  # Secret key for sessions

# Flask-Reuploaded configuration
files = UploadSet('files', ALL)
configure_uploads(app, files)

# Ensure the temporary files directory exists
os.makedirs(app.config['UPLOADED_FILES_DEST'], exist_ok=True)

# Initialize SQLite database
def init_db():
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        
        # Create the `scans` table if it does not exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,  -- Random scan ID for generating links
                session_id TEXT,
                filename TEXT,
                report TEXT,
                is_infected BOOLEAN,
                infection_details TEXT,
                reported BOOLEAN DEFAULT 0,
                report_date TEXT,
                user_ip TEXT,
                user_agent TEXT,
                location TEXT
            )
        ''')
        
        # Create the `file_logs` table to store the logs of file scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_logs (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,  -- Link this with scan_id from the scans table
                filename TEXT NOT NULL,
                log_content TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        conn.commit()

# Call the function to initialize the database
init_db()

# Update store_file_log function to store logs using scan_id
def store_file_log(scan_id, filename, log_content):
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_logs (scan_id, filename, log_content)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                log_content = excluded.log_content
        ''', (scan_id, filename, log_content))
        conn.commit()

def get_file_log(file_id):
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT log_content FROM file_logs WHERE file_id = ?
        ''', (file_id,))
        log_entry = cursor.fetchone()
        return log_entry[0] if log_entry else None

# PDF scanning function using peepdf and pdfplumber
def scan_pdf(file_path):
    try:
        # Scan with peepdf
        peepdf_output = subprocess.run(['peepdf', file_path], capture_output=True, text=True)
        peepdf_report = peepdf_output.stdout

        # Analyze peepdf output for suspicious elements
        is_infected = False
        infection_details = []

        for suspicious in ["/OpenAction", "/JS", "/JavaScript"]:
            if suspicious in peepdf_report:
                is_infected = True
                infection_details.append(f"Suspicious element found: {suspicious} - May contain potentially malicious code.")

        # Scan with pdfplumber
        try:
            with pdfplumber.open(file_path) as pdf:
                parsed_content = "\n".join(page.extract_text() or '' for page in pdf.pages)
            parser_output = f"Extracted PDF Content:\n{parsed_content}"
        except Exception as e:
            parser_output = f"Error analyzing the PDF with pdfplumber: {str(e)}"
            logging.error(parser_output)

        # Return the combined report
        report = f"Peepdf Report:\n{peepdf_report}\n\nPDF-Parser Report:\n{parser_output}"
        return report, is_infected, infection_details

    except Exception as e:
        logging.error(f"Error during PDF scan: {str(e)}")
        return "Error during PDF scan", False, []

# Execute JavaScript using PyMiniRacer
def execute_javascript(js_code):
    try:
        ctx = py_mini_racer.MiniRacer()
        result = ctx.eval(js_code)
        return f"Executed JavaScript Result: {result}"
    except Exception as e:
        logging.error(f"JavaScript execution error: {str(e)}")
        return f"JavaScript execution error: {str(e)}"

# File scanning function using ClamAV
def scan_file_with_clamav(file_path):
    try:
        scanner = clamav.ClamAV()
        scan_result = scanner.scan_file(file_path)
        return scan_result
    except Exception as e:
        logging.error(f"ClamAV scan error: {str(e)}")
        return f"ClamAV scan error: {str(e)}"

# Restart the application if too many errors occur
def restart_application():
    logging.warning("Restarting the application due to excessive errors...")
    os.execv(sys.executable, ['python'] + sys.argv)

# Track errors and restart if necessary
error_count = 0
error_threshold = 5

def track_errors():
    global error_count
    error_count += 1
    if error_count >= error_threshold:
        restart_application()

# Save scan result to the database and store the corresponding log
def save_scan_result(session_id, filename, report, is_infected, infection_details, user_ip, user_agent, location):
    scan_id = str(uuid.uuid4())  # Generate a random scan ID
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (scan_id, session_id, filename, report, is_infected, infection_details, user_ip, user_agent, location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, session_id, filename, report, is_infected, ', '.join(infection_details), user_ip, user_agent, location))
        conn.commit()

        # After saving the scan result, also store the log content in file_logs
        log_content = report  # Example: using the report as log content
        store_file_log(scan_id, filename, log_content)  # Call to store the log content using scan_id

# Fetch scan history for the current session
def fetch_scan_history(session_id):
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, filename, is_infected, reported FROM scans WHERE session_id = ?', (session_id,))
        return cursor.fetchall()

# Fetch reported files
def fetch_reported_files():
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT scan_id, filename, is_infected, report_date FROM scans WHERE reported = 1')
        return cursor.fetchall()

# Update report status
def report_file(file_id):
    with sqlite3.connect('file_scans.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE scans SET reported = 1, report_date = ? WHERE id = ?', (time.strftime("%Y-%m-%d %H:%M:%S"), file_id))
        conn.commit()

# Ollama Classifier function for AI interaction with file analysis
def ollama_file_analyzer(file_analysis_log, additional_context="", is_log=False):
    """
    This function interacts with the Ollama AI model to analyze a file's scan log and provide insights.

    Parameters:
    - file_analysis_log (str): The content/log of the file analysis to be examined.
    - additional_context (str): Any additional context or information that might help in the analysis.
    - is_log (bool): If True, prints the prompt and response for debugging.

    Returns:
    - str: The AI's response based on the provided file analysis log.
    """
    
    # Ensure there's meaningful content to analyze
    if not file_analysis_log or file_analysis_log.strip() == '':
        file_analysis_log = 'No log content provided for analysis.'

    # Ensure there's some additional context
    if not additional_context or additional_context.strip() == '':
        additional_context = 'No additional context provided.'

    # Construct the prompt for Ollama AI
    prompt = (
        f"Analyze the following file scan log and provide insights. "
        f"File_Scan_Log: {file_analysis_log.strip()} "
        f"Additional_Context: {additional_context.strip()} ###"
    )

    # Invoke Ollama to get the response
    response = llm.invoke(prompt)

    # Log the prompt and response if needed for debugging
    if is_log:
        print('- Prompt:', prompt)
        print('- Response:', response)

    return response


# Main route for file uploads and scanning
@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        # Generate a unique session ID for the user
        if 'session_id' not in session:
            session['session_id'] = str(uuid.uuid4())

        user_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        location = "Unknown"  # Replace this with actual location logic

        if request.method == 'POST':
            if 'file' not in request.files:
                return 'No file part', 400
            
            file = request.files['file']
            if file.filename == '':
                return 'No file selected', 400
            
            if file:
                # Save the file to the temporary directory
                filename = files.save(file)
                file_path = os.path.join(app.config['UPLOADED_FILES_DEST'], filename)
                
                # Determine file type and scan
                if file.filename.lower().endswith('.pdf'):
                    report, is_infected, infection_details = scan_pdf(file_path)
                else:
                    report = scan_file_with_clamav(file_path)
                    is_infected = "Not applicable"
                    infection_details = []
                
                # Save scan result to the database with user data
                save_scan_result(session['session_id'], filename, report, is_infected, infection_details, user_ip, user_agent, location)
                
                # Delete the file after scanning
                os.remove(file_path)
                return render_template('report.html', report=report, is_infected=is_infected, infection_details=infection_details)
        
        # Fetch scan history for the current session
        scan_history = fetch_scan_history(session['session_id'])
        reported_files = fetch_reported_files()
        return render_template('index.html', scan_history=scan_history, reported_files=reported_files)
    
    except Exception as e:
        logging.error(f"Error in the main route: {str(e)}")
        track_errors()
        return "An error occurred during the file scan. Please try again later.", 500

# Route for reporting a file
@app.route('/report/<int:file_id>', methods=['POST'])
def report(file_id):
    try:
        report_file(file_id)
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error reporting file: {str(e)}")
        track_errors()
        return "An error occurred while reporting the file. Please try again later.", 500

# Route for viewing a detailed report
@app.route('/view_report/<scan_id>', methods=['GET'])
def view_report(scan_id):
    try:
        with sqlite3.connect('file_scans.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT report FROM scans WHERE scan_id = ?', (scan_id,))
            report = cursor.fetchone()
            if report:
                return render_template('report.html', report=report[0])
            else:
                return "Report not found", 404
    except Exception as e:
        logging.error(f"Error fetching report: {str(e)}")
        track_errors()
        return "An error occurred while fetching the report. Please try again later.", 500

# Route for AI Chat
@app.route('/chat_with_ai', methods=['POST'])
def chat_with_ai():
    file_id = request.form.get('file_id')  # Correctly capture file_id from request
    question = request.form.get('question')  # Correctly capture question from request
    
    if not file_id or not question:
        return jsonify({'response': 'Invalid input parameters. Please ensure a file and a question are selected.'})

    try:
        # Connect to the database and retrieve the log of the file using file_id
        with sqlite3.connect('file_scans.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT log_content FROM file_logs WHERE file_id = ?", (file_id,))
            log_entry = cursor.fetchone()  # Fetch the log entry for the selected file

        if log_entry:
            file_analysis_log = log_entry[0]
            logging.info(f"Retrieved log content for file_id {file_id}.")
        else:
            file_analysis_log = 'No log content found for this file ID.'
            logging.warning(f"No log content found for file_id {file_id}.")

        # Call the AI analysis function
        ai_response = ollama_file_analyzer(file_analysis_log, additional_context=question, is_log=True)
    
        return jsonify({'response': ai_response})
    
    except Exception as e:
        logging.error(f"Error during AI interaction: {str(e)}")
        return jsonify({'response': 'An error occurred during AI interaction. Please try again later.'})


# Clean up old temporary files
def cleanup_temp_files():
    now = time.time()
    temp_dir = app.config['UPLOADED_FILES_DEST']
    
    for f in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, f)
        if os.stat(file_path).st_mtime < now - 86400:  # 86400 seconds = 24 hours
            os.remove(file_path)
            logging.info(f"Deleted old file: {file_path}")

# Maintenance task that runs every 24 hours
def maintenance_task():
    while True:
        try:
            cleanup_temp_files()
            time.sleep(86400)  # Wait 24 hours
        except Exception as e:
            logging.error(f"Error in maintenance task: {str(e)}")
            track_errors()

# Check for system resource usage and restart if necessary
def monitor_system_resources():
    while True:
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent

            if cpu_usage > 90 or memory_usage > 90:
                logging.warning("High system resource usage detected. Restarting the application...")
                restart_application()

            time.sleep(300)  # Check every 5 minutes
        except Exception as e:
            logging.error(f"Error in resource monitoring: {str(e)}")
            track_errors()

# Start the application
if __name__ == '__main__':
    # Start the maintenance and resource monitoring threads
    maintenance_thread = Thread(target=maintenance_task, daemon=True)
    maintenance_thread.start()

    resource_monitor_thread = Thread(target=monitor_system_resources, daemon=True)
    resource_monitor_thread.start()

    # Start the Flask application accessible from other machines
    app.run(host='0.0.0.0', port=5000, debug=True)
