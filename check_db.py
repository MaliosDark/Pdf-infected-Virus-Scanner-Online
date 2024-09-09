import sqlite3
import logging
from prettytable import PrettyTable

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def print_formatted_database_entries():
    """
    Connects to the SQLite database and prints formatted entries
    from the 'scans' and 'file_logs' tables using ASCII art.
    """
    try:
        # Connect to the SQLite database
        with sqlite3.connect('file_scans.db') as conn:
            cursor = conn.cursor()
            
            # Query all entries from the scans table
            cursor.execute('SELECT scan_id, filename, is_infected, infection_details, user_ip, user_agent, location FROM scans')
            scans = cursor.fetchall()
            
            if scans:
                # Create a PrettyTable for formatted output
                table = PrettyTable()
                table.field_names = ["File Name", "Scan ID", "Infected?", "Infection Details", "User IP", "User Agent", "Location"]
                
                for scan in scans:
                    filename, scan_id, is_infected, infection_details, user_ip, user_agent, location = scan[1], scan[0], scan[2], scan[3], scan[4], scan[5], scan[6]

                    # Add rows to the table
                    table.add_row([
                        filename,
                        scan_id,
                        "Yes" if is_infected else "No",
                        infection_details if infection_details else "N/A",
                        user_ip if user_ip else "Unknown",
                        user_agent if user_agent else "Unknown",
                        location if location else "Unknown"
                    ])
                
                print("Scans Table:")
                print(table)

                # Print associated file logs for each scan
                print("\nFile Logs Associated with Each Scan:")
                for scan in scans:
                    scan_id = scan[0]
                    filename = scan[1]

                    cursor.execute('SELECT log_content FROM file_logs WHERE scan_id = ?', (scan_id,))
                    log_entry = cursor.fetchone()

                    if log_entry:
                        print(f"\nLog for File: {filename} (Scan ID: {scan_id})")
                        print("-" * 50)
                        print(log_entry[0][:500] + "..." if len(log_entry[0]) > 500 else log_entry[0])  # Limit log display length
                        print("-" * 50)
                    else:
                        print(f"\nNo log found for File: {filename} (Scan ID: {scan_id})")

            else:
                print("No entries found in the scans table.")
            
    except sqlite3.Error as e:
        logging.error(f"Error accessing the database: {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")

if __name__ == '__main__':
    # Run the function to print all database entries formatted
    print_formatted_database_entries()
