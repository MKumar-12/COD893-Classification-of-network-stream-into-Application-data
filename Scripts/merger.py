'''
merger.py: 
    1. Extract flows from pcap file
    2. Compute basic flow statistics(timestamps, sizes, dir.) from each pcap file
    3. Save collected flow details from diff. classes into a single .csv file           (i.e., contains LABELLED FLOWs)

'''

from scapy.all import rdpcap, IP, TCP, UDP
import csv
import sys
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import logging
import re


csv.field_size_limit(10**9)   # To avoid field size limit error

def extract_dataset_name(input_dir):
    """Extracts dataset name from input directory, assuming 'Dataset_' prefix."""
    base_name = os.path.basename(os.path.normpath(input_dir))  
    
    if base_name.startswith("Dataset_"):
        return base_name.split("Dataset_")[-1]  
    return base_name        # If no 'Dataset_' prefix, return full basename

def setup_logging(current_dataset):
    """Sets up logging dynamically based on the dataset name."""
    log_file = f"../Logs/logs_{current_dataset}.txt"
    logging.basicConfig(
        filename=log_file, 
        filemode="w",  # "w" to overwrite, "a" to append
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info(f"Logging initialized for dataset: {current_dataset}")

def get_abbreviation(input_dir):
    """fn. to extract first initials or camel-case letters from input directory name. """
    base_name = os.path.basename(os.path.normpath(input_dir))       # Extracts base folder name
    logging.info(f"Input dir.'s base name: {base_name}")
    
    words = re.findall(r'[A-Z]+[a-z]*|[a-z]+', base_name)           # Extract words from CamelCase or underscores
    abbr = ''.join(word[0] for word in words).lower()               # Take first letter of each word
    logging.info(f"Suffix for Output_dir: {abbr}")
    return abbr

def process_pcap(pcap_file, output_csv):
    logging.info(f"Processing: {pcap_file}")
    connections = defaultdict(lambda: {"timestamps": [], "sizes": [], "directions": []})
    
    try:
        packets = rdpcap(pcap_file)
        
        for pkt in packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                protocol = "TCP" if TCP in pkt else "UDP"
                conn_tuple = (src_ip, src_port, dst_ip, dst_port, protocol)
                
                connections[conn_tuple]["timestamps"].append(pkt.time)
                connections[conn_tuple]["sizes"].append(len(pkt))
                connections[conn_tuple]["directions"].append(1)             # Source to destination

                rev_conn_tuple = (dst_ip, dst_port, src_ip, src_port, protocol)
                if rev_conn_tuple in connections:
                    connections[rev_conn_tuple]["directions"][-1] = 0       # Destination to source
    
        with open(output_csv, "w", newline="") as csvfile:
            fieldnames = ["index", "connection", "timestamps", "sizes", "directions", "file_name"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for idx, (conn, data) in enumerate(connections.items(), start=1):
                writer.writerow({
                    "index": idx,
                    "connection": str(conn),
                    "timestamps": ",".join(map(str, data["timestamps"])),
                    "sizes": str(data["sizes"]),
                    "directions": str(data["directions"]),
                    "file_name": os.path.basename(pcap_file)
                })
        logging.info(f"Completed : {os.path.basename(pcap_file)}")
    except Exception as e:
        logging.error(f"Error processing {pcap_file}: {str(e)}")

def merge_csv_files(csv_files, merged_csv):
    """Merges all processed CSV files into a single CSV file."""
    if not csv_files:
        logging.warning("No CSV files to merge.")
        return

    try:
        with open(merged_csv, "w", newline="") as outfile:
            fieldnames = ["index", "connection", "timestamps", "sizes", "directions", "file_name"]
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            index = 1
            for csv_file in csv_files:
                with open(csv_file, "r") as infile:
                    reader = csv.DictReader(infile)
                    for row in reader:
                        row["index"] = index  # Assigning a new global index
                        writer.writerow(row)
                        index += 1

        logging.info(f"Merged CSV saved as: {os.path.basename(merged_csv)}")
    except Exception as e:
        logging.error(f"Error merging CSV files: {str(e)}")

def process_pcap_wrapper(args):
    pcap_file, output_csv = args
    process_pcap(pcap_file, output_csv)
    print(f"Completed : {pcap_file}")
    return output_csv  # Return output CSV path for merging

def process_directory(input_dir, output_dir, current_dataset):
    """Processes a directory containing multiple PCAP files."""
    logging.info(f"Processing directory: {input_dir}")

    pcap_files = [
        (os.path.join(input_dir, filename), os.path.join(output_dir, filename.replace(".pcap", ".csv")))
        for filename in os.listdir(input_dir) if filename.endswith(".pcap")
    ]

    csv_files = []
    with ThreadPoolExecutor() as executor:
        csv_files = list(executor.map(process_pcap_wrapper, pcap_files))

    # Merge all CSV files into one
    os.makedirs(f"./../CSV", exist_ok=True)
    merged_csv = f"./../CSV/merged_output_{current_dataset}.csv"
    merge_csv_files(csv_files, merged_csv)
    print("Execution completed!")



# python merger.py ./../Dataset_SIT_diff_classes
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python merger.py <input_directory>")
        sys.exit(1)
    
    input_dir = sys.argv[1]

    # Extract CURRENT_DATASET from folder name
    CURRENT_DATASET = extract_dataset_name(input_dir)

    # Set up logging dynamically
    setup_logging(CURRENT_DATASET)

    # generate abbreviation for output dir.
    abbr = get_abbreviation(input_dir)
    output_dir = f"./../Output_parallel_{abbr}"
    os.makedirs(output_dir, exist_ok=True)

    # Process computing flows for diff. pcaps in //
    process_directory(input_dir, output_dir, CURRENT_DATASET)