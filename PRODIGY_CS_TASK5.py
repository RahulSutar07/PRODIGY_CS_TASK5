import psutil
import socket
import logging
from datetime import datetime

class NetworkAnalyzer:
    def __init__(self, log_file='network_log.txt', max_connections=50):
        logging.basicConfig(
            filename=log_file, 
            level=logging.INFO, 
            format='%(asctime)s - %(message)s'
        )
        self.max_connections = max_connections

    def analyze_network_connections(self):
        print("🔍 Comprehensive Network Connection Analyzer")
        print("Warning: Authorized educational use only\n")

        # Extended headers for detailed information
        print(f"{'Local Address':<30} {'Remote Address':<40} {'Protocol':<10} {'Status':<15} {'Process'}")
        print("-" * 110)

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    # Determine protocol
                    protocol = self._get_protocol(conn)
                    
                    # Format addresses
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # Get process details
                    process_name = self._get_process_name(conn.pid)
                    
                    # Formatted connection details
                    connection_info = (
                        f"{local_addr:<30} {remote_addr:<40} "
                        f"{protocol:<10} {conn.status:<15} {process_name}"
                    )
                    
                    print(connection_info)
                    logging.info(connection_info)
                    
                    # Stop if max connections reached
                    if len(list(psutil.net_connections())) >= self.max_connections:
                        break

        except Exception as e:
            print(f"Error analyzing connections: {e}")

    def _get_process_name(self, pid):
        """Get process name with error handling."""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"

    def _get_protocol(self, connection):
        """Determine network protocol."""
        try:
            if connection.type == socket.SOCK_STREAM:
                return 'TCP'
            elif connection.type == socket.SOCK_DGRAM:
                return 'UDP'
            else:
                return 'Other'
        except Exception:
            return 'Unknown'

def main():
    analyzer = NetworkAnalyzer()
    analyzer.analyze_network_connections()

if __name__ == "__main__":
    main()