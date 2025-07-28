# PURPOSE: Main entry point for the application. Run this file.
# ==============================================================================
import multiprocessing
from threading import Thread
import uvicorn
import psutil
import socket

# Import from our new modular structure
from interface_selector import select_interface
from core.sniffer import start_monitoring
from core.processor import update_connection_map, process_packets_from_queue
from web.api import app
import core.data_models as data_models

def get_interface_ip(iface_name: str) -> str:
    """Gets the primary IPv4 address for a given interface name."""
    try:
        addrs = psutil.net_if_addrs().get(iface_name, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
    except Exception:
        return ""

if __name__ == '__main__':
    multiprocessing.freeze_support()
    
    # --- Initialization ---
    selected_iface = select_interface()
    data_models.selected_interface = selected_iface # Store globally for the API
    local_ip = get_interface_ip(selected_iface)
    if not local_ip:
        print(f"[Warning] Could not determine IP for {selected_iface}.")

    packet_queue = multiprocessing.Queue()
    
    # --- Start Background Tasks ---
    mapper_thread = Thread(target=update_connection_map, daemon=True)
    processor_thread = Thread(target=process_packets_from_queue, args=(packet_queue,), daemon=True)
    sniffer_process = multiprocessing.Process(
        target=start_monitoring, 
        args=(selected_iface, packet_queue, local_ip), 
        daemon=True
    )
    
    mapper_thread.start()
    processor_thread.start()
    sniffer_process.start()
    
    print("\n--- Network Task Monitor v2 ---")
    print(f"Starting server...")
    print(f"==> Open your browser to: http://127.0.0.1:8000 <==")
    print("---------------------------------")
    
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000)
    except Exception as e:
        print(f"\nAn error occurred during server execution: {e}")
    finally:
        if sniffer_process.is_alive():
            sniffer_process.terminate()
            sniffer_process.join()
        print("Monitoring stopped.")