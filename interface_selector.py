# FILE: interface_selector.py
# PURPOSE: Reusable module to find and select a network interface.


try:
    import psutil
    import sys
    import socket
except ImportError:
    print("Error: Required libraries not found. Please run: pip install psutil")
    sys.exit(1)

def select_interface():
    """
    Lists all network interfaces with their status (online/offline).
    Returns the name of the selected interface.
    """
    print("Detecting network interfaces...")
    try:
        interfaces_addrs = psutil.net_if_addrs()
        interfaces_stats = psutil.net_if_stats()
        interface_list = list(interfaces_addrs.keys())
    except Exception as e:
        print(f"Unable to retrieve interfaces: {e}")
        sys.exit(1)

    if not interface_list:
        print("Error: No network interfaces found on this system.")
        sys.exit(1)

    print("Please select the network interface you want to use:")
    for i, iface_name in enumerate(interface_list):
        status_text = "[OFF]"
        if iface_name in interfaces_stats and interfaces_stats[iface_name].isup:
            status_text = "[ON]"

        ip_address = ""
        if iface_name in interfaces_addrs:
            for addr in interfaces_addrs[iface_name]:
                if addr.family == socket.AF_INET:
                    ip_address = f"(IP: {addr.address})"
                    break
        
        print(f"  {i + 1}: {status_text} {iface_name} {ip_address}")

    while True:
        try:
            choice = int(input(f"Enter the number (1-{len(interface_list)}): "))
            if 1 <= choice <= len(interface_list):
                return interface_list[choice - 1]
            else:
                print("Invalid number. Please try again.")
        except (ValueError, KeyboardInterrupt):
            print("\nSelection cancelled. Exiting.")
            sys.exit(0)
