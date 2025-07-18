# interface_selector.py
# A reusable module to find and select a network interface.
try:
    import psutil
    import sys
    import socket
except ImportError:
    print("Error: Required libraries not found.")
    sys.exit(1)

def select_interface():
    """
    Lists all network interfaces with their status (online/offline).
    Returns the name of the user selected interface.
    """
    print("Detecting network interfaces...")
    try:
        # Get a dictionary of all network interface addresses
        interfaces_addrs = psutil.net_if_addrs()
        # Get a dictionary of all network interface stats (for status)
        interfaces_stats = psutil.net_if_stats()
        interface_list = list(interfaces_addrs.keys())
    except Exception as e:
        print(f"Could not retrieve interfaces: {e}")
        sys.exit(1)

    if not interface_list:
        print("Error: No network interfaces found on this system.")
        sys.exit(1)

    print("Please select the network interface you want to use:")
    for i, iface_name in enumerate(interface_list):
        # Check if the interface is up (online) and set status emoji
        status_emoji = "🔴"  # Default to offline
        if iface_name in interfaces_stats and interfaces_stats[iface_name].isup:
            status_emoji = "🟩"  # Set to online if 'isup' is true

        # Find the primary IPv4 address to make the choice clearer
        ip_address = ""
        if iface_name in interfaces_addrs:
            for addr in interfaces_addrs[iface_name]:
                if addr.family == socket.AF_INET:
                    ip_address = f"(IP: {addr.address})"
                    break


        print(f"  {i + 1}: {status_emoji} {iface_name} {ip_address}")

    while True:
        try:
            choice = int(input(f"Enter the number (1-{len(interface_list)}): "))
            if 1 <= choice <= len(interface_list):
                # Return the string name of the chosen interface
                return interface_list[choice - 1]
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except (EOFError, KeyboardInterrupt):
            print("\nSelection cancelled. Exiting.")
            sys.exit(0)



if __name__ == '__main__':
    print("--- Interface Selector Test ---")
    selected_interface = select_interface()
    print(f"\nYou selected: {selected_interface}")
    print("-----------------------------")
