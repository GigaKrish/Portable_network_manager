# ==============================================================================
# FILE: core/data_models.py
# PURPOSE: Defines shared data structures and global state.
# ==============================================================================
import collections
from threading import Lock
from typing import Dict, Any, Tuple

data_lock = Lock()
# Maps a connection tuple to a PID
connection_to_pid: Dict[Tuple, int] = {}
# Maps a PID to its process info and stats
process_traffic: Dict[int, Dict[str, Any]] = collections.defaultdict(
    lambda: {'name': 'N/A', 'in_count': 0, 'out_count': 0}
)
# Maps a remote IP to its info and stats
ip_traffic: Dict[str, Dict[str, Any]] = collections.defaultdict(
    lambda: {'in_count': 0, 'out_count': 0, 'hostname': 'N/A'}
)
# Caches DNS lookups
dns_cache = {}
# Stores recent packet rate history
packet_rate_history = collections.deque(maxlen=60)
# Global variable to hold the selected interface name
selected_interface = ""