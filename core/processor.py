# FILE: core/processor.py
# PURPOSE: Processes packets from the queue and updates data models.



import time
import socket
import psutil
from queue import Empty
from .data_models import (
    data_lock, connection_to_pid, process_traffic, ip_traffic,
    dns_cache, packet_rate_history
)

def update_connection_map():
    """Periodically updates the connection-to-pid mapping."""
    while True:
        try:
            local_map = {}
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.pid:
                    continue
                key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                local_map[key] = conn.pid
            with data_lock:
                connection_to_pid.clear()
                connection_to_pid.update(local_map)
        except psutil.Error:
            pass
        time.sleep(5)

def process_packets_from_queue(queue):
    """Processes packets, updates all data models, and handles DNS lookups."""
    last_rate_update = time.time()
    packet_count_since_last = 0
    while True:
        try:
            conn_tuple, direction, remote_ip = queue.get(timeout=1)
            packet_count_since_last += 1

            current_time = time.time()
            if current_time - last_rate_update >= 1.0:
                rate = packet_count_since_last / (current_time - last_rate_update)
                with data_lock:
                    packet_rate_history.append((int(current_time * 1000), rate))
                packet_count_since_last = 0
                last_rate_update = current_time

            with data_lock:
                if direction == 'in': ip_traffic[remote_ip]['in_count'] += 1
                else: ip_traffic[remote_ip]['out_count'] += 1
                
                pid = connection_to_pid.get(conn_tuple) or connection_to_pid.get((conn_tuple[2], conn_tuple[3], conn_tuple[0], conn_tuple[1]))
                if pid:
                    if process_traffic[pid]['name'] == 'N/A':
                        try: process_traffic[pid]['name'] = psutil.Process(pid).name()
                        except psutil.NoSuchProcess: del process_traffic[pid]; continue
                    if direction == 'in': process_traffic[pid]['in_count'] += 1
                    else: process_traffic[pid]['out_count'] += 1

            if remote_ip not in dns_cache:
                try: hostname, _, _ = socket.gethostbyaddr(remote_ip)
                except (socket.herror, socket.gaierror): hostname = remote_ip
                dns_cache[remote_ip] = hostname
                with data_lock:
                    if remote_ip in ip_traffic: ip_traffic[remote_ip]['hostname'] = hostname
        except Empty:
            continue
        except Exception:
            pass
