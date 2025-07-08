#!/usr/bin/env python3

# --- Core Libraries ---
import sys
import time
import socket
import collections
import multiprocessing
import asyncio
import json
from queue import Empty
from threading import Thread, Lock
from typing import List, Dict, Any, Tuple
from contextlib import asynccontextmanager

# Make sure to install these: pip install scapy psutil "fastapi[all]" uvicorn websockets
try:
    from scapy.all import sniff, IP, TCP, UDP
    import psutil
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
except ImportError:
    print("Error: Required libraries not found.")
    print("Please install them using: pip install scapy psutil \"fastapi[all]\" uvicorn websockets")
    sys.exit(1)

# --- Local Modules ---
try:
    from interface_selector import select_interface
except ImportError:
    print("Error: 'interface_selector.py' not found.")
    print("Please ensure it's in the same directory as this script.")
    sys.exit(1)

# --- Global Data Structures & Locks ---
data_lock = Lock()
# --- Process-level data ---
connection_to_pid: Dict[Tuple, int] = {}
process_traffic: Dict[int, Dict[str, Any]] = collections.defaultdict(
    lambda: {'name': 'N/A', 'in_count': 0, 'out_count': 0}
)
# --- IP-level data ---
ip_traffic: Dict[str, Dict[str, Any]] = collections.defaultdict(
    lambda: {'in_count': 0, 'out_count': 0, 'hostname': 'N/A'}
)
dns_cache = {}
packet_rate_history = collections.deque(maxlen=60)
selected_interface = ""


# --- Backend ---

def get_interface_ip(iface_name: str) -> str:
    try:
        addrs = psutil.net_if_addrs().get(iface_name, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
    except Exception:
        return ""


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
                global connection_to_pid
                connection_to_pid = local_map
        except psutil.Error:
            pass
        time.sleep(5)


def packet_callback(packet, queue, local_ip):
    """Places packet info into a queue for processing."""
    try:
        if IP not in packet or not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return

        src_ip, dst_ip = packet[IP].src, packet[IP].dst

        # Only process packets involving the local machine
        if src_ip != local_ip and dst_ip != local_ip:
            return

        proto = packet.getlayer(TCP) or packet.getlayer(UDP)
        conn_tuple = (src_ip, proto.sport, dst_ip, proto.dport)

        direction = "out" if src_ip == local_ip else "in"
        remote_ip = dst_ip if direction == "out" else src_ip

        queue.put((conn_tuple, direction, remote_ip))

    except Exception:
        pass


def start_monitoring(interface, queue, local_ip):
    """Target function for the sniffing process."""
    print(f"\n[Sniffer] Starting monitoring on interface: {interface} ({local_ip})")
    try:
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, queue, local_ip), store=0)
    except Exception as e:
        print(f"\n[Sniffer] An error occurred: {e}")


def process_packets_from_queue(queue):
    """Processes packets, updates all data models, and handles DNS lookups."""
    last_rate_update = time.time()
    packet_count_since_last = 0

    while True:
        try:
            conn_tuple, direction, remote_ip = queue.get(timeout=1)
            packet_count_since_last += 1

            # Update rate history every second
            current_time = time.time()
            if current_time - last_rate_update >= 1.0:
                rate = packet_count_since_last / (current_time - last_rate_update)
                with data_lock:
                    packet_rate_history.append((int(current_time * 1000), rate))
                packet_count_since_last = 0
                last_rate_update = current_time

            with data_lock:
                # --- Update IP-level data ---
                if direction == 'in':
                    ip_traffic[remote_ip]['in_count'] += 1
                else:
                    ip_traffic[remote_ip]['out_count'] += 1

                # --- Update Process-level data ---
                pid = connection_to_pid.get(conn_tuple) or connection_to_pid.get(
                    (conn_tuple[2], conn_tuple[3], conn_tuple[0], conn_tuple[1]))
                if pid:
                    if process_traffic[pid]['name'] == 'N/A':
                        try:
                            process_traffic[pid]['name'] = psutil.Process(pid).name()
                        except psutil.NoSuchProcess:
                            del process_traffic[pid]
                            continue

                    if direction == 'in':
                        process_traffic[pid]['in_count'] += 1
                    else:
                        process_traffic[pid]['out_count'] += 1

            # --- Handle DNS Lookup (outside lock) ---
            if remote_ip not in dns_cache:
                try:
                    hostname, _, _ = socket.gethostbyaddr(remote_ip)
                    dns_cache[remote_ip] = hostname
                except (socket.herror, socket.gaierror):
                    dns_cache[remote_ip] = remote_ip

                with data_lock:
                    if remote_ip in ip_traffic:
                        ip_traffic[remote_ip]['hostname'] = dns_cache[remote_ip]

        except Empty:
            continue
        except Exception as e:
            print(f"[Processor] Error: {e}")


# --- Frontend: FastAPI Web Server ---

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


async def broadcast_data():
    """Broadcasts the combined data model to all clients."""
    while True:
        with data_lock:
            # --- Prepare IP data ---
            sorted_ips = sorted(ip_traffic.items(), key=lambda item: item[1]['in_count'] + item[1]['out_count'],
                                reverse=True)
            top_talkers_payload = [
                {'ip': ip, 'in_count': data['in_count'], 'out_count': data['out_count'], 'hostname': data['hostname']}
                for ip, data in sorted_ips[:30]
            ]

            # --- Prepare Process data ---
            sorted_pids = sorted(process_traffic.keys(),
                                 key=lambda pid: process_traffic[pid]['in_count'] + process_traffic[pid]['out_count'],
                                 reverse=True)
            process_payload = [
                {'pid': pid, 'name': proc_data['name'], 'in_count': proc_data['in_count'],
                 'out_count': proc_data['out_count']}
                for pid, proc_data in [(p, process_traffic[p]) for p in sorted_pids[:30]]
            ]

            payload = {
                'type': 'update',
                'interface': selected_interface,
                'packet_rate': list(packet_rate_history),
                'top_talkers': top_talkers_payload,
                'processes': process_payload
            }
        await manager.broadcast(json.dumps(payload))
        await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(broadcast_data())
    yield


app = FastAPI(lifespan=lifespan)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Request Manager </title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <style>
        html.dark body { background-color: #111827; color: #e5e7eb; }
        .card { background-color: white; }
        html.dark .card { background-color: #1f2937; }
        .chart-container { height: 250px; }
        .tab-button { transition: all 0.2s; }
        .tab-button.active { border-color: #3b82f6; color: #3b82f6; }
    </style>
</head>
<body class="p-4 md:p-6">
    <div class="max-w-7xl mx-auto">
        <header class="mb-6">
            <h1 class="text-3xl font-bold">Network Request Manager </h1>
            <p class="text-gray-500 dark:text-gray-400">Interface: <span id="interfaceName" class="font-semibold text-cyan-500">...</span></p>
        </header>

        <div class="card shadow-lg rounded-lg p-4 md:p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4">Live Packet Rate (packets/sec)</h2>
            <div class="chart-container">
                <canvas id="rateChart"></canvas>
            </div>
        </div>

        <div class="card shadow-lg rounded-lg p-4 md:p-6">
            <!-- Tabs -->
            <div class="border-b border-gray-200 dark:border-gray-700 mb-4">
                <nav class="-mb-px flex space-x-8" aria-label="Tabs">
                    <button id="tab-processes" class="tab-button active whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm">By Process</button>
                    <button id="tab-connections" class="tab-button whitespace-nowrap py-4 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300 dark:hover:border-gray-600 font-medium text-sm">By Connection</button>
                </nav>
            </div>

            <!-- Tab Content -->
            <div id="content-processes" class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-800">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">PID</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Process Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Packets (In/Out)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="processTableBody" class="divide-y divide-gray-200 dark:divide-gray-700"></tbody>
                </table>
            </div>
            <div id="content-connections" class="overflow-x-auto hidden">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                     <thead class="bg-gray-50 dark:bg-gray-800">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Direction</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Remote IP</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Hostname</th>
                            <th class="px-6 py-3 text-left text-xs font-medium uppercase">Packets (In/Out)</th>
                        </tr>
                    </thead>
                    <tbody id="connectionTableBody" class="divide-y divide-gray-200 dark:divide-gray-700"></tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const rateCtx = document.getElementById('rateChart').getContext('2d');
        const rateChart = new Chart(rateCtx, {
            type: 'line',
            data: { datasets: [{ label: 'Packets/sec', data: [], borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', fill: true, tension: 0.4 }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }, x: { type: 'time', time: { unit: 'second', displayFormats: { second: 'HH:mm:ss' }}, ticks: { color: '#9ca3af', maxRotation: 0, autoSkip: true, maxTicksLimit: 10 }, grid: { display: false } } }, plugins: { legend: { display: false } }, animation: { duration: 0 } }
        });

        const processTableBody = document.getElementById('processTableBody');
        const connectionTableBody = document.getElementById('connectionTableBody');

        function updateDashboard(data) {
            document.getElementById('interfaceName').textContent = data.interface;
            rateChart.data.datasets[0].data = data.packet_rate.map(point => ({ x: point[0], y: point[1] }));
            rateChart.update();

            let processHtml = '';
            data.processes.forEach(proc => {
                processHtml += `<tr class="hover:bg-gray-100 dark:hover:bg-gray-700">
                    <td class="px-6 py-4">${proc.pid}</td>
                    <td class="px-6 py-4 font-semibold">${proc.name}</td>
                    <td class="px-6 py-4"><span class="text-green-500">⬇️ ${proc.in_count}</span> / <span class="text-blue-500">⬆️ ${proc.out_count}</span></td>
                    <td class="px-6 py-4"><button onclick="terminateProcess(${proc.pid})" class="px-3 py-1 text-xs text-white bg-red-600 rounded hover:bg-red-700">Terminate</button></td>
                </tr>`;
            });
            processTableBody.innerHTML = processHtml;

            let connectionHtml = '';
            data.top_talkers.forEach(item => {
                const directionIcon = item.in_count > item.out_count ? '⬇️' : '⬆️';
                connectionHtml += `<tr class="hover:bg-gray-100 dark:hover:bg-gray-700">
                    <td class="px-6 py-4 text-lg">${directionIcon}</td>
                    <td class="px-6 py-4">${item.ip}</td>
                    <td class="px-6 py-4">${item.hostname}</td>
                    <td class="px-6 py-4"><span class="text-green-500">${item.in_count}</span> / <span class="text-blue-500">${item.out_count}</span></td>
                </tr>`;
            });
            connectionTableBody.innerHTML = connectionHtml;
        }

        async function terminateProcess(pid) {
            if (!confirm('Are you sure you want to terminate process ' + pid + '?')) return;
            const response = await fetch('/api/process/' + pid + '/terminate', { method: 'POST' });
            const result = await response.json();
            alert(result.message);
        }

        const ws = new WebSocket('ws://' + window.location.host + '/ws');
        ws.onmessage = (event) => updateDashboard(JSON.parse(event.data));

        // Tab functionality
        const tabProcesses = document.getElementById('tab-processes');
        const tabConnections = document.getElementById('tab-connections');
        const contentProcesses = document.getElementById('content-processes');
        const contentConnections = document.getElementById('content-connections');

        tabProcesses.addEventListener('click', () => {
            tabProcesses.classList.add('active');
            tabConnections.classList.remove('active');
            contentProcesses.classList.remove('hidden');
            contentConnections.classList.add('hidden');
        });

        tabConnections.addEventListener('click', () => {
            tabConnections.classList.add('active');
            tabProcesses.classList.remove('active');
            contentConnections.classList.remove('hidden');
            contentProcesses.classList.add('hidden');
        });
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def get_root():
    return HTML_TEMPLATE


@app.post("/api/process/{pid}/terminate", response_class=JSONResponse)
async def api_terminate_process(pid: int):
    try:
        p = psutil.Process(pid)
        p.terminate()
        message = f"Successfully sent termination signal to process {pid} ({p.name()})."
        return {"status": "success", "message": message}
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process with PID {pid} not found.")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail=f"Access denied. Cannot terminate process {pid}.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# --- Main Application Execution ---

if __name__ == '__main__':
    multiprocessing.freeze_support()

    selected_interface = select_interface()
    local_ip = get_interface_ip(selected_interface)
    if not local_ip:
        print(f"[Warning] Could not determine IP for {selected_interface}. Directionality may be incorrect.")

    packet_queue = multiprocessing.Queue()

    # Start all background threads and processes
    mapper_thread = Thread(target=update_connection_map, daemon=True)
    mapper_thread.start()

    processor_thread = Thread(target=process_packets_from_queue, args=(packet_queue,), daemon=True)
    processor_thread.start()

    sniffer_process = multiprocessing.Process(target=start_monitoring,
                                              args=(selected_interface, packet_queue, local_ip), daemon=True)
    sniffer_process.start()

    try:
        uvicorn.run(app, host="127.0.0.1", port=8000)
    except Exception as e:
        print(f"\nAn error occurred during server execution: {e}")
    finally:
        if sniffer_process.is_alive():
            sniffer_process.terminate()
            sniffer_process.join()
        print("Monitoring stopped.")
