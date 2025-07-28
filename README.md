# Portable_Network_Manager

Completely modular Portable Network Manger inspired by a Process Task Manager in OS,
hence a Network Manager for closed network or servers.

> [!IMPORTANT]
> You need admin privileges to execute the program properly!

### File Structure:
<pre>|-- net_task_monitor_v2.py 
|-- interface_selector.py  
|
|-- core/
|   |-- __init__.py
|   |-- data_models.py
|   |-- sniffer.py
|   |-- processor.py
|
|-- web/
|   |-- __init__.py
|   |-- api.py
|   |-- static/
|       |-- index.html
</pre>

### Usage:
1) Start IDE with **ADMIN PRIVILEGES** and execute net_task_monitor_v2.py .
2) Select choice from displayed network interface.
3) Use the given port to access monitoring API.
