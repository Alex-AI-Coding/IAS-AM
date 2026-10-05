import threading
import time
import logging
from scapy.all import sniff, IP, TCP, UDP
import psutil

logger = logging.getLogger(__name__)

class NetworkMonitorService:
    def __init__(self, alert_callback=None, poll_interval=5):
        """
        Hybrid Network Traffic & Connection Monitor Service.
        Combines psutil background polling (for process attribution and threat intel)
        with Scapy packet sniffing (for payload inspection).
        """
        self.alert_callback = alert_callback
        self.poll_interval = poll_interval
        
        self._running = False
        self._psutil_thread = None
        self._scapy_thread = None
        
        self.connection_map = {}
        self.map_lock = threading.Lock()
        
        self.blacklist_ips = {"198.51.100.42", "203.0.113.88"}
        self.suspicious_ports = {4444, 6667, 1337, 31337}
        self.suspicious_keywords = [b"malware", b"cmd.exe", b"/bin/sh", b"eval("]

    def start(self):
        """Starts both the psutil connection poller and scapy sniffer background threads."""
        if self._running:
            logger.warning("NetworkMonitorService is already running.")
            return

        self._running = True
        logger.info("Starting NetworkMonitorService background threads...")

        self._psutil_thread = threading.Thread(target=self._psutil_worker, daemon=True)
        self._psutil_thread.start()

        self._scapy_thread = threading.Thread(target=self._scapy_worker, daemon=True)
        self._scapy_thread.start()

    def stop(self):
        """Gracefully stops all background monitoring threads."""
        if not self._running:
            return
            
        logger.info("Stopping NetworkMonitorService...")
        self._running = False
        
        if self._psutil_thread:
            self._psutil_thread.join(timeout=2)
        if self._scapy_thread:
            self._scapy_thread.join(timeout=2)
            
        logger.info("NetworkMonitorService stopped successfully.")

    def _psutil_worker(self):
        """Periodically maps active local sockets to system processes and checks blacklists."""
        while self._running:
            try:
                new_map = {}
                for conn in psutil.net_connections(kind='inet'):
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        pid = conn.pid
                        
                        proc_name = "Unknown"
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                proc_name = "Terminated/Inaccessible"
                        
                        new_map[(remote_ip, remote_port)] = (pid, proc_name)
                        
                        if remote_ip in self.blacklist_ips:
                            self._trigger_alert({
                                "type": "BLACKLIST_IP",
                                "severity": "HIGH",
                                "ip": remote_ip,
                                "port": remote_port,
                                "pid": pid,
                                "process": proc_name,
                                "details": f"Active connection to blacklisted IP {remote_ip}"
                            })

                with self.map_lock:
                    self.connection_map = new_map

            except Exception as e:
                logger.error(f"Error in network psutil worker: {e}")

            for _ in range(self.poll_interval):
                if not self._running:
                    break
                time.sleep(1)

    def _scapy_worker(self):
        """Sniffs live packets for deep packet inspection (payload keywords & suspicious ports)."""
        def packet_callback(packet):
            if not self._running:
                return
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    sport, dport = None, None
                    if TCP in packet:
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                    elif UDP in packet:
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                    
                    local_app = "Unknown App"
                    with self.map_lock:
                        if (src_ip, sport) in self.connection_map:
                            pid, name = self.connection_map[(src_ip, sport)]
                            local_app = f"{name} (PID {pid})"
                        elif (dst_ip, dport) in self.connection_map:
                            pid, name = self.connection_map[(dst_ip, dport)]
                            local_app = f"{name} (PID {pid})"

                    if dport in self.suspicious_ports or sport in self.suspicious_ports:
                        target_port = dport if dport in self.suspicious_ports else sport
                        self._trigger_alert({
                            "type": "SUSPICIOUS_PORT",
                            "severity": "MEDIUM",
                            "ip": dst_ip,
                            "port": target_port,
                            "process": local_app,
                            "details": f"Traffic routed through high-risk port {target_port}"
                        })

                    if packet.haslayer('Raw'):
                        payload = packet['Raw'].load
                        for kw in self.suspicious_keywords:
                            if kw in payload:
                                self._trigger_alert({
                                    "type": "PAYLOAD_SIGNATURE",
                                    "severity": "HIGH",
                                    "ip": dst_ip,
                                    "port": dport,
                                    "process": local_app,
                                    "details": f"Matched malicious keyword signature: {kw.decode('utf-8', errors='ignore')}"
                                })
                                break
            except Exception as e:
                pass

        try:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self._running)
        except Exception as e:
            logger.error(f"Scapy sniffer encountered an error (are privileges/Npcap configured?): {e}")

    def _trigger_alert(self, alert_data):
        """Dispatches structured alerts safely to the application's callback/UI listener."""
        logger.warning(f"Security Alert Triggered: {alert_data}")
        if self.alert_callback:
            try:
                self.alert_callback(alert_data)
            except Exception as e:
                logger.error(f"Error in alert_callback execution: {e}")