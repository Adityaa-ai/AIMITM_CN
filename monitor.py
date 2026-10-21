
import threading
import time
from collections import deque
from datetime import datetime

from scapy.all import ARP, IP, Ether, AsyncSniffer
from sklearn.ensemble import IsolationForest


class LivePacketMonitor:
    WINDOW_SECONDS = 5
    BASELINE_WINDOWS = 12

    def __init__(self):
        self.lock = threading.Lock()
        self.sniffer = None
        self.running = False
        self.interface = None

        self.detector = IsolationForest(
            n_estimators=100,
            contamination=0.10,
            random_state=42
        )

        self.baseline = []
        self.trained = False
        self.history = deque(maxlen=50)
        self.events = deque(maxlen=100)

        self._reset_window()
        self.arp_table = {}

        self.status = "Stopped"
        self.error = None

    def _reset_window(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.arp_count = 0
        self.source_macs = set()
        self.source_ips = set()
        self.mac_changes = 0

    def _packet_callback(self, packet):
        with self.lock:
            self.packet_count += 1
            self.total_bytes += len(packet)

            if Ether in packet:
                mac = packet[Ether].src
                if mac:
                    self.source_macs.add(mac.lower())

            if IP in packet:
                self.source_ips.add(packet[IP].src)

            if ARP in packet:
                self.arp_count += 1
                arp = packet[ARP]

                # Track IP-to-MAC mappings from ARP replies.
                if int(arp.op) == 2:
                    ip = str(arp.psrc)
                    mac = str(arp.hwsrc).lower()

                    previous_mac = self.arp_table.get(ip)

                    if previous_mac and previous_mac != mac:
                        self.mac_changes += 1
                        self.events.appendleft({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "type": "ARP mapping change",
                            "message": (
                                f"{ip} was {previous_mac}; "
                                f"now observed as {mac}"
                            ),
                            "severity": "Warning"
                        })

                    self.arp_table[ip] = mac

    def _worker(self):
        try:
            while self.running:
                time.sleep(self.WINDOW_SECONDS)

                with self.lock:
                    if not self.running:
                        break

                    packets = self.packet_count
                    byte_count = self.total_bytes
                    arp_count = self.arp_count
                    mac_count = len(self.source_macs)
                    ip_count = len(self.source_ips)
                    mac_changes = self.mac_changes

                    self._reset_window()

                features = [
                    packets / self.WINDOW_SECONDS,
                    arp_count / self.WINDOW_SECONDS,
                    mac_count,
                    mac_changes,
                    ip_count,
                    byte_count / self.WINDOW_SECONDS
                ]

                result = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "packets_per_second": round(features[0], 2),
                    "arp_per_second": round(features[1], 2),
                    "unique_source_macs": int(features[2]),
                    "mac_changes": int(features[3]),
                    "unique_source_ips": int(features[4]),
                    "bytes_per_second": round(features[5], 2),
                    "classification": "Calibrating",
                    "anomaly_score": None
                }

                if not self.trained:
                    self.baseline.append(features)

                    if len(self.baseline) >= self.BASELINE_WINDOWS:
                        self.detector.fit(self.baseline)
                        self.trained = True
                        result["classification"] = (
                            "Baseline ready; next window will be analyzed"
                        )
                else:
                    prediction = self.detector.predict([features])[0]
                    score = float(self.detector.decision_function([features])[0])

                    result["anomaly_score"] = round(score, 4)
                    result["classification"] = (
                        "Anomaly" if prediction == -1 else "Normal"
                    )

                    if prediction == -1:
                        with self.lock:
                            self.events.appendleft({
                                "time": result["time"],
                                "type": "ML traffic anomaly",
                                "message": (
                                    "Traffic features differ from the "
                                    "learned baseline. Investigate the traffic."
                                ),
                                "severity": "Warning"
                            })

                with self.lock:
                    self.history.appendleft(result)

        except Exception as exc:
            self.error = str(exc)
            self.status = "Error"
        finally:
            self.running = False

    def start(self, interface=None):
        with self.lock:
            if self.running:
                return {"ok": False, "message": "Monitor is already running."}

            self.interface = interface
            self.error = None
            self.trained = False
            self.baseline = []
            self.history.clear()
            self.events.clear()
            self.arp_table.clear()
            self._reset_window()
            self.running = True
            self.status = "Starting"

        try:
            self.sniffer = AsyncSniffer(
                iface=interface,
                prn=self._packet_callback,
                store=False
            )
            self.sniffer.start()
        except Exception as exc:
            self.running = False
            self.status = "Error"
            self.error = str(exc)
            return {"ok": False, "message": str(exc)}

        threading.Thread(target=self._worker, daemon=True).start()
        self.status = "Monitoring"

        return {
            "ok": True,
            "message": "Live packet monitoring started."
        }

    def stop(self):
        self.running = False

        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
        except Exception as exc:
            self.error = str(exc)

        self.status = "Stopped"
        return {"ok": True, "message": "Monitoring stopped."}

    def snapshot(self):
        with self.lock:
            return {
                "running": self.running,
                "status": self.status,
                "interface": self.interface or "Default interface",
                "trained": self.trained,
                "baseline_windows": len(self.baseline),
                "required_baseline_windows": self.BASELINE_WINDOWS,
                "latest": self.history[0] if self.history else None,
                "history": list(self.history),
                "events": list(self.events),
                "error": self.error
            }


monitor = LivePacketMonitor()
