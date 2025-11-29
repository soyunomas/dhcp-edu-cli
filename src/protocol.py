import random
import time
import threading
from scapy.all import DHCP, BOOTP, Ether, IP, UDP, ARP, sniff, sendp, srp1, ICMP
from src.constants import *
from src.state import DHCPState

class DHCPClientCore:
    """
    Maneja la lógica de red, estados y tiempos del ciclo de vida DHCP.
    Cumple con RFC 2131 (Máquina de estados) y RFC 5227 (Detección de conflictos ACD).
    """
    def __init__(self, interface, mac_address, on_packet_received, on_log):
        self.interface = interface
        self.mac = mac_address
        self.on_packet_received = on_packet_received
        self.on_log = on_log
        
        # Estado DHCP
        self.state = DHCPState.INIT
        self.xid = None
        self.current_ip = None
        self.server_ip = None
        self.server_mac = None
        
        # Simulación Educativa
        self.force_conflict = False  # Bandera para el "Botón de Sabotaje"
        
        # Ciclo de Vida (Timers)
        self.lease_obtained_time = 0
        self.lease_total = 0
        self.t1 = 0
        self.t2 = 0
        
        # Hilos
        self.stop_sniffer = threading.Event()
        self.sniffer_thread = None
        self.monitor_thread = threading.Thread(target=self._lifecycle_monitor, daemon=True)
        self.monitor_thread.start()

        # Configuración "Modo Dios" (Paquetes Custom)
        self.default_config = {
            "ether_src": self.mac, "ether_dst": BROADCAST_MAC,
            "ip_src": ZERO_IP, "ip_dst": BROADCAST_IP,
            "bootp_xid": 0,
            "hostname": "dhcp-edu-client",
            "vendor_class_id": "", "client_id": "", "client_fqdn": "",
            "req_lease_time": 0, "max_msg_size": 1500,
            "param_req_list": [1, 3, 6, 15, 119]
        }
        self.config = self.default_config.copy()

    def reset_config(self):
        self.config = self.default_config.copy()
        self.config["ether_src"] = self.mac

    def _generate_new_xid(self):
        if self.config.get("bootp_xid", 0) != 0:
            self.xid = self.config["bootp_xid"]
        else:
            self.xid = random.randint(0, 0xFFFFFFFF)

    def change_mac(self):
        new_mac = "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
        )
        self.mac = new_mac
        self.config["ether_src"] = new_mac
        self.reset_data()
        self.on_log(f"🎭 Nueva Identidad MAC generada: {self.mac}", "bold magenta")
        return self.mac

    # --- NETWORK LOOP ---
    def start_listening(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive(): return
        self.stop_sniffer.clear()
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        self.on_log("👂 Escuchando tráfico DHCP, ARP e ICMP...", "info")

    def _sniff_loop(self):
        dhcp_filter = f"(udp and (port {SERVER_PORT} or port {CLIENT_PORT})) or arp or icmp"
        
        def process_packet(pkt):
            # 1. DHCP Handling
            if DHCP in pkt and BOOTP in pkt:
                is_for_me = False
                
                # --- CORRECCIÓN CRÍTICA DE SCAPY (SIGNED INT BUG) ---
                packet_xid = pkt[BOOTP].xid & 0xFFFFFFFF
                
                if packet_xid == self.xid: is_for_me = True
                elif self.current_ip and IP in pkt and pkt[IP].dst == self.current_ip: is_for_me = True
                
                if is_for_me: self.on_packet_received(pkt)

            # 2. ARP Handling (Defensa de IP)
            if ARP in pkt and pkt[ARP].op == 1: # Who has?
                if self.current_ip and pkt[ARP].pdst == self.current_ip:
                    self.on_log(f"🛡️ ARP Request recibido por {self.current_ip}. Defendiendo...", "dim blue")
                    arp_reply = Ether(src=self.mac, dst=pkt[ARP].hwsrc) / ARP(
                        op=2, hwsrc=self.mac, psrc=self.current_ip,
                        hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc
                    )
                    sendp(arp_reply, iface=self.interface, verbose=False)

            # 3. ICMP Handling (Ping Reply)
            if ICMP in pkt and pkt[ICMP].type == 8: # Echo Request
                if self.current_ip and IP in pkt and pkt[IP].dst == self.current_ip:
                    self.on_log(f"🏓 PING recibido de {pkt[IP].src}", "dim green")
                    icmp_reply = (
                        Ether(src=self.mac, dst=pkt[Ether].src) /
                        IP(src=self.current_ip, dst=pkt[IP].src) /
                        ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
                        pkt[ICMP].payload
                    )
                    sendp(icmp_reply, iface=self.interface, verbose=False)

        sniff(
            iface=self.interface, filter=dhcp_filter, prn=process_packet,
            store=0, stop_filter=lambda x: self.stop_sniffer.is_set()
        )

    def stop(self):
        self.stop_sniffer.set()

    # --- LIFECYCLE MONITOR (T1/T2) ---
    def _lifecycle_monitor(self):
        """Monitor de tiempos según RFC 2131 Sec 4.4.5"""
        while True:
            time.sleep(1)
            if self.state not in [DHCPState.BOUND, DHCPState.RENEWING] or self.lease_obtained_time == 0:
                continue
            
            elapsed = time.time() - self.lease_obtained_time
            
            if elapsed >= self.t2:
                if self.state != DHCPState.REBINDING:
                    self.state = DHCPState.REBINDING
                    self.on_log("⏰ T2 Expirado: Servidor original no responde.", "bold red")
                    self.on_log("   -> Entrando en REBINDING (Broadcast a cualquiera)", "bold red")
                    self.send_rebind_request()
            
            elif elapsed >= self.t1:
                if self.state == DHCPState.BOUND:
                    self.state = DHCPState.RENEWING
                    self.on_log("⏰ T1 Expirado: Tiempo de renovar.", "bold yellow")
                    self.on_log("   -> Entrando en RENEWING (Unicast al Servidor)", "bold yellow")
                    self.send_renew()

            if elapsed >= self.lease_total:
                self.on_log("💀 LEASE EXPIRADO: Se ha perdido la IP.", "bold magenta")
                self.reset_data()

    # --- DHCP PACKET BUILDERS ---
    def _build_common_options(self, msg_type):
        opts = [("message-type", msg_type)]
        if self.config["max_msg_size"]: opts.append(("max_dhcp_size", self.config["max_msg_size"]))
        if self.config["hostname"]: opts.append(("hostname", self.config["hostname"]))
        if self.config["client_fqdn"]: opts.append(("client_fqdn", self.config["client_fqdn"]))
        if self.config["vendor_class_id"]: opts.append(("vendor_class_id", self.config["vendor_class_id"]))
        if self.config["client_id"]: opts.append(("client_id", self.config["client_id"]))
        if self.config["req_lease_time"] > 0: opts.append(("lease_time", self.config["req_lease_time"]))
        return opts

    def send_discover(self):
        self._generate_new_xid()
        self.state = DHCPState.SELECTING
        self.on_log(f"🚀 Enviando DISCOVER (XID: {hex(self.xid)})", "bold yellow")
        
        dhcp_opts = self._build_common_options("discover")
        dhcp_opts.append(("param_req_list", self.config["param_req_list"]))
        dhcp_opts.append("end")
        
        pkt = (
            Ether(src=self.config["ether_src"], dst=self.config["ether_dst"]) /
            IP(src=self.config["ip_src"], dst=self.config["ip_dst"]) /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid, flags=0x8000) /
            DHCP(options=dhcp_opts)
        )
        sendp(pkt, iface=self.interface, verbose=False)

    def send_request(self, requested_ip, server_id):
        self.state = DHCPState.REQUESTING
        self.on_log(f"📝 Enviando REQUEST por {requested_ip}", "bold cyan")
        
        dhcp_opts = self._build_common_options("request")
        dhcp_opts.append(("requested_addr", requested_ip))
        dhcp_opts.append(("server_id", server_id))
        dhcp_opts.append(("param_req_list", self.config["param_req_list"]))
        dhcp_opts.append("end")
        
        pkt = (
            Ether(src=self.config["ether_src"], dst=self.config["ether_dst"]) /
            IP(src=self.config["ip_src"], dst=self.config["ip_dst"]) /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid, flags=0x8000) /
            DHCP(options=dhcp_opts)
        )
        sendp(pkt, iface=self.interface, verbose=False)

    def send_renew(self):
        dhcp_opts = self._build_common_options("request")
        dhcp_opts.append("end")
        
        dst_mac = self.server_mac if self.server_mac else BROADCAST_MAC
        pkt = (Ether(src=self.mac, dst=dst_mac) / 
               IP(src=self.current_ip, dst=self.server_ip) / 
               UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / 
               BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) / 
               DHCP(options=dhcp_opts))
        sendp(pkt, iface=self.interface, verbose=False)

    def send_rebind_request(self):
        dhcp_opts = self._build_common_options("request")
        dhcp_opts.append("end")

        pkt = (Ether(src=self.mac, dst=BROADCAST_MAC) / 
               IP(src=self.current_ip, dst=BROADCAST_IP) / 
               UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / 
               BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) / 
               DHCP(options=dhcp_opts))
        sendp(pkt, iface=self.interface, verbose=False)

    def send_decline(self, server_ip, requested_ip):
        self.state = DHCPState.DECLINING
        self.on_log(f"⚠️ Enviando DECLINE por {requested_ip} (Conflicto)", "bold red")
        
        dhcp_opts = [("message-type", "decline"), 
                     ("requested_addr", requested_ip), 
                     ("server_id", server_ip), 
                     "end"]
                     
        pkt = (Ether(src=self.mac, dst=BROADCAST_MAC) / 
               IP(src=ZERO_IP, dst=BROADCAST_IP) / 
               UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / 
               BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) / 
               DHCP(options=dhcp_opts))
        sendp(pkt, iface=self.interface, verbose=False)
        self.reset_data()

    def send_release(self):
        if not self.current_ip: return
        self.on_log(f"👋 Enviando RELEASE para {self.current_ip}", "bold magenta")
        dst_mac = self.server_mac if self.server_mac else BROADCAST_MAC
        
        pkt = (Ether(src=self.mac, dst=dst_mac) / 
               IP(src=self.current_ip, dst=self.server_ip) / 
               UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / 
               BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) / 
               DHCP(options=[("message-type", "release"), ("server_id", self.server_ip), "end"]))
        sendp(pkt, iface=self.interface, verbose=False)
        self.reset_data()

    def send_init_reboot(self, bad_ip="10.20.30.40"):
        self._generate_new_xid()
        self.state = DHCPState.REQUESTING 
        self.on_log(f"⚡ Enviando REQUEST Directo (Init-Reboot) por {bad_ip}...", "bold yellow")
        dhcp_opts = [("message-type", "request"), ("requested_addr", bad_ip), ("param_req_list", [1, 3, 6, 15]), "end"]
        pkt = (Ether(src=self.mac, dst=BROADCAST_MAC) / IP(src=ZERO_IP, dst=BROADCAST_IP) / UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid, flags=0x8000) / DHCP(options=dhcp_opts))
        sendp(pkt, iface=self.interface, verbose=False)

    # --- ARP & CONFLICT FUNCTIONS ---

    def send_arp_probe_blocking(self, target_ip, timeout=1):
        """
        RFC 5227: ARP Probe.
        Envía un ARP Request para ver si alguien responde.
        """
        # 1. Enviar el paquete REAL (Ahora con src=self.mac para que coincida en tcpdump)
        probe = Ether(src=self.mac, dst=BROADCAST_MAC) / \
                ARP(op=1, hwsrc=self.mac, psrc="0.0.0.0", hwdst="00:00:00:00:00:00", pdst=target_ip)
        sendp(probe, iface=self.interface, verbose=False)
        
        # 2. Verificar simulación
        if self.force_conflict:
            self.on_log("⚡ [SIMULACIÓN] Forzando detección de conflicto ARP...", "bold red")
            return True

        # 3. Esperar respuesta real
        ans = srp1(probe, iface=self.interface, timeout=timeout, verbose=0)
        return ans is not None

    def send_gratuitous_arp(self):
        """RFC 5227: Announcement."""
        if not self.current_ip: return
        garp = Ether(src=self.mac, dst=BROADCAST_MAC) / \
               ARP(op=2, hwsrc=self.mac, psrc=self.current_ip, hwdst=BROADCAST_MAC, pdst=self.current_ip)
        sendp(garp, iface=self.interface, verbose=False)

    def reset_data(self):
        self.current_ip = None
        self.server_ip = None
        self.lease_obtained_time = 0
        self.lease_total = 0
        self.t1 = 0
        self.t2 = 0
        self.state = DHCPState.INIT
        # FIX: No reseteamos force_conflict aquí. 
        # Si el usuario lo activó antes de liberar, debe persistir.
