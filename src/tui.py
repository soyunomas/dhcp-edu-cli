import time
import threading
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal, VerticalScroll, Grid
from textual.widgets import Header, Footer, Static, Button, Log, Label, Rule, Input
from textual.screen import Screen
from textual.reactive import reactive
from scapy.all import DHCP, BOOTP, Ether, IP

from src.protocol import DHCPClientCore
from src.state import DHCPState
from src.explainer import DHCPExplainer
from src.constants import *

# --- WIDGETS DE ESTADO ---

class StateDisplay(Static):
    state_name = reactive("INIT")
    current_ip = reactive("---")
    server_ip = reactive("---")
    mac_addr = reactive("---")

    def compose(self) -> ComposeResult:
        with Vertical(classes="info-box"):
            yield Label("ESTADO:", classes="info-title")
            yield Label(self.state_name, id="state_label")
            yield Rule(line_style="dashed", classes="dashed-rule") 
            yield Label(f"MAC: {self.mac_addr}", id="mac_label", classes="info-text")
            yield Label(f"IP: {self.current_ip}", id="ip_label", classes="info-text")
            yield Label(f"Srv: {self.server_ip}", id="server_label", classes="info-text")

    def watch_state_name(self, new_state):
        try:
            label = self.query_one("#state_label", Label)
            color = "white"
            state_str = str(new_state)
            if state_str == "BOUND": color = "bold green"
            elif state_str in ["SELECTING", "REQUESTING", "RENEWING"]: color = "bold yellow"
            elif state_str == "INIT": color = "dim white"
            elif state_str in ["NAK", "DECLINING", "REBINDING"]: color = "bold red"
            label.update(Text(state_str, style=color))
        except: pass

    def watch_current_ip(self, val): 
        try: self.query_one("#ip_label").update(f"IP: {val}")
        except: pass
    def watch_server_ip(self, val): 
        try: self.query_one("#server_label").update(f"Srv: {val}")
        except: pass
    def watch_mac_addr(self, val): 
        try: self.query_one("#mac_label").update(f"MAC: {val}")
        except: pass

class TimerDisplay(Static):
    remaining_t1 = reactive(0)
    remaining_t2 = reactive(0)
    remaining_lease = reactive(0)

    def on_mount(self):
        self.set_interval(1, self.tick)

    def tick(self):
        if self.remaining_t1 > 0: self.remaining_t1 -= 1
        if self.remaining_t2 > 0: self.remaining_t2 -= 1
        if self.remaining_lease > 0: self.remaining_lease -= 1

    def render(self) -> str:
        t1 = f"{self.remaining_t1}s" if self.remaining_t1 > 0 else "--"
        t2 = f"{self.remaining_t2}s" if self.remaining_t2 > 0 else "--"
        ttl = f"{self.remaining_lease}s" if self.remaining_lease > 0 else "--"
        return f"[b]T1 (Renew):[/b] {t1}\n[b]T2 (Rebind):[/b] {t2}\n[b]Expire:[/b] {ttl}"

# --- PANTALLA DE CONFIGURACIÓN ---

class PacketConfigScreen(Screen):
    CSS = """
    PacketConfigScreen { align: center middle; background: rgba(0,0,0,0.8); }
    #config-dialog { width: 95; height: 90%; border: heavy green; background: $surface; padding: 1 2; overflow-y: scroll; }
    .cfg-label { color: yellow; margin-top: 1; text-style: bold; }
    .cfg-input { border: solid white; height: 3; }
    .cfg-sub { color: #00ff00; text-style: bold underline; margin-top: 2; margin-bottom: 1; }
    #cfg-buttons { margin-top: 2; height: 3; align: center middle; layout: horizontal; }
    #cfg-buttons Button { margin-right: 1; width: auto; min-width: 10; height: 3; border: tall $background; }
    """

    def __init__(self, client_core):
        super().__init__()
        self.client = client_core

    def compose(self) -> ComposeResult:
        with Vertical(id="config-dialog"):
            yield Label("🛠️ CONSTRUCTOR DE PAQUETES (MODO DIOS)", classes="info-title")
            
            yield Label("CAPA 2 - ETHERNET", classes="cfg-sub")
            yield Label("Ethernet Source (MAC Spoofing)", classes="cfg-label")
            yield Input(id="in_eth_src", value=str(self.client.config["ether_src"]))
            yield Label("Ethernet Destination (ff:ff:ff:ff:ff:ff para Broadcast)", classes="cfg-label")
            yield Input(id="in_eth_dst", value=str(self.client.config["ether_dst"]))

            yield Label("CAPA 3 - IP", classes="cfg-sub")
            yield Label("IP Source (0.0.0.0 para DHCP Inicial)", classes="cfg-label")
            yield Input(id="in_ip_src", value=str(self.client.config["ip_src"]))
            yield Label("IP Destination (255.255.255.255 para Broadcast)", classes="cfg-label")
            yield Input(id="in_ip_dst", value=str(self.client.config["ip_dst"]))

            yield Label("CAPA BOOTP", classes="cfg-sub")
            yield Label("Transaction ID (XID) - 0 = Aleatorio", classes="cfg-label")
            val_xid = hex(self.client.config["bootp_xid"]) if self.client.config["bootp_xid"] != 0 else "0"
            yield Input(id="in_xid", value=val_xid)

            yield Label("DHCP: IDENTIDAD Y SPOOFING", classes="cfg-sub")
            yield Label("Hostname (Option 12)", classes="cfg-label")
            yield Input(id="in_hostname", value=str(self.client.config["hostname"]))
            yield Label("Client FQDN (Option 81)", classes="cfg-label")
            yield Input(id="in_fqdn", value=str(self.client.config["client_fqdn"]))
            yield Label("Vendor Class ID (Option 60)", classes="cfg-label")
            yield Input(id="in_vendor", value=str(self.client.config["vendor_class_id"]))
            yield Label("Client Identifier (Option 61)", classes="cfg-label")
            yield Input(id="in_clientid", value=str(self.client.config["client_id"]))

            yield Label("DHCP: PARÁMETROS TÉCNICOS", classes="cfg-sub")
            yield Label("Max Message Size (Option 57)", classes="cfg-label")
            yield Input(id="in_maxsize", value=str(self.client.config["max_msg_size"]))
            yield Label("Requested Lease Time (Option 51)", classes="cfg-label")
            yield Input(id="in_lease", value=str(self.client.config["req_lease_time"]))
            yield Label("Parameter Request List (Option 55 - CSV)", classes="cfg-label")
            val_prl = ",".join(map(str, self.client.config["param_req_list"]))
            yield Input(id="in_prl", value=val_prl)

            with Horizontal(id="cfg-buttons"):
                yield Button("Guardar Todo", id="btn_save", variant="primary")
                yield Button("💣 IANA Full", id="btn_iana_full", variant="warning")
                yield Button("Restablecer", id="btn_reset")
                yield Button("Cancelar", id="btn_cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id
        if btn_id == "btn_cancel": self.app.pop_screen()
        elif btn_id == "btn_reset":
            self.client.reset_config()
            self.app.pop_screen()
            self.app.notify("Valores restablecidos.")
        elif btn_id == "btn_iana_full":
            self.query_one("#in_prl").value = "1,3,6,15,26,28,33,42,43,51,53,54,58,59,60,61,66,67,119,121,252"
            self.app.notify("Lista IANA común inyectada.")
        elif btn_id == "btn_save":
            try:
                self.client.config["ether_src"] = self.query_one("#in_eth_src").value
                self.client.config["ether_dst"] = self.query_one("#in_eth_dst").value
                self.client.config["ip_src"] = self.query_one("#in_ip_src").value
                self.client.config["ip_dst"] = self.query_one("#in_ip_dst").value
                
                xid_str = self.query_one("#in_xid").value
                self.client.config["bootp_xid"] = int(xid_str, 16) if "x" in xid_str else int(xid_str)
                
                self.client.config["hostname"] = self.query_one("#in_hostname").value
                self.client.config["client_fqdn"] = self.query_one("#in_fqdn").value
                self.client.config["vendor_class_id"] = self.query_one("#in_vendor").value
                self.client.config["client_id"] = self.query_one("#in_clientid").value
                
                msg_str = self.query_one("#in_maxsize").value
                self.client.config["max_msg_size"] = int(msg_str) if msg_str.isdigit() else 1500
                lease_str = self.query_one("#in_lease").value
                self.client.config["req_lease_time"] = int(lease_str) if lease_str.isdigit() else 0
                
                prl_str = self.query_one("#in_prl").value
                self.client.config["param_req_list"] = [int(x.strip()) for x in prl_str.split(",") if x.strip().isdigit()]

                self.app.pop_screen()
                self.app.notify("Configuración Guardada.")
            except Exception as e: self.app.notify(f"Error: {e}", severity="error")

# --- APP PRINCIPAL ---

class DHCPApp(App):
    CSS = """
    #main-layout { layout: horizontal; height: 1fr; }
    #left-col { width: 35; height: 100%; border-right: solid green; background: $surface-darken-1; padding: 1; }
    .info-box { height: auto; border: solid green; padding: 0 1; margin-bottom: 1; background: $surface; }
    .info-title { color: green; text-style: bold; width: 100%; text-align: center; }
    .info-text { color: #e0e0e0; margin-top: 1; }
    .dashed-rule { color: green; margin: 1 0; }
    #state_label { width: 100%; text-align: center; padding: 1; text-style: bold; }
    
    .btn-section-title { color: yellow; text-style: bold; margin-top: 1; margin-bottom: 1; border-bottom: solid yellow; width: 100%; }
    #left-col Button { width: 100%; height: 1; border: none; margin-bottom: 0; padding: 0; }
    #left-col Button:focus { background: $primary; color: black; text-style: bold; }
    
    .conflict-active { background: red; color: white; text-style: bold; }
    #spacer { height: 1fr; }

    #right-col { width: 1fr; height: 100%; }
    #log-title { background: blue; color: white; text-style: bold; width: 100%; padding: 0 1; }
    #log-view { height: 1fr; overflow-y: scroll; padding: 1; scrollbar-size-vertical: 1; }
    
    Rule { color: green; }
    .log-header { color: black; background: green; text-style: bold; padding: 0 1; width: 100%; }
    """

    def __init__(self, interface, mac_addr):
        super().__init__()
        self.interface = interface
        self.client = DHCPClientCore(
            interface=interface, 
            mac_address=mac_addr,
            on_packet_received=self.handle_packet_from_thread,
            on_log=self.handle_log_from_thread
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Container(id="left-col"):
                yield StateDisplay(id="state_display")
                with Vertical(classes="info-box"):
                    yield TimerDisplay(id="timer_display")

                yield Label("CICLO DE VIDA", classes="btn-section-title")
                yield Button("▶ Iniciar DORA", id="btn_discover", variant="primary")
                yield Button("⏹ Liberar", id="btn_release", variant="error")
                yield Button("↻ Renovar", id="btn_renew", disabled=True)

                yield Label("PRUEBAS AVANZADAS", classes="btn-section-title")
                yield Button("🛠️ Configurar / Spoofing", id="btn_config")
                yield Button("🎭 Nueva MAC", id="btn_new_mac", variant="warning")
                yield Button("⚡ Init-Reboot (Bad IP)", id="btn_reboot_nak", variant="warning")
                yield Button("⚠️ Simular Conflicto", id="btn_conflict")
                
                yield Static(id="spacer") 
                yield Button("Salir", id="btn_quit")
            
            with Container(id="right-col"):
                yield Label(" LOG DE EVENTOS Y PAQUETES", id="log-title")
                yield VerticalScroll(id="log-view")
        yield Footer()

    def on_mount(self):
        self.client.start_listening()
        self.update_ui_state()
        self.add_log_separator("APLICACIÓN INICIADA")
        self.add_log(f"Interfaz: {self.interface}\nMAC Inicial: {self.client.mac}", "info")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        
        if btn_id == "btn_config":
            self.push_screen(PacketConfigScreen(self.client))

        elif btn_id == "btn_discover":
            if self.client.state != DHCPState.INIT:
                self.add_log("⚠️ Error: Libera la IP antes de pedir otra.", "warning")
            else:
                self.add_log_separator("INICIANDO PROCESO DORA")
                self.client.send_discover()

        elif btn_id == "btn_release":
            self.add_log_separator("LIBERANDO CONCESIÓN")
            self.client.send_release()
            self._reset_timers()

        elif btn_id == "btn_renew":
            self.add_log_separator("SOLICITANDO RENOVACIÓN (UNICAST)")
            self.client.send_renew()

        elif btn_id == "btn_new_mac":
            old_mac = self.client.mac
            new_mac = self.client.change_mac()
            self._reset_timers()
            self.add_log_separator("CAMBIO DE IDENTIDAD")
            self.add_log(f"MAC Anterior: {old_mac}", "dim")
            self.add_log(f"MAC Nueva:    {new_mac}", "bold magenta")

        elif btn_id == "btn_reboot_nak":
            self.add_log_separator("SIMULANDO REINICIO CON IP INCORRECTA")
            self.client.send_init_reboot(bad_ip="10.20.30.40")

        elif btn_id == "btn_conflict":
            self.client.force_conflict = not self.client.force_conflict
            if self.client.force_conflict:
                event.button.classes = "conflict-active"
                self.add_log_separator("MODO SABOTAJE ACTIVADO")
                self.add_log("El próximo ACK provocará un DECLINE.", "bold red")
            else:
                event.button.classes = ""
                self.add_log("Modo sabotaje desactivado.", "info")

        elif btn_id == "btn_quit":
            self.client.stop()
            self.exit()
            
        self.update_ui_state()

    def update_ui_state(self):
        display = self.query_one(StateDisplay)
        display.state_name = str(self.client.state.name)
        display.current_ip = self.client.current_ip or "---"
        display.server_ip = self.client.server_ip or "---"
        display.mac_addr = self.client.mac
        
        try:
            btn_renew = self.query_one("#btn_renew", Button)
            btn_renew.disabled = (self.client.state != DHCPState.BOUND)
        except: pass

    def _reset_timers(self):
        try:
            timer = self.query_one(TimerDisplay)
            timer.remaining_t1 = 0
            timer.remaining_t2 = 0
            timer.remaining_lease = 0
        except: pass

    def handle_log_from_thread(self, msg, level):
        if threading.current_thread() is threading.main_thread(): self.add_log(msg, level)
        else: self.call_from_thread(self.add_log, msg, level)

    def handle_packet_from_thread(self, pkt):
        if threading.current_thread() is threading.main_thread(): self.process_packet(pkt)
        else: self.call_from_thread(self.process_packet, pkt)

    def add_log_separator(self, title):
        try:
            log_view = self.query_one("#log-view")
            log_view.mount(Rule(line_style="heavy"))
            log_view.mount(Label(f" {title} ", classes="log-header"))
            log_view.scroll_end()
        except: pass

    def add_log(self, text, style="white"):
        if style == "info": style = "dim white"
        if style == "warning": style = "bold yellow"
        if style == "red": style = "bold red"
        if style == "green": style = "bold green"
        try:
            log_view = self.query_one("#log-view")
            log_view.mount(Label(Text(text, style=style)))
            log_view.scroll_end()
        except: pass

    def process_packet(self, pkt):
        try:
            explainer_table = DHCPExplainer.explain(pkt)
            self.query_one("#log-view").mount(Static(explainer_table))
            self.query_one("#log-view").scroll_end()
        except: pass

        if DHCP not in pkt: return
        
        options = pkt[DHCP].options
        msg_type = next((o[1] for o in options if isinstance(o, tuple) and o[0] == "message-type"), 0)

        if self.client.state == DHCPState.SELECTING and msg_type == DHCP_OFFER:
            offered_ip = pkt[BOOTP].yiaddr
            server_id = next((o[1] for o in options if isinstance(o, tuple) and o[0] == "server_id"), None)
            if not server_id and IP in pkt: server_id = pkt[IP].src
            
            self.client.server_ip = server_id
            self.client.server_mac = pkt[Ether].src

            self.add_log(f"✅ OFFER aceptado: {offered_ip}. Pidiendo IP...", "green")
            self.client.send_request(offered_ip, server_id)
            self.update_ui_state()

        elif (self.client.state in [DHCPState.REQUESTING, DHCPState.RENEWING]) and msg_type == DHCP_ACK:
            potential_ip = pkt[BOOTP].yiaddr
            server_id = next((o[1] for o in options if isinstance(o, tuple) and o[0] == "server_id"), self.client.server_ip)
            
            self.add_log(f"📥 ACK Recibido para {potential_ip}.", "bold yellow")
            self.add_log("🕵️  Iniciando ARP Probe (Detección de Conflictos)...", "yellow")
            
            # --- ACADEMIC CRITICAL STEP: ARP PROBE ---
            is_conflict = self.client.send_arp_probe_blocking(potential_ip)

            if is_conflict:
                self.add_log(f"🛑 CONFLICTO DETECTADO: {potential_ip} en uso.", "bold red")
                self.add_log("   -> Enviando DHCP DECLINE.", "red")
                self.client.send_decline(server_id, potential_ip)
                self.client.state = DHCPState.INIT
                
                # Desactivar botón sabotaje (One-shot)
                if self.client.force_conflict:
                    self.client.force_conflict = False
                    try: self.query_one("#btn_conflict").classes = ""
                    except: pass
                    self.add_log("   (Simulación finalizada)", "dim")

            else:
                self.add_log("✅ ARP Probe limpio. La IP es segura.", "bold green")
                self.add_log("📢 Enviando Gratuitous ARP (Announcement).", "green")
                self.client.send_gratuitous_arp()
                
                self.client.state = DHCPState.BOUND
                self.client.current_ip = potential_ip
                
                lease_time = 3600
                for opt in options:
                    if isinstance(opt, tuple) and opt[0] == "lease_time":
                        try: lease_time = int(opt[1])
                        except: pass
                
                self.client.lease_total = lease_time
                self.client.t1 = int(lease_time * 0.5)
                self.client.t2 = int(lease_time * 0.875)
                self.client.lease_obtained_time = time.time()
                
                try:
                    timer_widget = self.query_one(TimerDisplay)
                    timer_widget.remaining_t1 = self.client.t1
                    timer_widget.remaining_t2 = self.client.t2
                    timer_widget.remaining_lease = self.client.lease_total
                except: pass

            self.update_ui_state()

        elif msg_type == DHCP_NAK:
            self.add_log("❌ ERROR: Servidor envió NAK. IP Rechazada.", "bold red")
            self.client.reset_data()
            self._reset_timers()
            self.update_ui_state()

    def on_unmount(self):
        self.client.stop()
