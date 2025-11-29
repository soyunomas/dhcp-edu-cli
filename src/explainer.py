from scapy.all import DHCP, BOOTP, Ether, IP
from rich.table import Table
from rich import box

class DHCPExplainer:
    """
    Clase estática encargada de traducir paquetes Raw de Scapy a 
    componentes visuales educativos.
    
    Contiene la base de datos completa de Opciones DHCP asignadas por la IANA.
    Fuente: https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
    """

    MSG_TYPES = {
        1: "DISCOVER (Busco Servidor)",
        2: "OFFER (Tengo una IP para ti)",
        3: "REQUEST (Quiero esa IP)",
        4: "DECLINE (Esa IP está ocupada)",
        5: "ACK (Confirmado, es tuya)",
        6: "NAK (Denegado, reinicia)",
        7: "RELEASE (Ya no la quiero)",
        8: "INFORM (Solo dame config)"
    }

    # --- BASE DE DATOS IANA MERGEADA CON INFO EDUCATIVA ---
    # Formato: Code: ("Nombre Corto", "Descripción")
    
    KNOWN_OPTIONS = {
        # --- RFC 1497 / RFC 2132 Vendor Extensions ---
        0:   ("Pad", "Padding (Relleno)"),
        1:   ("Subnet Mask", "Máscara de subred. Define el tamaño de la red local."),
        2:   ("Time Offset", "Time Offset in Seconds from UTC"),
        3:   ("Router", "Gateway por defecto. A dónde enviar tráfico de internet."),
        4:   ("Time Server", "Time Server (RFC 868)"),
        5:   ("Name Server", "Servidor de Nombres (IEN 116). Precursor obsoleto del DNS."),
        6:   ("DNS Server", "Servidor de Nombres. Traduce google.com a IP."),
        7:   ("Log Server", "MIT-LCS UDP Log Server"),
        8:   ("Quotes Server", "Cookie/Quotes Server"),
        9:   ("LPR Server", "LPR Printer Server"),
        10:  ("Impress Server", "Impress Server"),
        11:  ("RLP Server", "Resource Location Protocol Server"),
        12:  ("Hostname", "Nombre de host del cliente."),
        13:  ("Boot File Size", "Size of boot file in 512 byte chunks"),
        14:  ("Merit Dump File", "Client to dump and name the file to dump it to"),
        15:  ("Domain Name", "Nombre de dominio de la red (ej: local)."),
        16:  ("Swap Server", "Swap Server address"),
        17:  ("Root Path", "Path name for root disk"),
        18:  ("Extension File", "Path name for more BOOTP info"),
        
        # --- IP Layer Parameters per Host ---
        19:  ("Forward On/Off", "Enable/Disable IP Forwarding"),
        20:  ("SrcRte On/Off", "Enable/Disable Source Routing"),
        21:  ("Policy Filter", "Routing Policy Filters"),
        22:  ("Max DG Assembly", "Max Datagram Reassembly Size"),
        23:  ("Default IP TTL", "Default IP Time to Live"),
        24:  ("MTU Timeout", "Path MTU Aging Timeout"),
        25:  ("MTU Plateau", "Path MTU Plateau Table"),
        
        # --- IP Layer Parameters per Interface ---
        26:  ("MTU Interface", "Interface MTU Size"),
        27:  ("MTU Subnet", "All Subnets are Local"),
        28:  ("Broadcast Addr", "Dirección de difusión de la red."),
        29:  ("Mask Discovery", "Perform Mask Discovery"),
        30:  ("Mask Supplier", "Provide Mask to Others"),
        31:  ("Router Discovery", "Perform Router Discovery"),
        32:  ("Router Request", "Router Solicitation Address"),
        33:  ("Static Route", "Static Routing Table"),
        
        # --- Link Layer Parameters ---
        34:  ("Trailers", "Trailer Encapsulation"),
        35:  ("ARP Timeout", "ARP Cache Timeout"),
        36:  ("Ethernet", "Ethernet Encapsulation"),
        
        # --- TCP Parameters ---
        37:  ("Default TCP TTL", "Default TCP Time to Live"),
        38:  ("Keepalive Time", "TCP Keepalive Interval"),
        39:  ("Keepalive Data", "TCP Keepalive Garbage"),
        
        # --- Application and Service Parameters ---
        40:  ("NIS Domain", "NIS Domain Name"),
        41:  ("NIS Servers", "NIS Server Addresses"),
        42:  ("NTP Servers", "Servidores de tiempo para sincronizar el reloj."),
        43:  ("Vendor Specific", "Vendor Specific Information"),
        44:  ("NETBIOS Name Srv", "NETBIOS Name Servers"),
        45:  ("NETBIOS Dist Srv", "NETBIOS Datagram Distribution"),
        46:  ("NETBIOS Node Type", "NETBIOS Node Type"),
        47:  ("NETBIOS Scope", "NETBIOS Scope"),
        48:  ("X Window Font", "X Window Font Server"),
        49:  ("X Window Manager", "X Window Display Manager"),
        
        # --- DHCP Extensions (RFC 2132) ---
        50:  ("Requested IP", "La IP específica que el cliente está pidiendo."),
        51:  ("Lease Time", "Tiempo de alquiler de la IP en segundos."),
        52:  ("Overload", "Overload 'sname' or 'file'"),
        53:  ("Message Type", "Tipo de mensaje DHCP (El paso del baile DORA)."),
        54:  ("Server ID", "Identificador (IP) del servidor DHCP que responde."),
        55:  ("Param Req List", "Lista de opciones extra que el cliente solicita."),
        56:  ("DHCP Message", "Mensaje de error o texto del servidor."),
        57:  ("Max Msg Size", "DHCP Maximum Message Size"),
        58:  ("Renewal (T1)", "Tiempo para renovar con el MISMO servidor (50%)."),
        59:  ("Rebinding (T2)", "Tiempo para renovar con CUALQUIERA (87.5%)."),
        60:  ("Class Id", "Vendor Class Identifier"),
        61:  ("Client ID", "Identificador único del cliente (suele ser la MAC)."),
        
        # --- NetWare/IP (RFC 2242) ---
        62:  ("NetWare/IP Domain", "NetWare/IP Domain Name"),
        63:  ("NetWare/IP Option", "NetWare/IP sub Options"),
        
        # --- NIS+ (RFC 2132) ---
        64:  ("NIS+ Domain", "NIS+ v3 Client Domain Name"),
        65:  ("NIS+ Servers", "NIS+ v3 Server Addresses"),
        
        # --- Other RFC 2132 ---
        66:  ("TFTP Server Name", "TFTP Server Name"),
        67:  ("Bootfile Name", "Boot File Name"),
        68:  ("Home Agent", "Home Agent Addresses"),
        69:  ("SMTP Server", "Simple Mail Server Addresses"),
        70:  ("POP3 Server", "Post Office Server Addresses"),
        71:  ("NNTP Server", "Network News Server Addresses"),
        72:  ("WWW Server", "WWW Server Addresses"),
        73:  ("Finger Server", "Finger Server Addresses"),
        74:  ("IRC Server", "Chat Server Addresses"),
        75:  ("StreetTalk Srv", "StreetTalk Server Addresses"),
        76:  ("STDA Server", "ST Directory Assist. Addresses"),
        
        # --- Modern Extensions ---
        77:  ("User Class", "User Class Information (RFC 3004)"),
        80:  ("Rapid Commit", "Rapid Commit (RFC 4039)"),
        81:  ("Client FQDN", "Fully Qualified Domain Name (RFC 4702)"),
        82:  ("Relay Agent Info", "Info añadida por el Relay DHCP (Option 82)."),
        85:  ("NDS Servers", "Novell Directory Services"),
        86:  ("NDS Tree Name", "Novell Directory Services"),
        87:  ("NDS Context", "Novell Directory Services"),
        93:  ("Client System", "Client System Architecture (PXE)"),
        94:  ("Client NDI", "Client Network Device Interface (PXE)"),
        97:  ("UUID/GUID", "UUID/GUID-based Client Identifier (PXE)"),
        114: ("Captive Portal", "URL del Portal Cautivo (RFC 8910)."),
        116: ("Auto-Config", "DHCP Auto-Configuration (RFC 2563)"),
        118: ("Subnet Selection", "Subnet Selection Option (RFC 3011)"),
        119: ("Domain Search", "Lista de búsqueda de dominios (RFC 3397)."),
        120: ("SIP Servers", "SIP Servers DHCP Option (RFC 3361)"),
        121: ("Classless Route", "Rutas estáticas sin clase (RFC 3442)."),
        122: ("CableLabs Client", "CableLabs Client Configuration"),
        128: ("TFTP/Etherboot", "TFTP Server IP / Etherboot / DOCSIS"),
        138: ("CAPWAP AC", "CAPWAP Access Controller addresses (RFC 5417)"),
        150: ("TFTP Server", "TFTP server address (VoIP/GRUB)"),
        161: ("MUD URL", "Manufacturer Usage Descriptions (RFC 8520)"),
        255: ("End", "Fin de las opciones.")
    }

    @staticmethod
    def explain(pkt) -> Table:
        """Analiza un paquete y devuelve una tabla explicativa detallada."""
        
        msg_type_code = 0
        title = "Paquete Desconocido"
        color = "white"

        # Detectar tipo de mensaje para el título
        if DHCP in pkt:
            options = pkt[DHCP].options
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == 'message-type':
                    msg_type_code = opt[1]
                    break
        
        if msg_type_code:
            type_str = DHCPExplainer.MSG_TYPES.get(msg_type_code, 'Desconocido')
            title = f"DHCP {type_str}"
            if msg_type_code in [2, 5]: # OFFER, ACK
                color = "green"
            elif msg_type_code in [6, 4]: # NAK, DECLINE
                color = "red"
            else:
                color = "cyan"

        # Configuración visual de la tabla
        table = Table(
            title=title, 
            title_style=f"bold {color}", 
            show_header=True, 
            expand=True,
            box=box.SIMPLE,
            header_style="bold white on blue"
        )
        table.add_column("Capa / Campo", style="bold white", width=25)
        table.add_column("Valor Decodificado", style="yellow")
        table.add_column("Contexto Educativo", style="dim italic")

        # 1. Capa Ethernet
        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            table.add_row("Ethernet Src", src_mac, "MAC Física del remitente.")
            table.add_row("Ethernet Dst", dst_mac, "Broadcast (todos) o Unicast.")

        # 2. Capa IP
        if IP in pkt:
            table.add_row("IP Src", pkt[IP].src, "0.0.0.0 = Cliente sin IP aún.")
            table.add_row("IP Dst", pkt[IP].dst, "255.255.255.255 = Grito a todos.")

        # 3. Capa BOOTP
        if BOOTP in pkt:
            bootp = pkt[BOOTP]
            table.add_row("BOOTP XID", hex(bootp.xid), "ID de Transacción.")
            if bootp.yiaddr != "0.0.0.0":
                table.add_row("BOOTP yiaddr", f"[bold green]{bootp.yiaddr}[/]", "Your IP. La dirección ofrecida.")
            if bootp.siaddr != "0.0.0.0":
                table.add_row("BOOTP siaddr", str(bootp.siaddr), "Next Server IP (TFTP/PXE).")

        # 4. Opciones DHCP
        if DHCP in pkt:
            for opt in pkt[BOOTP][DHCP].options:
                if opt == "end": continue
                
                # Scapy devuelve tuplas (nombre_scapy, valor) o strings puros
                if isinstance(opt, tuple):
                    scapy_name, val = opt
                    
                    # Intentamos mapear el nombre de Scapy a nuestro ID numérico IANA
                    opt_id = DHCPExplainer._scapy_name_to_id(scapy_name)
                    
                    display_val = str(val)
                    explanation = f"Opción estándar IANA {opt_id}"
                    display_name = scapy_name

                    if opt_id in DHCPExplainer.KNOWN_OPTIONS:
                        nice_name, edu_text = DHCPExplainer.KNOWN_OPTIONS[opt_id]
                        display_name = f"Opt {opt_id}: {nice_name}"
                        explanation = edu_text
                        
                        # --- LÓGICA ESPECIAL DE VISUALIZACIÓN ---
                        
                        # Lista de opciones solicitadas (Parameter Request List)
                        if opt_id == 55 and isinstance(val, list): 
                            translated_reqs = []
                            for req_code in val:
                                if isinstance(req_code, int):
                                    # Recursividad: Buscamos el nombre de la opción pedida en nuestra propia DB
                                    r_name = DHCPExplainer.KNOWN_OPTIONS.get(req_code, (f"Opt-{req_code}",))[0]
                                    translated_reqs.append(f"{req_code}({r_name})")
                                else:
                                    translated_reqs.append(str(req_code))
                            display_val = ", ".join(translated_reqs)
                        
                        # Formato amigable para tiempos
                        elif opt_id in [51, 58, 59] and isinstance(val, (int, bytes)): 
                            try: display_val = f"{int(val)} segundos"
                            except: pass

                        # Tipo de mensaje
                        elif opt_id == 53:
                            display_val = f"{val} ({DHCPExplainer.MSG_TYPES.get(val, '?')})"

                    table.add_row(display_name, display_val, explanation)

        return table

    @staticmethod
    def _scapy_name_to_id(scapy_name):
        """
        Mapea los nombres internos (strings) que usa Scapy a los códigos numéricos IANA.
        Scapy no es consistente: a veces usa strings, a veces códigos.
        """
        map_name = {
            'subnet_mask': 1,
            'time_zone': 2,
            'router': 3,
            'time_server': 4,
            'name_server': 5,          # IEN 116
            'domain_name_server': 6,   # DNS Estándar
            'log_server': 7,
            'cookie_server': 8,
            'lpr_server': 9,
            'hostname': 12,
            'boot_file_size': 13,
            'domain': 15,
            'swap_server': 16,
            'root_path': 17,
            'extensions_path': 18,
            'ip_forwarding': 19,
            'non_local_source_routing': 20,
            'policy_filter': 21,
            'max_dgram_reasssembly': 22,
            'default_ttl': 23,
            'pmtu_timeout': 24,
            'path_mtu_plateau_table': 25,
            'interface_mtu': 26,
            'all_subnets_local': 27,
            'broadcast_address': 28,
            'perform_mask_discovery': 29,
            'mask_supplier': 30,
            'perform_router_discovery': 31,
            'router_solicitation_address': 32,
            'static_routes': 33,
            'trailer_encapsulation': 34,
            'arp_cache_timeout': 35,
            'ethernet_encapsulation': 36,
            'tcp_ttl': 37,
            'tcp_keepalive_interval': 38,
            'tcp_keepalive_garbage': 39,
            'nis_domain': 40,
            'nis_server': 41,
            'ntp_server': 42, # Scapy a veces usa ntp_servers
            'ntp_servers': 42,
            'vendor_specific': 43,
            'netbios_name_server': 44,
            'netbios_dist_server': 45,
            'netbios_node_type': 46,
            'netbios_scope': 47,
            'font_server': 48,
            'x_display_manager': 49,
            'requested_addr': 50,
            'lease_time': 51,
            'option_overload': 52,
            'message-type': 53,
            'server_id': 54,
            'param_req_list': 55,
            'error_message': 56,
            'max_dhcp_size': 57,
            'renewal_time': 58,
            'rebinding_time': 59,
            'vendor_class_id': 60,
            'client_id': 61,
            'nwip_domain': 62,
            'nwip_suboptions': 63,
            'nisplus_domain': 64,
            'nisplus_server': 65,
            'tftp_server_name': 66,
            'boot_file_name': 67,
            'mobile_ip_home_agent': 68,
            'smtp_server': 69,
            'pop3_server': 70,
            'nntp_server': 71,
            'www_server': 72,
            'finger_server': 73,
            'irc_server': 74,
            'streettalk_server': 75,
            'stda_server': 76,
            'user_class': 77,
            'relay_agent_information': 82,
            'client_fqdn': 81,
            'captive_portal': 114,
            'domain_search': 119,
            'classless_static_route': 121,
            'end': 255
        }
        return map_name.get(scapy_name, 0)
