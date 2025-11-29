from enum import Enum, auto

class DHCPState(Enum):
    """
    Representación estricta de la Máquina de Estados del Cliente DHCP (RFC 2131).
    """
    INIT = auto()           # Estado inicial, sin IP, sin conocimiento.
    SELECTING = auto()      # Discover enviado, recolectando Offers.
    REQUESTING = auto()     # Offer seleccionado, Request enviado.
    BOUND = auto()          # ACK recibido. Tenemos IP y timers activos.
    RENEWING = auto()       # T1 expirado. Intentando renovar (Unicast).
    REBINDING = auto()      # T2 expirado. Intentando re-vincular (Broadcast).
    
    # Estados adicionales para manejo de errores/ciclo de vida
    DECLINING = auto()      # IP detectada en uso (ARP Check), enviando Decline.
    RELEASED = auto()       # Usuario liberó la IP manualmente.

    def __str__(self):
        return self.name
