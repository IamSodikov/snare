import socket
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox
from PySide6.QtCore import Qt

def get_local_ip():
    try:
        # Create a dummy socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class MobileSetupDialog(QDialog):
    def __init__(self, port, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Mobil sozlamalar va SSL sertifikati")
        self.resize(520, 320)
        
        layout = QVBoxLayout(self)
        
        ip = get_local_ip()
        
        info = QLabel(
            f"<b>Kompyuteringizning Wi-Fi IP manzili:</b> {ip}<br>"
            f"<b>Proksi porti:</b> {port}<br><br>"
            "<b>Mobil telefonni ulash bo'yicha ko'rsatma:</b><br>"
            "1. Telefoningizni kompyuter ulangan Wi-Fi tarmog'iga ulang.<br>"
            f"2. Telefoningiz Wi-Fi sozlamalarida proksi manziliga <b>{ip}</b> va portiga <b>{port}</b> kiriting.<br>"
            "3. Telefonda istalgan brauzerni ochib <b>http://mitm.it</b> manziliga kiring.<br>"
            "4. Qurilmangiz turiga mos (iOS yoki Android) sertifikatni yuklab oling va o'rnating.<br>"
            "<i>(Eslatma: iOS qurilmalarida sertifikat o'rnatilgach, Sozlamalar > Asosiy > Qurilma haqida > Sertifikatlarga ishonch sozlamalari orqali faollashtirilishi kerak)</i>."
        )
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Tushunarli")
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
