from pathlib import Path

from PySide6.QtCore import QByteArray, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtNetwork import QAbstractSocket, QNetworkInterface
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QVBoxLayout,
)

from desktop_sniffer.ui.helpers.widgets import button


def local_addresses():
    addresses = []
    for interface in QNetworkInterface.allInterfaces():
        flags = interface.flags()
        if (
            not flags & QNetworkInterface.InterfaceFlag.IsUp
            or flags & QNetworkInterface.InterfaceFlag.IsLoopBack
        ):
            continue
        for entry in interface.addressEntries():
            if (
                entry.ip().protocol()
                == QAbstractSocket.NetworkLayerProtocol.IPv4Protocol
            ):
                addresses.append((interface.humanReadableName(), entry.ip().toString()))
    return addresses


def get_local_ip():
    addresses = local_addresses()
    return addresses[0][1] if addresses else "127.0.0.1"


class MobileSetupDialog(QDialog):
    def __init__(
        self, port, parent=None, lan=False, ready=False, password="", ca_dir=None
    ):
        super().__init__(parent)
        self.setWindowTitle("Mobile Setup — ulanish va CA")
        self.resize(600, 660)
        layout = QVBoxLayout(self)
        status = QLabel(
            f"Engine: {'Running' if ready else 'Stopped'} · LAN: {'On' if lan else 'Off'}"
        )
        layout.addWidget(status)
        self.adapter = QComboBox()
        addresses = local_addresses()
        for name, ip in addresses:
            self.adapter.addItem(f"{name} — {ip}", ip)
        if not addresses:
            self.adapter.addItem("LAN adapter topilmadi", "")
        layout.addWidget(self.adapter)
        details = QLabel()
        details.setWordWrap(True)
        layout.addWidget(details)
        qr = QSvgWidget()
        qr.setFixedSize(200, 200)
        layout.addWidget(qr, alignment=Qt.AlignmentFlag.AlignHCenter)

        def update():
            ip = self.adapter.currentData()
            text = f"Host: {ip or 'adapter kerak'}\nPort: {port}" + (
                f"\nUsername: snare\nPassword: {password}" if password else ""
            )
            details.setText(text)
            if ip:
                import qrcode
                import qrcode.image.svg

                image = qrcode.make(
                    f"http://{ip}:{port}", image_factory=qrcode.image.svg.SvgPathImage
                )
                qr.load(QByteArray(image.to_string()))

        self.adapter.currentIndexChanged.connect(update)
        update()
        layout.addWidget(
            button(
                "IP / Port nusxa olish",
                lambda: QGuiApplication.clipboard().setText(details.text()),
            )
        )
        instruction = QLabel(
            "1. Kompyuter va telefonni bir LAN/Wi-Fi tarmog‘iga ulang.\n2. Snare’da Telefon/LAN va engine’ni yoqing.\n3. Telefon proksisiga yuqoridagi IP va portni kiriting.\n4. Telefon brauzeridan http://mitm.it orqali CA o‘rnating.\n5. iOS’da CA uchun full trust yoqing. Android debug ilovasida Network Security Configuration user/debug CA’ga ishonishi kerak.\n\nCertificate pinning ishlatilsa CA o‘rnatish yetmasligi mumkin. Firewall, VPN yoki noto‘g‘ri adapter ham ulanishni to‘sadi.\n\nQR faqat host/portni ko‘rsatadi; telefon proksisini avtomatik o‘rnatmaydi."
        )
        instruction.setWordWrap(True)
        layout.addWidget(instruction)
        directory = Path(ca_dir) if ca_dir else None
        if directory:
            layout.addWidget(
                button(
                    "CA papkasini ochish",
                    lambda: QDesktopServices.openUrl(
                        QUrl.fromLocalFile(str(directory))
                    ),
                )
            )
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
