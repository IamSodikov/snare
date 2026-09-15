import sys
from pathlib import Path

# When running frozen, mitmdump must be able to import desktop_sniffer
package_root = str(Path(__file__).resolve().parents[3])
if package_root not in sys.path:
    sys.path.insert(0, package_root)

from desktop_sniffer.infrastructure.mitmproxy.addon import DesktopAddon

addons = [DesktopAddon()]