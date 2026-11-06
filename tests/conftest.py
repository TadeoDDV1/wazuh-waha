"""Configuración común de pytest.

Añade `relay/` al path para que los tests puedan importar `wazuh_waha`
aunque el paquete no esté instalado (p. ej. ejecutando desde la raíz con
`PYTHONPATH=.`). Mantiene compatibilidad con el import `wazuh_waha`.
"""

import sys
from pathlib import Path

RELAY_DIR = Path(__file__).resolve().parents[1] / "relay"
if str(RELAY_DIR) not in sys.path:
    sys.path.insert(0, str(RELAY_DIR))
