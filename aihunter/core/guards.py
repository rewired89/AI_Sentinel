from typing import List, Dict, Any
from aihunter.modules.phishing.stripe_guard import StripePhishingGuard

class GuardRegistry:
    """
    Este registro es como el portero de discoteca:
    - Llama a cada 'guard' (módulo detector)
    - Junta sus resultados
    - Decide si permitir, marcar como sospechoso o bloquear
    """

    def __init__(self):
        self.guards = []  # type: List[object]
        self._load_defaults()

    def _load_defaults(self):
        # Aquí registramos los detectores que queremos usar por defecto
        self.guards.append(StripePhishingGuard())

    def scan_message(self, subject: str = "", body_text: str = "", body_html: str = "") -> Dict[str, Any]:
        final = {"verdict": "ALLOW", "hits": [], "by": []}

        for g in self.guards:
            res = g.scan_message(subject, body_text, body_html)
            final["hits"].extend(res.get("hits", []))
            final["by"].append({g.__class__.__name__: res})

            if res["verdict"] == "BLOCK":
                final["verdict"] = "BLOCK"
            elif res["verdict"] == "SUSPICIOUS" and final["verdict"] != "BLOCK":
                final["verdict"] = "SUSPICIOUS"

        return final
