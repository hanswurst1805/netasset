"""
Matching von Application-Components gegen die SBOM.

Eine Komponente ist eine Regel auf Paket-Identität; diese Funktion liefert die
SQL-Bedingung, die ein SBOM-Paket gegen die Regel matcht. Wird sowohl von der
Components-API als auch vom BASIS-Diagramm genutzt.
"""

from __future__ import annotations

from sqlalchemy import func

from src.models.all_models import SBOMEntry


def component_condition(match_kind: str, match_value: str):
    v = (match_value or "").lower()
    if match_kind == "prefix":
        return func.lower(SBOMEntry.pkg_name).like(v + "%")
    if match_kind == "purl":
        return func.lower(SBOMEntry.purl).like("%" + v + "%")
    if match_kind == "cpe":
        return func.lower(SBOMEntry.cpe).like("%" + v + "%")
    # default: exakter Paketname
    return func.lower(SBOMEntry.pkg_name) == v
