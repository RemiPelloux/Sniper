"""Normalizers for different security tool findings.

This package contains normalizers for various security tools integrated in Sniper CLI.
"""

from src.results.normalizers.nmap_normalizer import NmapFindingNormalizer
from src.results.normalizers.wappalyzer_normalizer import WappalyzerFindingNormalizer
from src.results.normalizers.zap_normalizer import ZAPFindingNormalizer

# Export normalizers
__all__ = [
    "NmapFindingNormalizer",
    "WappalyzerFindingNormalizer",
    "ZAPFindingNormalizer",
]
