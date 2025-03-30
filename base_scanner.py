from abc import ABC, abstractmethod
from pathlib import Path
from uuid import UUID
from typing import Dict


class Scanner(ABC):
    def __init__(self, model_path: Path, file_id : UUID):
        """Initialize base scanner with model path and file ID"""
        self.model_path: Path = model_path
        self.file_id: UUID = file_id
        self.scan_results: Dict[str, str] = {}  # Holds scan results (e.g., weakness: severity)
        self.is_anomaly: bool = False
        #self.metadata_scanner: MetaDataScanner = MetaDataScanner()

    @abstractmethod
    def weakness_scan(self):
        """Abstract method for scanning weaknesses in the model - Any format and his vulnerabilities.
        Each vulnerability detected needs to be added to the scan_results dict in the mentioned format above."""
        pass

    def metadata_extractor(self) -> str:
        """Extracts raw metadata from the model file"""
        pass

    # Right now not to implement
    def metadata_scan(self, metadata: str):
        """Scan extracted metadata using the metadata scanner"""
        pass

    def final_scan_report(self, scan_results: Dict[str, str]) -> Dict[str, str]:
        """Generate final formatted scan report"""

        if self.is_anomaly:
            report = {
                "file_id": str(self.file_id),
                "scan_summary": str(scan_results)
            }
            return report
