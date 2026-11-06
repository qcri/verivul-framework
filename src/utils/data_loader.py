import json
import hashlib
from typing import List, Dict, Any
from pathlib import Path
from .logger import logger

class DatasetLoader:
    def __init__(self, dataset_path: str):
        self.log = logger.get_logger("dataset_loader")
        self.log.info(f"Initializing DatasetLoader for path: {dataset_path}")
        self.dataset_path = Path(dataset_path)
        
        if not self.dataset_path.exists():
            self.log.error(f"Dataset file not found: {dataset_path}")
            raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
            
        self.log.debug(f"File format: {self.dataset_path.suffix}")

    def load(self) -> List[Dict[str, Any]]:
        self.log.info("Loading dataset")
        try:
            if self.dataset_path.suffix == '.jsonl':
                self.log.debug("Detected JSONL format")
                raw = self._load_jsonl()
            elif self.dataset_path.suffix == '.json':
                self.log.debug("Detected JSON format")
                raw = self._load_json()
            else:
                error_msg = f"Unsupported file format: {self.dataset_path.suffix}"
                self.log.error(error_msg)
                raise ValueError(error_msg)
            for dp in raw:
                dp['cwes'] = self._normalise_cwes(dp.get('cwes'))
            return self._deduplicate(raw)
        except Exception as e:
            self.log.error(f"Failed to load dataset: {str(e)}", exc_info=True)
            raise

    def _deduplicate(self, datapoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove entries whose code content is identical to an earlier entry."""
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for dp in datapoints:
            h = hashlib.sha256(dp.get('code', '').encode('utf-8', errors='replace')).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(dp)
        removed = len(datapoints) - len(unique)
        if removed:
            self.log.warning(f"Removed {removed} duplicate datapoint(s) by code hash.")
        return unique

    def _load_jsonl(self) -> List[Dict[str, Any]]:
        self.log.info("Loading JSONL dataset")
        dataset = []
        invalid_count = 0
        line_count = 0
        
        try:
            with open(self.dataset_path) as f:
                for line_number, line in enumerate(f, 1):
                    line_count += 1
                    try:
                        data = json.loads(line.strip())
                        if self._validate_datapoint(data):
                            dataset.append(data)
                        else:
                            invalid_count += 1
                            self.log.warning(f"Invalid datapoint at line {line_number}: missing required fields")
                            
                    except json.JSONDecodeError as e:
                        invalid_count += 1
                        self.log.error(f"JSON decode error at line {line_number}: {str(e)}")
                        
                    if line_number % 1000 == 0:
                        self.log.debug(f"Processed {line_number} lines...")
                        
            self.log.info(f"JSONL loading completed. Total lines: {line_count}, "
                         f"Valid entries: {len(dataset)}, Invalid entries: {invalid_count}")
            return dataset
            
        except Exception as e:
            self.log.error(f"Error loading JSONL file: {str(e)}", exc_info=True)
            raise

    def _load_json(self) -> List[Dict[str, Any]]:
        self.log.info("Loading JSON dataset")
        try:
            with open(self.dataset_path) as f:
                dataset = json.load(f)
                
            if not isinstance(dataset, list):
                error_msg = "JSON file must contain a list of objects"
                self.log.error(error_msg)
                raise ValueError(error_msg)
                
            valid_data = [d for d in dataset if self._validate_datapoint(d)]
            invalid_count = len(dataset) - len(valid_data)
            
            self.log.info(f"JSON loading completed. Total entries: {len(dataset)}, "
                         f"Valid entries: {len(valid_data)}, Invalid entries: {invalid_count}")
            
            if invalid_count > 0:
                self.log.warning(f"Found {invalid_count} invalid entries in JSON dataset")
                
            return valid_data
            
        except json.JSONDecodeError as e:
            self.log.error(f"Failed to parse JSON file: {str(e)}", exc_info=True)
            raise
        except Exception as e:
            self.log.error(f"Error loading JSON file: {str(e)}", exc_info=True)
            raise

    @staticmethod
    def _normalise_cwes(value) -> List[str]:
        """Accept a list, a comma-separated string or a printed Python list."""
        import re
        if isinstance(value, list):
            items = value
        else:
            items = re.findall(r"CWE-\d+|NVD-CWE-[A-Za-z]+", str(value or ''))
        return sorted({str(c).strip() for c in items if str(c).strip()})

    def _validate_datapoint(self, data: Dict[str, Any]) -> bool:
        required_fields = {'uuid', 'code', 'language', 'slice_code', 'cwes', 'project'}
        is_valid = all(field in data for field in required_fields)
        
        if not is_valid:
            missing_fields = required_fields - set(data.keys())
            self.log.debug(f"Validation failed - missing fields: {missing_fields}")
        
        return is_valid
