"""Data loader for PatchEval dataset."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json
import logging
from pathlib import Path


logger = logging.getLogger(__name__)

DEFAULT_DATASET_PATH = Path(
    "/Users/tomiowolabi/projects/vuln-agent/PatchEval/patcheval/datasets/input.json"
)


@dataclass
class Sample:
    """A single vulnerability sample from PatchEval."""
    sample_id: str
    cve_id: str
    cwe_id: List[str]  # List of CWE IDs
    file_path: str
    vulnerable_code: str
    programming_language: str = "Python"
    line_hint: Optional[int] = None
    repo_url: Optional[str] = None
    docker_image: Optional[str] = None
    test_paths: List[str] = field(default_factory=list)
    poc_test: Optional[str] = None
    commit_hash: Optional[str] = None
    patch_description: Optional[str] = None
    work_dir: Optional[str] = None
    problem_statement: Optional[str] = None
    vulnerability_locations: List[Dict[str, Any]] = field(default_factory=list)
    cwe_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for orchestrator."""
        return {
            'sample_id': self.sample_id,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'file_path': self.file_path,
            'vulnerable_code': self.vulnerable_code,
            'programming_language': self.programming_language,
            'line_hint': self.line_hint,
            'repo_url': self.repo_url,
            'docker_image': self.docker_image,
            'test_paths': self.test_paths,
            'poc_test': self.poc_test,
            'commit_hash': self.commit_hash,
            'patch_description': self.patch_description,
            'work_dir': self.work_dir,
            'problem_statement': self.problem_statement,
            'vulnerability_locations': self.vulnerability_locations,
            'cwe_info': self.cwe_info,
        }


class PatchEvalDataset:
    """Loader for PatchEval benchmark dataset."""
    
    def __init__(self, dataset_path: Optional[str] = None):
        """
        Initialize dataset loader.
        
        Args:
            dataset_path: Path to PatchEval dataset file (defaults to input.json)
        """
        if dataset_path:
            self.dataset_path = Path(dataset_path)
        else:
            self.dataset_path = DEFAULT_DATASET_PATH
        self.samples: List[Sample] = []
        self._load()
    
    def _load(self):
        """Load samples from dataset file."""
        if not self.dataset_path.exists():
            if self.dataset_path != DEFAULT_DATASET_PATH and DEFAULT_DATASET_PATH.exists():
                logger.warning(
                    "Dataset not found at %s; falling back to %s",
                    self.dataset_path,
                    DEFAULT_DATASET_PATH
                )
                self.dataset_path = DEFAULT_DATASET_PATH
            else:
                raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
        
        # Detect format based on file extension
        if self.dataset_path.suffix == '.jsonl':
            # JSONL format (one JSON object per line)
            raw_samples = []
            with open(self.dataset_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        raw_samples.append(json.loads(line))
        else:
            # Standard JSON format
            with open(self.dataset_path, 'r') as f:
                data = json.load(f)
            
            # Handle both formats
            if isinstance(data, list):
                raw_samples = data
            elif isinstance(data, dict):
                raw_samples = list(data.values())
            else:
                raise ValueError(f"Unexpected dataset format: {type(data)}")
        
        for raw in raw_samples:
            try:
                sample = self._parse_sample(raw)
                self.samples.append(sample)
            except Exception as e:
                logger.warning(f"Failed to parse sample: {e}")
        
        logger.info(f"Loaded {len(self.samples)} samples from {self.dataset_path}")
    
    def _parse_sample(self, raw: Dict[str, Any]) -> Sample:
        """Parse a raw sample into Sample dataclass."""
        # Handle different field names in PatchEval
        cve_id = raw.get('cve_id') or raw.get('CVE') or raw.get('id', '')
        
        # Check if this is the SWE-agent JSONL format (has problem_statement)
        problem_statement = raw.get('problem_statement', '')
        work_dir = raw.get('work_dir', '')
        image_name = raw.get('image_name', '')
        is_poc = raw.get('is_poc')
        
        # Parse vulnerability locations and CWE info from problem_statement
        vulnerability_locations = []
        cwe_info = {}
        cwe_ids = []  # List of CWE IDs
        patch_description = ''
        vul_func_list = raw.get('vul_func', [])
        vul_func_locations = []
        if isinstance(vul_func_list, list):
            for item in vul_func_list:
                if not isinstance(item, dict):
                    continue
                vul_func_locations.append({
                    'file_path': item.get('file_path', ''),
                    'start_line': item.get('start_line'),
                    'end_line': item.get('end_line'),
                })
        
        if problem_statement:
            # Parse structured info from problem_statement
            parsed = self._parse_problem_statement(problem_statement)
            vulnerability_locations = parsed.get('vulnerability_locations', [])
            cwe_info = parsed.get('cwe_info', {})
            cwe_ids = list(cwe_info.keys()) if cwe_info else []
            patch_description = parsed.get('description', '')
            
            # Get file path and line hint from vulnerability locations
            if vulnerability_locations:
                file_path = vulnerability_locations[0].get('file_path', '')
                line_hint = vulnerability_locations[0].get('start_line')
            elif vul_func_locations:
                vulnerability_locations = vul_func_locations
                file_path = vul_func_locations[0].get('file_path', '')
                line_hint = vul_func_locations[0].get('start_line')
            else:
                file_path = ''
                line_hint = None
            
            vulnerable_code = ''
            if isinstance(vul_func_list, list) and vul_func_list:
                vul_info = vul_func_list[0]
                if isinstance(vul_info, dict):
                    vulnerable_code = vul_info.get('snippet', '') or vulnerable_code
        else:
            # Original PatchEval format
            cwe_id_raw = raw.get('cwe_id') or raw.get('CWE') or ''
            if isinstance(cwe_id_raw, list):
                cwe_ids = cwe_id_raw
            else:
                cwe_ids = [cwe_id_raw] if cwe_id_raw else []
            
            # Get vulnerable function info from vul_func array
            if vul_func_list and isinstance(vul_func_list, list) and len(vul_func_list) > 0:
                vul_info = vul_func_list[0]
                file_path = vul_info.get('file_path', '')
                vulnerable_code = vul_info.get('snippet', '')
                line_hint = vul_info.get('start_line')
                vulnerability_locations = vul_func_locations
            else:
                vulnerable_code = (
                    raw.get('vulnerable_code') or 
                    raw.get('code') or
                    raw.get('buggy_code') or
                    raw.get('input', {}).get('code', '')
                )
                file_path = (
                    raw.get('file_path') or
                    raw.get('target_file') or
                    raw.get('input', {}).get('file_path', '')
                )
                line_hint = raw.get('line_hint') or raw.get('buggy_line')
            
            patch_description = raw.get('cve_description') or raw.get('description', '')
        
        if isinstance(line_hint, str) and line_hint.isdigit():
            line_hint = int(line_hint)
        
        # Programming language - infer from file extension if not specified
        programming_language = raw.get('programming_language', '')
        if not programming_language and file_path:
            programming_language = self._infer_language_from_path(file_path)
        if not programming_language:
            programming_language = 'unknown'
        
        # Docker image
        docker_image = image_name or raw.get('docker_image')
        if is_poc is True and not docker_image and cve_id:
            docker_image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
        elif is_poc is False:
            docker_image = None
        
        return Sample(
            sample_id=cve_id,
            cve_id=cve_id,
            cwe_id=cwe_ids if cwe_ids else self._infer_cwe(cve_id),
            file_path=file_path,
            vulnerable_code=vulnerable_code,
            programming_language=programming_language,
            line_hint=line_hint,
            repo_url=raw.get('repo_url') or raw.get('repo'),
            docker_image=docker_image,
            test_paths=raw.get('test_paths', []),
            poc_test=raw.get('poc_test') or raw.get('poc_path'),
            commit_hash=raw.get('commit_hash') or raw.get('commit'),
            patch_description=patch_description,
            work_dir=work_dir,
            problem_statement=problem_statement,
            vulnerability_locations=vulnerability_locations,
            cwe_info=cwe_info,
        )
    
    def _parse_problem_statement(self, problem_statement: str) -> Dict[str, Any]:
        """
        Parse the problem_statement field from SWE-agent format.
        
        Extracts vulnerability description, CWE info, and vulnerability locations.
        """
        import re
        
        result = {
            'description': '',
            'cwe_info': {},
            'vulnerability_locations': [],
        }
        
        # Extract description (text after "## Vulnerability Description" until next section)
        desc_match = re.search(
            r'## Vulnerability Description\s*\n(.*?)(?=\n## |\n\[|\Z)',
            problem_statement,
            re.DOTALL
        )
        if desc_match:
            result['description'] = desc_match.group(1).strip()
        
        # Extract CWE Info (JSON block after "## CWE Information")
        cwe_match = re.search(
            r'## CWE Information\s*\n(\{.*?\})\s*(?=\n## |\Z)',
            problem_statement,
            re.DOTALL
        )
        if cwe_match:
            try:
                result['cwe_info'] = json.loads(cwe_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Extract Vulnerability Location (JSON array after "## Vulnerability Location")
        loc_match = re.search(
            r'## Vulnerability Location\s*\n(\[.*?\])\s*(?=\n## |\Z)',
            problem_statement,
            re.DOTALL
        )
        if loc_match:
            try:
                result['vulnerability_locations'] = json.loads(loc_match.group(1))
            except json.JSONDecodeError:
                pass
        
        return result
    
    def _infer_language_from_path(self, file_path: str) -> str:
        """Infer programming language from file extension."""
        ext_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.h': 'C',
            '.hpp': 'C++',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.rs': 'Rust',
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, '')
    
    def _infer_cwe(self, cve_id: str) -> List[str]:
        """Attempt to infer CWE from CVE ID (fallback)."""
        # Could integrate with NVD API or local mapping
        # For now, return empty list
        return []
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Sample:
        return self.samples[idx]
    
    def __iter__(self):
        return iter(self.samples)
    
    def get_by_id(self, sample_id: str) -> Optional[Sample]:
        """Get a sample by its ID."""
        for sample in self.samples:
            if sample.sample_id == sample_id:
                return sample
        return None
    
    def filter_by_cwe(self, cwe_id: str) -> List[Sample]:
        """Filter samples by CWE ID."""
        return [s for s in self.samples if s.cwe_id == cwe_id]
    
    def filter_by_language(self, language: str) -> List[Sample]:
        """Filter samples by programming language."""
        return [s for s in self.samples if s.programming_language.lower() == language.lower()]
    
    def get_sample_ids(self) -> List[str]:
        """Get list of all sample IDs."""
        return [s.sample_id for s in self.samples]


def load_dataset(path: Optional[str] = None) -> PatchEvalDataset:
    """Convenience function to load dataset."""
    return PatchEvalDataset(path)
