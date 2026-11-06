from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime

class CodeSnippetResponse(BaseModel):
    uuid: str
    seed_uuid: str
    generation_model: str
    code: str
    cwes: List[str] = []
    label: Optional[str] = None
    status: str
    type: str
    compilation_log: Optional[str] = None
    install_command: Optional[str] = None
    slice_code: Optional[str] = None
    esbmc_log: Optional[str] = None
    witness: Optional[str] = None
    esbmc_cwes: Optional[List[str]] = None
    verification_meta: Optional[Dict[str, Any]] = None
    reproduced: Optional[str] = None
    sanitizer_log: Optional[str] = None
    poc_input: Optional[str] = None
    sanitizer_cwes: Optional[List[str]] = None
    reproduce_attempts: int = 0
    parent_uuid: Optional[str] = None
    attempt_count: int
    commit_message: Optional[str] = None
    commit_hash: Optional[str] = None
    project: Optional[str] = None
    repo_url: Optional[str] = None
    dataset: Optional[str] = None
    cve: Optional[str] = None
    language: Optional[str] = None
    info: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True

class CodeSnippetConciseResponse(BaseModel):
    uuid: str
    seed_uuid: str
    generation_model: str
    label: Optional[str] = None
    status: str
    type: str
    attempt_count: int
    cwes: List[str] = []
    esbmc_cwes: Optional[List[str]] = None
    reproduced: Optional[str] = None
    language: Optional[str] = None
    project: Optional[str] = None
    dataset: Optional[str] = None
    cve: Optional[str] = None
    commit_hash: Optional[str] = None
    repo_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True

class StatusCountResponse(BaseModel):
    status: str
    count: int

class StatsResponse(BaseModel):
    total_snippets: int
    status_counts: List[StatusCountResponse]
    label_counts: Dict[str, int]
    model_counts: Dict[str, int]
    vulnerable_count: int
    safe_count: int
    cwe_distribution: Dict[str, int]

class ModelsResponse(BaseModel):
    models: List[str]

class PairSnippet(BaseModel):
    uuid: str
    label: Optional[str] = None
    status: str
    generation_model: str
    cwes: List[str] = []
    language: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class PairResponse(BaseModel):
    pair_type: str          # "fix" or "injection"
    seed_uuid: str
    original: PairSnippet   # VULNERABLE (fix pair) or SAFE (injection pair)
    derived: PairSnippet    # SAFE fixed child  or VULNERABLE injected child

class MetricStats(BaseModel):
    min: Optional[float] = None
    max: Optional[float] = None
    mean: Optional[float] = None

class ExtendedStatsResponse(BaseModel):
    total_safe: int
    total_vulnerable: int
    loc: MetricStats
    cc: MetricStats
    nd: MetricStats
    cwe_distribution_vulnerable: Dict[str, int]
    language_distribution: Dict[str, int]
    compile_success: int
    compile_fail: int
    compilation_rate: Optional[float]  # 0.0–1.0, None when no attempts yet
