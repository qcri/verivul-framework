from enum import Enum
import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Integer, JSON, func, Table, or_
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Status(Enum):
    COMPILATION_SUCCESS = "COMPILATION_SUCCESS"
    COMPILATION_FAILED = "COMPILATION_FAILED"
    VERIFICATION_SUCCESS = "VERIFICATION_SUCCESS"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"
    VERIFICATION_TIMEOUT = "VERIFICATION_TIMEOUT"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    FIXING_SUCCESS = "FIXING_SUCCESS"
    GENERATION_FAILED = "GENERATION_FAILED"
    GENERATION_SUCCESS = "GENERATION_SUCCESS"
    GROUND_TRUTH = "GROUND_TRUTH"
    PENDING_COMPILATION = "PENDING_COMPILATION"

class Label(Enum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"

class Reproduced(Enum):
    """Whether a sanitizer crash backs a VULNERABLE label (see src/utils/dynamic_confirm.py)."""
    REPRODUCED = "REPRODUCED"          # a sanitizer fired on a concrete input (stored in poc_input)
    NOT_REPRODUCED = "NOT_REPRODUCED"  # every search stage ran and nothing fired
    PENDING = "PENDING"                # the sanitizer search or the LLM proof-of-concept is still running

class Type(Enum):
    SEED = "SEED"
    GENERATED = "GENERATED" 
    FIXED = "FIXED"

code_snippet_cwe_association = Table('code_snippet_cwe', Base.metadata,
    Column('code_snippet_uuid', String(36), ForeignKey('code_snippets.uuid'), primary_key=True),
    Column('cwe_id', String, ForeignKey('cwes.id'), primary_key=True)
)

class CWE(Base):
    __tablename__ = 'cwes'
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    code_snippets = relationship(
        "CodeSnippet",
        secondary=code_snippet_cwe_association,
        back_populates="cwes"
    )
    def __repr__(self):
        return f"<CWE(id={self.id}, name={self.name})>"

class CodeSnippet(Base):
    __tablename__ = 'code_snippets'
    
    uuid = Column(String(36), primary_key=True)
    seed_uuid = Column(String(36), nullable=False, index=True)
    generation_model = Column(String(50), nullable=False)
    code = Column(Text, nullable=False)
    code_hash = Column(String(64), nullable=True, index=True)  # SHA-256 hex of code; used to deduplicate seeds
    slice_code = Column(Text, nullable=True)
    label = Column(String(20), nullable=True)
    type = Column(String(20), nullable=True)
    status = Column(String(50), nullable=False)
    esbmc_log = Column(Text, nullable=True)
    witness = Column(Text, nullable=True)       # GraphML witness produced by ESBMC
    verification_meta = Column(JSON, nullable=True)  # command, version, image digest, parsed properties
    esbmc_cwes = Column(JSON, nullable=True)    # CWE ids ESBMC reported for a VULNERABLE verdict (cwes = our mapping)
    verified_code_hash = Column(String(64), nullable=True)  # hash of the text the verdict belongs to
    pair_attempts = Column(Integer, default=0, nullable=False, server_default='0')
    reproduced = Column(String(20), nullable=True, index=True)  # Reproduced; NULL for labels other than VULNERABLE
    sanitizer_log = Column(Text, nullable=True)     # ASan/UBSan/LSan report of the reproducing run
    poc_input = Column(Text, nullable=True)         # base64 of the reproducing input
    sanitizer_cwes = Column(JSON, nullable=True)    # CWE ids implied by the sanitizer report
    reproduce_attempts = Column(Integer, default=0, nullable=False, server_default='0')
    compilation_log = Column(Text, nullable=True)
    parent_uuid = Column(String(36), ForeignKey('code_snippets.uuid'), nullable=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    commit_message = Column(Text, nullable=True)
    commit_hash = Column(String(64), nullable=True)
    install_command = Column(Text, nullable=True)
    project = Column(String, nullable=True)
    repo_url = Column(Text, nullable=True)
    dataset = Column(String, nullable=True)
    cve = Column(String, nullable=True)
    language = Column(String, nullable=True)
    info = Column(Text, nullable=True)
    metrics = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    children = relationship("CodeSnippet", backref="parent", remote_side=[uuid])
    
    cwes = relationship(
        "CWE",
        secondary=code_snippet_cwe_association,
        back_populates="code_snippets"
    )

    def __repr__(self):
        return f"<CodeSnippet(uuid={self.uuid}, model={self.generation_model}, status={self.status})>"

class Stats(Base):
    __tablename__ = 'stats'
    id = Column(Integer, primary_key=True)
    total_snippets = Column(Integer, default=0)
    status_counts = Column(JSON, default={})
    label_counts = Column(JSON, default={})
    model_counts = Column(JSON, default={})
    vulnerable_count = Column(Integer, default=0)
    safe_count = Column(Integer, default=0)
    cwe_distribution = Column(JSON, default={})


SANITIZED_LANGUAGES = ('c', 'cpp')


def ready_for_counterpart(model=None):
    """SQL condition: a verified original may get its fix / injection task.  A C/C++
    VULNERABLE label must first be backed by a sanitizer crash (reproduced = REPRODUCED);
    other languages have no sanitizer stage."""
    m = model or CodeSnippet
    return or_(m.label != Label.VULNERABLE.value, m.reproduced == Reproduced.REPRODUCED.value,
               ~m.language.in_(SANITIZED_LANGUAGES))
