# Ingestion package initialization
from .base import NormalizedEvent, BaseLogSource
from .cowrie_parser import CowrieLogParser
from .auth_log_parser import AuthLogParser
from .file_tailer import IncrementalFileTailer
