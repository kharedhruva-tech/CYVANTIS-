import os
import json
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

class IncrementalFileTailer:
    """
    Robust incremental log reader with persistent byte offset checkpointing.
    Handles log rotation, truncation, Windows file locking, and process restarts.
    """
    def __init__(self, file_path: str, checkpoint_path: str = None):
        self.file_path = os.path.abspath(file_path)
        if checkpoint_path is None:
            self.checkpoint_path = f"{self.file_path}.checkpoint"
        else:
            self.checkpoint_path = os.path.abspath(checkpoint_path)

    def _read_checkpoint(self) -> Tuple[int, int]:
        """Returns (offset, last_seen_size)."""
        if not os.path.exists(self.checkpoint_path):
            return 0, 0
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return int(data.get("offset", 0)), int(data.get("size", 0))
        except Exception as e:
            logger.warning("Could not read checkpoint %s: %s", self.checkpoint_path, e)
            return 0, 0

    def _save_checkpoint(self, offset: int, size: int):
        """Atomically saves checkpoint to disk."""
        try:
            tmp_path = f"{self.checkpoint_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"offset": offset, "size": size}, f)
            if os.path.exists(self.checkpoint_path):
                os.replace(tmp_path, self.checkpoint_path)
            else:
                os.rename(tmp_path, self.checkpoint_path)
        except Exception as e:
            logger.warning("Could not save checkpoint %s: %s", self.checkpoint_path, e)

    def read_new_lines(self) -> List[str]:
        """Reads and yields only newly appended lines since last checkpoint."""
        if not os.path.exists(self.file_path):
            return []

        try:
            current_size = os.path.getsize(self.file_path)
        except OSError:
            # File may be temporarily locked
            return []

        offset, last_size = self._read_checkpoint()

        # Handle log rotation or file truncation: if file shrank, start from beginning
        if current_size < offset:
            logger.info("File %s rotated or truncated (size %d < offset %d). Rewinding to 0.", self.file_path, current_size, offset)
            offset = 0

        # No new bytes written
        if current_size == offset:
            return []

        lines = []
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                new_data = f.read()
                new_offset = f.tell()

                if new_data:
                    lines = new_data.splitlines()

            self._save_checkpoint(new_offset, current_size)
        except Exception as e:
            logger.error("Error reading file %s at offset %d: %s", self.file_path, offset, e)
            return []

        return lines
