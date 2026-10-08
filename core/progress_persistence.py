"""
Progress Persistence Module
Enables resume capability and incremental scanning
"""

import json
import os
import logging
from datetime import datetime
from typing import Any, Optional
from pathlib import Path
import hashlib

from core.evidence_signing import read_json
from core.secure_file import atomic_text_writer

logger = logging.getLogger(__name__)

_UNSAFE_CHECKPOINT_CHARS = frozenset('<>:"|?*')


def validate_checkpoint_id(checkpoint_id: str) -> str:
    """Validate the identifier independently of directory creation or network access."""
    if (
        not isinstance(checkpoint_id, str)
        or not checkpoint_id
        or checkpoint_id in {".", ".."}
        or "\x00" in checkpoint_id
        or "/" in checkpoint_id
        or "\\" in checkpoint_id
        or any(char in _UNSAFE_CHECKPOINT_CHARS for char in checkpoint_id)
        or any(char.isspace() for char in checkpoint_id)
    ):
        raise ValueError("Invalid checkpoint_id: path separators and reserved characters are not allowed")
    return checkpoint_id


class ProgressPersistence:
    """
    Manages progress persistence for resume capability and incremental scanning.
    """

    def __init__(self, checkpoint_dir: str = ".atilkurt_checkpoints"):
        """
        Initialize progress persistence.

        Args:
            checkpoint_dir: Directory to store checkpoint files
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        if self.checkpoint_dir.is_symlink():
            raise ValueError('Checkpoint directory must not be a symbolic link')
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.checkpoint_dir, 0o700)
        self.current_checkpoint: Optional[str] = None

    def _checkpoint_path(self, checkpoint_id: str) -> Path:
        """Validate a checkpoint identifier and resolve its in-directory path."""
        validate_checkpoint_id(checkpoint_id)
        base_path = self.checkpoint_dir.resolve()
        target = self.checkpoint_dir / f"{checkpoint_id}.json"
        if target.is_symlink():
            raise ValueError('Checkpoint file must not be a symbolic link')
        checkpoint_path = target.resolve(strict=False)
        try:
            checkpoint_path.relative_to(base_path)
        except ValueError as error:
            raise ValueError("Checkpoint path resolved outside checkpoint directory") from error
        return checkpoint_path

    def create_checkpoint_id(self, domain: str, timestamp: Optional[str] = None) -> str:
        """
        Create unique checkpoint ID.

        Args:
            domain: Domain name
            timestamp: Optional timestamp string

        Returns:
            str: Checkpoint ID
        """
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_domain = "".join(
            char if char.isalnum() or char in "._-" else "_"
            for char in str(domain)
        )
        return f"{safe_domain}_{timestamp}"

    def save_checkpoint(self, checkpoint_id: str, data: dict[str, Any]) -> str:
        """
        Save checkpoint data to file with secure file permissions (0o600).
        Checkpoint files contain sensitive AD data - access is restricted to owner only.

        Args:
            checkpoint_id: Unique checkpoint identifier (must not contain path traversal)
            data: Data to save

        Returns:
            str: Path to checkpoint file
        """
        checkpoint_file = self._checkpoint_path(checkpoint_id)

        checkpoint_data = {
            'checkpoint_id': checkpoint_id,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }

        try:
            with atomic_text_writer(checkpoint_file) as file_handle:
                json.dump(checkpoint_data, file_handle, indent=2, default=str)
            logger.info(f"Checkpoint saved: {checkpoint_file}")
            self.current_checkpoint = str(checkpoint_file)
            return str(checkpoint_file)
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {str(e)}")
            raise

    def load_checkpoint(self, checkpoint_id: str) -> Optional[dict[str, Any]]:
        """
        Load checkpoint data from file.

        Args:
            checkpoint_id: Checkpoint identifier

        Returns:
            Dict with checkpoint data or None if not found
        """
        checkpoint_file = self._checkpoint_path(checkpoint_id)

        if not checkpoint_file.exists():
            logger.warning(f"Checkpoint not found: {checkpoint_file}")
            return None

        try:
            checkpoint_data = read_json(str(checkpoint_file))
            if checkpoint_data.get('checkpoint_id') != checkpoint_id or not isinstance(checkpoint_data.get('data'), dict):
                raise ValueError("Checkpoint metadata or payload is invalid")
            logger.info(f"Checkpoint loaded: {checkpoint_file}")
            return checkpoint_data.get('data')
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {str(e)}")
            return None

    def list_checkpoints(self, domain: Optional[str] = None) -> list[dict[str, Any]]:
        """
        List all available checkpoints.

        Args:
            domain: Optional domain filter

        Returns:
            List of checkpoint metadata
        """
        checkpoints = []

        for checkpoint_file in self.checkpoint_dir.glob("*.json"):
            try:
                if checkpoint_file.is_symlink():
                    logger.warning("Ignoring symlinked checkpoint: %s", checkpoint_file)
                    continue
                checkpoint_data = read_json(str(checkpoint_file))
                checkpoint_id = checkpoint_data.get('checkpoint_id', '')
                if checkpoint_id != checkpoint_file.stem or not isinstance(checkpoint_data.get('data'), dict):
                    continue
                if domain and not checkpoint_id.casefold().startswith(f"{domain}_".casefold()):
                    continue
                checkpoints.append({
                    'checkpoint_id': checkpoint_id,
                    'file': str(checkpoint_file),
                    'timestamp': checkpoint_data.get('timestamp'),
                    'size': checkpoint_file.stat().st_size
                })
            except Exception as e:
                logger.debug(f"Error reading checkpoint {checkpoint_file}: {str(e)}")

        return sorted(checkpoints, key=lambda x: x.get('timestamp') or '', reverse=True)

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """
        Delete checkpoint file.

        Args:
            checkpoint_id: Checkpoint identifier

        Returns:
            bool: True if deleted, False otherwise
        """
        checkpoint_file = self._checkpoint_path(checkpoint_id)

        if checkpoint_file.exists():
            try:
                checkpoint_file.unlink()
                logger.info(f"Checkpoint deleted: {checkpoint_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete checkpoint: {str(e)}")
                return False
        return False

    def save_collection_state(self, checkpoint_id: str, collection_type: str,
                             items: list[dict[str, Any]], completed: bool = False) -> None:
        """
        Save collection state for incremental scanning.

        Args:
            checkpoint_id: Checkpoint identifier
            collection_type: Type of collection (users, computers, groups, etc.)
            items: Collected items
            completed: Whether collection is completed
        """
        checkpoint_data = self.load_checkpoint(checkpoint_id) or {}

        if 'collections' not in checkpoint_data:
            checkpoint_data['collections'] = {}

        checkpoint_data['collections'][collection_type] = {
            'items': items,
            'count': len(items),
            'completed': completed,
            'timestamp': datetime.now().isoformat()
        }

        self.save_checkpoint(checkpoint_id, checkpoint_data)

    def get_collection_state(self, checkpoint_id: str, collection_type: str) -> Optional[list[dict[str, Any]]]:
        """
        Get collection state for incremental scanning.

        Args:
            checkpoint_id: Checkpoint identifier
            collection_type: Type of collection

        Returns:
            List of collected items or None
        """
        checkpoint_data = self.load_checkpoint(checkpoint_id)

        if not checkpoint_data:
            return None

        collections = checkpoint_data.get('collections', {})
        collection_state = collections.get(collection_type)

        if collection_state:
            return collection_state.get('items', [])

        return None

    def is_collection_complete(self, checkpoint_id: str, collection_type: str) -> bool:
        """
        Check if collection is complete.

        Args:
            checkpoint_id: Checkpoint identifier
            collection_type: Type of collection

        Returns:
            bool: True if complete
        """
        checkpoint_data = self.load_checkpoint(checkpoint_id)

        if not checkpoint_data:
            return False

        collections = checkpoint_data.get('collections', {})
        collection_state = collections.get(collection_type)

        return collection_state.get('completed', False) if collection_state else False


class IncrementalScanner:
    """
    Enables incremental scanning by comparing current state with previous scan.
    """

    def __init__(self, persistence: ProgressPersistence):
        """
        Initialize incremental scanner.

        Args:
            persistence: ProgressPersistence instance
        """
        self.persistence = persistence

    def calculate_hash(self, item: dict[str, Any], key_fields: list[str]) -> str:
        """
        Calculate hash for item based on key fields.

        Args:
            item: Item dictionary
            key_fields: List of field names to use for hashing

        Returns:
            str: Hash value
        """
        key_values = [item.get(field) for field in key_fields]
        if not any(value not in (None, "") for value in key_values):
            fallback_identity = item.get("distinguishedName") or item.get("dn") or item
            key_values.append(fallback_identity)
        key_string = json.dumps(key_values, sort_keys=True, default=str, ensure_ascii=False)
        return hashlib.sha256(key_string.encode("utf-8")).hexdigest()

    def find_new_items(self, current_items: list[dict[str, Any]],
                      previous_items: list[dict[str, Any]],
                      key_fields: list[str]) -> list[dict[str, Any]]:
        """
        Find new items compared to previous scan.

        Args:
            current_items: Current scan items
            previous_items: Previous scan items
            key_fields: Fields to use for comparison

        Returns:
            List of new items
        """
        previous_hashes = {
            self.calculate_hash(item, key_fields)
            for item in previous_items
        }

        new_items = []
        for item in current_items:
            item_hash = self.calculate_hash(item, key_fields)
            if item_hash not in previous_hashes:
                new_items.append(item)

        return new_items

    def find_changed_items(self, current_items: list[dict[str, Any]],
                          previous_items: list[dict[str, Any]],
                          key_fields: list[str]) -> list[dict[str, Any]]:
        """
        Find changed items compared to previous scan.

        Args:
            current_items: Current scan items
            previous_items: Previous scan items
            key_fields: Fields to use for comparison

        Returns:
            List of changed items
        """
        previous_dict = {
            self.calculate_hash(item, key_fields): item
            for item in previous_items
        }

        changed_items = []
        for item in current_items:
            item_hash = self.calculate_hash(item, key_fields)
            if item_hash in previous_dict:
                # Item exists, check if changed
                prev_item = previous_dict[item_hash]
                # Match the JSON representation used by checkpoint persistence.
                # LDAP bytes and datetime values otherwise look changed on every run.
                if json.dumps(item, sort_keys=True, default=str) != json.dumps(prev_item, sort_keys=True, default=str):
                    changed_items.append({
                        'previous': prev_item,
                        'current': item,
                        'key': item_hash
                    })

        return changed_items

    def find_deleted_items(self, current_items: list[dict[str, Any]],
                          previous_items: list[dict[str, Any]],
                          key_fields: list[str]) -> list[dict[str, Any]]:
        """
        Find deleted items compared to previous scan.

        Args:
            current_items: Current scan items
            previous_items: Previous scan items
            key_fields: Fields to use for comparison

        Returns:
            List of deleted items
        """
        current_hashes = {
            self.calculate_hash(item, key_fields)
            for item in current_items
        }

        deleted_items = []
        for item in previous_items:
            item_hash = self.calculate_hash(item, key_fields)
            if item_hash not in current_hashes:
                deleted_items.append(item)

        return deleted_items
