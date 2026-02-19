"""
Progress Persistence Module
Enables resume capability and incremental scanning
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


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
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.current_checkpoint: Optional[str] = None
    
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
        return f"{domain}_{timestamp}"
    
    def save_checkpoint(self, checkpoint_id: str, data: Dict[str, Any]) -> str:
        """
        Save checkpoint data to file with secure file permissions (0o600).
        Checkpoint files contain sensitive AD data - access is restricted to owner only.
        
        Args:
            checkpoint_id: Unique checkpoint identifier (must not contain path traversal)
            data: Data to save
            
        Returns:
            str: Path to checkpoint file
        """
        # Prevent path traversal in checkpoint_id
        if not checkpoint_id or '..' in checkpoint_id or '/' in checkpoint_id or '\\' in checkpoint_id:
            raise ValueError("Invalid checkpoint_id: must not contain path traversal characters")
        
        checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
        # Ensure checkpoint path stays within checkpoint directory
        try:
            resolved = checkpoint_file.resolve()
            base_resolved = self.checkpoint_dir.resolve()
            if not str(resolved).startswith(str(base_resolved)):
                raise ValueError("Checkpoint path resolved outside checkpoint directory")
        except ValueError:
            raise
        except OSError:
            pass  # File may not exist yet
        
        checkpoint_data = {
            'checkpoint_id': checkpoint_id,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        try:
            with open(checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(checkpoint_data, f, indent=2, default=str)
            # Restrict file to owner read/write only (sensitive AD data)
            os.chmod(checkpoint_file, 0o600)
            logger.info(f"Checkpoint saved: {checkpoint_file}")
            self.current_checkpoint = str(checkpoint_file)
            return str(checkpoint_file)
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {str(e)}")
            raise
    
    def load_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Load checkpoint data from file.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            Dict with checkpoint data or None if not found
        """
        checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
        
        if not checkpoint_file.exists():
            logger.warning(f"Checkpoint not found: {checkpoint_file}")
            return None
        
        try:
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                checkpoint_data = json.load(f)
            logger.info(f"Checkpoint loaded: {checkpoint_file}")
            return checkpoint_data.get('data')
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {str(e)}")
            return None
    
    def list_checkpoints(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
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
                with open(checkpoint_file, 'r', encoding='utf-8') as f:
                    checkpoint_data = json.load(f)
                    checkpoint_id = checkpoint_data.get('checkpoint_id', '')
                    
                    if domain and not checkpoint_id.startswith(domain):
                        continue
                    
                    checkpoints.append({
                        'checkpoint_id': checkpoint_id,
                        'file': str(checkpoint_file),
                        'timestamp': checkpoint_data.get('timestamp'),
                        'size': checkpoint_file.stat().st_size
                    })
            except Exception as e:
                logger.debug(f"Error reading checkpoint {checkpoint_file}: {str(e)}")
        
        return sorted(checkpoints, key=lambda x: x['timestamp'], reverse=True)
    
    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """
        Delete checkpoint file.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            bool: True if deleted, False otherwise
        """
        checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
        
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
                             items: List[Dict[str, Any]], completed: bool = False) -> None:
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
    
    def get_collection_state(self, checkpoint_id: str, collection_type: str) -> Optional[List[Dict[str, Any]]]:
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
    
    def calculate_hash(self, item: Dict[str, Any], key_fields: List[str]) -> str:
        """
        Calculate hash for item based on key fields.
        
        Args:
            item: Item dictionary
            key_fields: List of field names to use for hashing
            
        Returns:
            str: Hash value
        """
        key_values = [str(item.get(field, '')) for field in key_fields]
        key_string = '|'.join(key_values)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def find_new_items(self, current_items: List[Dict[str, Any]], 
                      previous_items: List[Dict[str, Any]], 
                      key_fields: List[str]) -> List[Dict[str, Any]]:
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
    
    def find_changed_items(self, current_items: List[Dict[str, Any]], 
                          previous_items: List[Dict[str, Any]], 
                          key_fields: List[str]) -> List[Dict[str, Any]]:
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
                if item != prev_item:
                    changed_items.append({
                        'previous': prev_item,
                        'current': item,
                        'key': item_hash
                    })
        
        return changed_items
    
    def find_deleted_items(self, current_items: List[Dict[str, Any]], 
                          previous_items: List[Dict[str, Any]], 
                          key_fields: List[str]) -> List[Dict[str, Any]]:
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
