"""
Progress Tracking Module
Provides progress tracking and ETA estimation for long-running operations
"""

import logging
import time
from typing import Optional, Callable, Any
from threading import Lock

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Tracks progress of long-running operations with ETA estimation."""
    
    def __init__(self, operation_name: str, total_items: Optional[int] = None,
                 update_interval: float = 1.0, show_progress: bool = True):
        """
        Initialize progress tracker.
        
        Args:
            operation_name: Name of the operation being tracked
            total_items: Total number of items (None if unknown)
            update_interval: Minimum seconds between progress updates
            show_progress: Whether to show progress messages
        """
        self.operation_name = operation_name
        self.total_items = total_items
        self.update_interval = update_interval
        self.show_progress = show_progress
        
        self.current_count = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_count = 0
        self.lock = Lock()
        
        if self.show_progress:
            logger.info(f"[*] Starting {operation_name}...")
    
    def update(self, count: int, total: Optional[int] = None) -> None:
        """
        Update progress count.
        
        Args:
            count: Current count
            total: Total count (if known, overrides initial total)
        """
        with self.lock:
            self.current_count = count
            if total is not None:
                self.total_items = total
            
            current_time = time.time()
            elapsed = current_time - self.last_update_time
            
            # Only update display if enough time has passed
            if elapsed >= self.update_interval:
                self._display_progress()
                self.last_update_time = current_time
                self.last_count = count
    
    def increment(self, amount: int = 1) -> None:
        """
        Increment progress count.
        
        Args:
            amount: Amount to increment by
        """
        with self.lock:
            self.current_count += amount
            current_time = time.time()
            elapsed = current_time - self.last_update_time
            
            if elapsed >= self.update_interval:
                self._display_progress()
                self.last_update_time = current_time
                self.last_count = self.current_count
    
    def _display_progress(self) -> None:
        """Display current progress."""
        if not self.show_progress:
            return
        
        elapsed = time.time() - self.start_time
        
        if self.total_items is not None and self.total_items > 0:
            percentage = (self.current_count / self.total_items) * 100
            remaining = self.total_items - self.current_count
            
            # Calculate ETA
            if self.current_count > 0 and elapsed > 0:
                rate = self.current_count / elapsed
                if rate > 0:
                    eta_seconds = remaining / rate
                    eta_str = self._format_time(eta_seconds)
                else:
                    eta_str = "calculating..."
            else:
                eta_str = "calculating..."
            
            logger.info(
                f"[*] {self.operation_name}: {self.current_count}/{self.total_items} "
                f"({percentage:.1f}%) - ETA: {eta_str}"
            )
        else:
            # Unknown total
            if self.current_count > 0 and elapsed > 0:
                rate = self.current_count / elapsed
                rate_str = f"{rate:.1f}/sec"
            else:
                rate_str = "calculating..."
            
            logger.info(
                f"[*] {self.operation_name}: {self.current_count} items "
                f"({rate_str})"
            )
    
    def finish(self) -> None:
        """Mark operation as complete and display final statistics."""
        with self.lock:
            elapsed = time.time() - self.start_time
            
            if self.show_progress:
                if self.total_items is not None:
                    logger.info(
                        f"[+] {self.operation_name} completed: "
                        f"{self.current_count}/{self.total_items} items "
                        f"in {self._format_time(elapsed)}"
                    )
                else:
                    logger.info(
                        f"[+] {self.operation_name} completed: "
                        f"{self.current_count} items "
                        f"in {self._format_time(elapsed)}"
                    )
    
    def _format_time(self, seconds: float) -> str:
        """
        Format time duration in human-readable format.
        
        Args:
            seconds: Time in seconds
        
        Returns:
            Formatted time string
        """
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"


def create_progress_callback(tracker: ProgressTracker) -> Callable[[int, Optional[int]], None]:
    """
    Create a progress callback function for LDAP searches.
    
    Args:
        tracker: ProgressTracker instance
    
    Returns:
        Callback function
    """
    def callback(count: int, total: Optional[int] = None) -> None:
        tracker.update(count, total)
    
    return callback
