"""
Simple Performance Timer for ICS Simulations

Provides basic timing functionality for tracking key phases of simulation
and assessment processes.
"""

import time
from datetime import datetime
import json
import os
import logging

class PerformanceTimer:
    """Simple timer for tracking performance metrics across simulation phases."""
    
    def __init__(self):
        """Initialize the performance timer."""
        self.timings = {}
        self.active_timers = {}
        self.start_time = time.time()
        self.start_datetime = datetime.now().isoformat()
        self.logger = self._get_logger()
        
        self.logger.info("="*50)
        self.logger.info("Performance Timer initialized")
        self.logger.info(f"Start time: {self.start_datetime}")
        self.logger.info("="*50)
    
    def _get_logger(self):
        """Get logger instance"""
        return logging.getLogger("PerformanceTimer")
    
    def start(self, name: str) -> None:
        """Start timing a specific phase."""
        self.active_timers[name] = time.time()
        self.logger.info(f"Started timing: {name}")
    
    def stop(self, name: str) -> float:
        """Stop timing a specific phase and record the duration."""
        if name not in self.active_timers:
            return 0
        
        duration = time.time() - self.active_timers[name]
        self.timings[name] = duration
        del self.active_timers[name]
        
        self.logger.info(f"Completed: {name} - Duration: {duration:.2f} seconds")
        return duration
    
    def get_total_time(self) -> float:
        """Get the total elapsed time since timer initialization."""
        total = time.time() - self.start_time
        self.logger.info(f"Total elapsed time: {total:.2f} seconds")
        return total
    
    def save_to_file(self, output_dir: str) -> None:
        """
        Save timing metrics to a JSON file in the specified directory.
        
        Args:
            output_dir: Directory where the timing file will be saved
        """
        # Ensure the directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate total time if not already in timings
        total_time = self.get_total_time()
        
        # Prepare the data structure
        timing_data = {
            "start_time": self.start_datetime,
            "end_time": datetime.now().isoformat(),
            "total_duration": total_time,
            "phase_timings": self.timings
        }
        
        # Create the file path
        file_path = os.path.join(output_dir, "performance_metrics.json")
        
        # Write the data to the file
        try:
            with open(file_path, 'w') as f:
                json.dump(timing_data, f, indent=2)
            self.logger.info(f"Performance metrics saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Error saving performance metrics: {e}")