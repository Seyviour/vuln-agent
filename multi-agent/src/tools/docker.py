"""
Docker execution utilities.

Provides a safe interface for executing commands in Docker containers.
"""

import subprocess
import tempfile
import os
import logging
from typing import Optional, Tuple

from ..utils.exceptions import (
    DockerError,
    DockerNotAvailableError,
    ContainerNotFoundError,
    ContainerExecutionError,
)


logger = logging.getLogger(__name__)


class DockerExecutor:
    """
    Execute commands in a Docker container.
    
    Provides a safe interface for:
    - Running shell commands
    - Reading/writing files
    - Handling timeouts and errors
    
    Attributes:
        container_id: The Docker container name or ID
        work_dir: Default working directory in container
    """
    
    def __init__(
        self,
        container_id: str,
        work_dir: str = "/workspace"
    ):
        """
        Initialize Docker executor.
        
        Args:
            container_id: The container name or ID to execute in
            work_dir: Default working directory for commands
        """
        self.container_id = container_id
        self.work_dir = work_dir
        self._verified = False
    
    def verify_container(self) -> bool:
        """
        Verify the container exists and is running.
        
        Returns:
            True if container is available
        
        Raises:
            ContainerNotFoundError: If container doesn't exist
        """
        try:
            result = subprocess.run(
                ["docker", "inspect", self.container_id],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise ContainerNotFoundError(self.container_id)
            self._verified = True
            return True
        except subprocess.TimeoutExpired:
            raise DockerNotAvailableError()
        except FileNotFoundError:
            raise DockerNotAvailableError()
    
    def exec_command(
        self,
        cmd: str,
        timeout: int = 60,
        work_dir: Optional[str] = None
    ) -> Tuple[int, str]:
        """
        Execute a command in the container.
        
        Args:
            cmd: Shell command to execute
            timeout: Maximum execution time in seconds
            work_dir: Working directory override
        
        Returns:
            Tuple of (exit_code, combined_output)
        """
        effective_work_dir = work_dir or self.work_dir
        
        try:
            result = subprocess.run(
                [
                    "docker", "exec",
                    "-w", effective_work_dir,
                    self.container_id,
                    "bash", "-c", cmd
                ],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout + result.stderr
            return result.returncode, output
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out after {timeout}s: {cmd[:100]}...")
            return -1, f"Command timed out after {timeout} seconds"
            
        except Exception as e:
            logger.error(f"Docker exec failed: {e}")
            return -1, str(e)
    
    def write_file(
        self,
        container_path: str,
        content: str
    ) -> Tuple[int, str]:
        """
        Write content to a file in the container using docker cp.
        
        This method avoids shell quoting issues by using docker cp
        instead of echo/cat with escaped content.
        
        Args:
            container_path: Path in container (absolute or relative to work_dir)
            content: Content to write
        
        Returns:
            Tuple of (exit_code, message)
        """
        try:
            # Write to a local temp file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.tmp',
                delete=False
            ) as f:
                f.write(content)
                temp_path = f.name
            
            # Construct full path in container
            if not container_path.startswith('/'):
                full_container_path = f"{self.work_dir}/{container_path}"
            else:
                full_container_path = container_path
            
            # Copy to container
            result = subprocess.run(
                [
                    "docker", "cp",
                    temp_path,
                    f"{self.container_id}:{full_container_path}"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Clean up temp file
            os.unlink(temp_path)
            
            if result.returncode != 0:
                return result.returncode, result.stderr
            
            return 0, f"Successfully wrote to {full_container_path}"
            
        except Exception as e:
            logger.error(f"Failed to write file: {e}")
            return -1, str(e)
    
    def read_file(
        self,
        container_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> Tuple[int, str]:
        """
        Read file contents from the container.
        
        Args:
            container_path: Path to file in container
            start_line: Optional starting line (1-indexed)
            end_line: Optional ending line (inclusive)
        
        Returns:
            Tuple of (exit_code, file_content)
        """
        # Build the command
        if start_line is not None and end_line is not None:
            cmd = f"sed -n '{start_line},{end_line}p' '{container_path}'"
        elif start_line is not None:
            cmd = f"sed -n '{start_line},$p' '{container_path}'"
        else:
            cmd = f"cat '{container_path}'"
        
        return self.exec_command(cmd)
    
    def file_exists(self, container_path: str) -> bool:
        """Check if a file exists in the container."""
        exit_code, _ = self.exec_command(f"test -f '{container_path}'")
        return exit_code == 0
    
    def dir_exists(self, container_path: str) -> bool:
        """Check if a directory exists in the container."""
        exit_code, _ = self.exec_command(f"test -d '{container_path}'")
        return exit_code == 0
    
    def __repr__(self) -> str:
        return f"DockerExecutor(container={self.container_id}, work_dir={self.work_dir})"
