"""
Containers Module
Handles Docker container operations for secure extension installation.
"""

import os
import subprocess
import time


class DockerVSCodeContainer:
    """Manages Docker container for VS Code extension installation"""

    def __init__(self, image_name: str = "secure-vscode", container_name: str = "secure-vscode-container", vscode_version: str = None):
        self.image_name = image_name
        self.container_name = container_name
        self.vscode_version = vscode_version or "1.99.3"  # Safe default

    def build_image(self) -> bool:
        """Build Docker image with specific VS Code version"""
        dockerfile_content = f"""
FROM mcr.microsoft.com/devcontainers/base:ubuntu

RUN apt-get update && apt-get install -y curl wget gpg

RUN wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && \\
    install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg && \\
    echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | tee /etc/apt/sources.list.d/vscode.list > /dev/null && \\
    rm -f packages.microsoft.gpg && \\
    apt-get update && \\
    (apt-get install -y code={self.vscode_version}* || apt-get install -y code)

RUN echo '#!/bin/bash' > /install_extension.sh && \\
    echo 'code --no-sandbox --user-data-dir /tmp/vscode-data --extensions-dir /target/extensions --install-extension "$1"' >> /install_extension.sh && \\
    chmod +x /install_extension.sh

WORKDIR /workspace
"""
        try:
            with open("Dockerfile", "w") as f:
                f.write(dockerfile_content)

            subprocess.run(["docker", "build", "-t", self.image_name, "."],
                         check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError:
            return False
        finally:
            if os.path.exists("Dockerfile"):
                os.remove("Dockerfile")

    def start_container(self, volume_mount: str) -> bool:
        """Start temporary container with volume mount"""
        try:
            # Remove any existing container with same name first (cleanup from previous runs)
            self.cleanup()

            # Create fresh temporary container
            subprocess.run([
                "docker", "run", "-d", "--name", self.container_name,
                "-v", f"{volume_mount}:/target/extensions",
                self.image_name, "sleep", "infinity"
            ], check=True, capture_output=True, text=True)
            time.sleep(3)
            return True
        except subprocess.CalledProcessError as e:
            return False

    def install_extension(self, extension_id: str) -> bool:
        """Install single extension"""
        try:
            # Check if container is running
            check_result = subprocess.run([
                "docker", "ps", "--filter", f"name={self.container_name}", "--format", "{{.Names}}"
            ], capture_output=True, text=True)

            if self.container_name not in check_result.stdout:
                return False

            result = subprocess.run([
                "docker", "exec", self.container_name,
                "/install_extension.sh", extension_id
            ], capture_output=True, text=True, timeout=120)

            # Check if extension is already installed (common case)
            if "is already installed" in result.stdout or "is already installed" in result.stderr:
                return True

            if result.returncode != 0:
                return False
            else:
                return True

        except subprocess.TimeoutExpired:
            return False
        except subprocess.CalledProcessError as e:
            return False

    def cleanup(self) -> None:
        """Clean up container resources - ensures temporary container approach"""
        try:
            # Stop container if running
            subprocess.run(["docker", "stop", self.container_name],
                         capture_output=True, text=True, check=False)
            # Remove container
            subprocess.run(["docker", "rm", self.container_name],
                         capture_output=True, text=True, check=False)
        except subprocess.CalledProcessError:
            pass
