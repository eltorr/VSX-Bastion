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
        """Create temporary container ready for use"""
        # Container will be created on-demand for each extension install
        # This just validates the setup
        self.volume_mount = volume_mount
        return True

    def install_extension(self, extension_id: str, force_reinstall: bool = False) -> bool:
        """Install single extension using temporary container"""
        try:
            # Build command for temporary container
            install_cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.volume_mount}:/target/extensions",
                self.image_name,
                "code", "--no-sandbox", "--user-data-dir", "/tmp/vscode-data",
                "--extensions-dir", "/target/extensions", "--install-extension", extension_id
            ]

            if force_reinstall:
                install_cmd.append("--force")
                print(f"🔄 Force reinstalling: {extension_id}")

            # Run in temporary container that auto-removes when done
            result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=120)

            # Check if extension is already installed (only if not force reinstalling)
            if not force_reinstall and ("is already installed" in result.stdout or "is already installed" in result.stderr):
                print(f"✅ Already installed: {extension_id}")
                return True

            # Check for successful installation
            if result.returncode == 0:
                if "successfully installed" in result.stdout.lower():
                    print(f"✅ Successfully installed: {extension_id}")
                    return True
                else:
                    print(f"⚠️  Unclear result for {extension_id}: {result.stdout}")
                    return True

            # Handle failure cases
            print(f"❌ Failed to install {extension_id}")
            print(f"   Return code: {result.returncode}")
            print(f"   stdout: {result.stdout}")
            print(f"   stderr: {result.stderr}")
            return False

        except subprocess.TimeoutExpired:
            print(f"⏰ Timeout installing {extension_id}")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Command failed for {extension_id}: {e}")
            return False

    def cleanup(self) -> None:
        """No cleanup needed - containers auto-remove with --rm flag"""
        pass
