# MP4Recover

**Easily recover broken MP4 files using advanced technical means.**

MP4Recover is a powerful web-based tool that leverages multiple recovery strategies (fix_avcC, ffmpeg, MP4Box, remoover, untrunc, reencode, etc.) to restore corrupted video files.

## 🚀 Getting Started

This tool runs entirely on **Docker**, making it easy to set up on any operating system.

### Prerequisites

You need to have **Docker** installed on your machine.

- **Windows / macOS**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).
- **Linux**: Install Docker Engine and Docker Compose.

### Installation & Usage

#### 1. Clone the Repository
Open your terminal (Command Prompt, PowerShell, or Terminal) and run:
```bash
git clone https://github.com/ActiveTK/MP4Recover.git
cd MP4Recover
```

#### 2. Build and Start
Run the build script for your operating system.

**🪟 Windows**
Double-click `build.bat` or run it from PowerShell:
```powershell
.\build.bat
```

**🐧 Linux / 🍎 macOS**
Run the shell script:
```bash
chmod +x build.sh
./build.sh
```

#### 3. Access the Tool
Once the script finishes, open your browser and go to:
👉 **http://localhost:8080**

- **Web Interface**: `http://localhost:8080`
- **Orchestrator API**: `http://localhost:8000`

---

## 🌍 Multi-language Support
The interface supports **English**, **Italian**, and **Japanese**. You can switch languages using the links in the top-right corner of the page.

## 🛠 Troubleshooting

**"Docker is not running"**
- Make sure Docker Desktop is started.
- On Linux, ensure the docker daemon is active (`sudo systemctl start docker`).

**"Ports are already in use"**
- The tool uses ports `8080` and `8000`. If these are taken, edit `docker-compose.yml` and change the ports mapping (e.g., `"8081:80"`).

---

## 📜 License
This project is released under the **MIT License**.
See [LICENSE](LICENSE) for details.

© 2025 MCarraroDev.
