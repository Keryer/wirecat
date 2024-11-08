# WireCat

这是一个使用 Python 和 `scapy` 构建的简单抓包工具，允许用户捕获、过滤和检查网络数据包。该工具提供了一个使用 `Tkinter` 构建的图形用户界面（GUI），使得捕获和分析网络流量变得简单且用户友好。

**GitHub仓库地址：** https://github.com/Keryer/wirecat

## 功能
- **协议过滤**：用户可以根据协议类型（如 TCP、UDP、ICMP 或 IP）过滤数据包。
- **数据包捕获**：实时捕获数据包，并将其摘要显示在列表中。
- **协议识别**：如果数据包包含 HTTP 数据，则在列表中标记为 "HTTP"。
- **数据包检查**：点击列表中的任意数据包，可以查看详细信息，包括数据包的十六进制和 ASCII 格式，以及协议特定的字段。
- **保存捕获的数据包**：将捕获的数据包保存为 `.pcap` 文件，以便使用 Wireshark 等工具进行进一步分析。
- **可调整大小的 GUI**：数据包列表显示区域会随着窗口动态调整大小，提供更好的用户体验。

## 依赖要求
- Python 3.x
- `scapy` 库
- `tkinter`（通常包含在 Python 中）

### 安装
要安装所需的 Python 包，请运行：

```sh
pip install scapy
```

`tkinter` 通常包含在大多数 Python 发行版中，但如果未安装，可以通过包管理器进行安装：

对于 Ubuntu/Debian：
```sh
sudo apt-get install python3-tk
```

对于 Fedora：
```sh
sudo dnf install python3-tkinter
```

## 使用方法
使用 Python 运行脚本：

```sh
python packet_capture_gui.py
```

### GUI 概述
- **协议过滤**：使用下拉菜单选择要过滤的协议类型（例如 TCP、UDP、ICMP、IP）。
- **开始抓包**：点击“开始抓包”按钮开始捕获数据包，捕获的数据包会显示在列表框中。
- **停止抓包**：点击“停止抓包”按钮结束数据包捕获。
- **保存抓包**：点击“保存抓包”按钮，将捕获的数据包保存为 `.pcap` 文件。
- **数据包详情**：点击列表中的某个数据包，会打开一个新窗口显示详细信息，包括：
  - **十六进制和 ASCII 表示**：并排显示数据包的十六进制和 ASCII 格式。
  - **协议字段**：显示数据包中每个协议层的具体详细信息，包括 IP、TCP、UDP、ICMP 和 HTTP 头部。

### HTTP 数据包识别
- 如果捕获的数据包包含 HTTP 信息（例如 GET 或 POST 请求），则在数据包摘要中标记为 "HTTP"。
- 在检查 HTTP 数据包时，工具会显示 HTTP 头部信息以便于分析。

## 注意事项
- 该工具使用 `scapy` 进行数据包嗅探，可能需要管理员权限。在 Linux 上运行脚本时，可能需要使用 `sudo`，或者确保您在系统上具有必要的权限。
- 需要正确配置网络接口以进行数据包捕获。确保您已连接到适当的网络接口以进行数据包嗅探。

## 鸣谢
- 使用 `scapy` 进行数据包嗅探，使用 `Tkinter` 构建 GUI。
- 特别感谢开源社区提供的有用示例和文档。

## 免责声明
此工具仅供教育用途。未经授权的网络数据包捕获和分析可能会违反隐私和法律法规。请负责任地使用本工具。