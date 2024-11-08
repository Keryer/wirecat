import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import *
import threading
import binascii

class PacketCaptureGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Packet Capture Tool")
        self.master.geometry("700x500")

        self.filter = tk.StringVar()
        self.filter.set("tcp")
        self.filename = "capture.pcap"
        self.packets = []

        # 协议选择
        self.protocol_label = tk.Label(master, text="选择协议过滤:")
        self.protocol_label.pack(pady=10)

        self.protocol_combo = tk.OptionMenu(master, self.filter, "tcp", "udp", "icmp", "ip")
        self.protocol_combo.pack(pady=5)

        # 开始抓包按钮
        self.start_button = tk.Button(master, text="开始抓包", command=self.start_capture)
        self.start_button.pack(pady=10)


        # 开始抓包按钮
        self.stop_button = tk.Button(master, text="停止抓包", command=self.stop_capture)
        self.stop_button.pack(pady=10)


        # 保存抓包按钮
        self.save_button = tk.Button(master, text="保存抓包", command=self.save_capture, state=tk.DISABLED)
        self.save_button.pack(pady=5)


        # 清空抓包按钮
        self.clear_button = tk.Button(master, text="清空抓包", command=self.clear_packets, state=tk.DISABLED)
        self.clear_button.pack(pady=5)

        # 数据包显示区域
        self.packet_display = tk.Listbox(master, width=80, height=10)
        self.packet_display.pack(fill=tk.BOTH, expand=True, pady=20)

        self.packet_display.bind("<ButtonRelease-1>", self.on_packet_click)

        # 错误信息提示
        self.status_label = tk.Label(master, text="状态：等待操作")
        self.status_label.pack(pady=5)

        # 抓包线程控制标志
        self.capturing = False

    def packet_callback(self, pkt):
        """ 抓包回调函数 """
        if self.capturing:
            self.packets.append(pkt)
            packet_number = len(self.packets)
            protocol_name = "HTTP" if pkt.haslayer(Raw) and (b'GET' in bytes(pkt[Raw]) or b'POST' in bytes(pkt[Raw]) or b'HTTP' in bytes(pkt[Raw])) else ""
            summary = f"{packet_number}. " + pkt.summary() + (f" ({protocol_name})" if protocol_name else "")
            self.packet_display.insert(tk.END, summary)

    def start_capture(self):
        """ 开始抓包，启动一个新的线程进行抓包 """
        # 确保之前的抓包停止
        self.stop_capture()

        self.capturing = True
        self.status_label.config(text="状态：抓包中...")
        self.start_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.current_filter = self.filter.get()

        # 启动抓包线程
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        """ 停止抓包 """
        self.capturing = False
        self.status_label.config(text="状态：抓包已停止")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.NORMAL)

    def capture_packets(self):
        """ 在后台进行数据包抓取 """
        filter = self.current_filter
        # 只允许合法的过滤器表达式（tcp、udp、icmp、ip）
        if filter not in ["tcp", "udp", "icmp", "ip"]:
            filter = None
        sniff(prn=self.packet_callback, filter=filter, store=0, stop_filter=lambda x: not self.capturing)

    def clear_packets(self):
        """ 清空已捕获的数据包 """
        self.packets.clear()
        self.packet_display.delete(0, tk.END)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

    def save_capture(self):
        """ 保存抓包到文件 """
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("保存成功", f"抓包文件已保存到 {file_path}")

    def on_packet_click(self, event):
        """ 点击数据包列表项后显示详细内容 """
        selected_index = self.packet_display.curselection()
        if selected_index:
            selected_pkt = self.packets[selected_index[0]]
            self.show_packet_details(selected_pkt)

    def show_packet_details(self, pkt):
        """ 弹出新窗口展示包的详细内容 """
        details_window = tk.Toplevel(self.master)
        details_window.title("Packet Details")
        details_window.geometry("800x600")

        # 创建框来分细详细内容
        hex_ascii_frame = tk.Frame(details_window)
        hex_ascii_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

        protocol_frame = tk.Frame(details_window)
        protocol_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 协议详细内容框
        protocol_text = tk.Text(protocol_frame, height=15, width=80)
        protocol_text.pack(pady=5)

        # 创建左右布局框架
        hex_frame = tk.Frame(hex_ascii_frame)
        hex_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ascii_frame = tk.Frame(hex_ascii_frame)
        ascii_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        # 华世码和ASCII格式框
        hex_text = tk.Text(hex_frame, height=15, width=40)
        hex_text.pack(pady=5)

        ascii_text = tk.Text(ascii_frame, height=15, width=40)
        ascii_text.pack(pady=5)

        # 获取数据包的华世码内容和ASCII内容
        raw_data = bytes(pkt)
        hex_data = binascii.hexlify(raw_data).decode('utf-8')
        ascii_data = ''.join([chr(byte) if 32 <= byte <= 126 else '.' for byte in raw_data])

        # 填充华世码和ASCII框
        hex_text.insert(tk.END, f"Hex Format:\n{hex_data}\n\n")
        ascii_text.insert(tk.END, f"ASCII Format:\n{ascii_data}\n\n")

        # 协议层详细内容
        protocol_text.insert(tk.END, "Protocol Fields:\n")
        if pkt.haslayer(IP):
            self.show_ip_fields(pkt, protocol_text)
        if pkt.haslayer(TCP):
            self.show_tcp_fields(pkt, protocol_text)
        if pkt.haslayer(UDP):
            self.show_udp_fields(pkt, protocol_text)
        if pkt.haslayer(ICMP):
            self.show_icmp_fields(pkt, protocol_text)
        if pkt.haslayer(Raw):
            self.show_application_layer_fields(pkt, protocol_text)

        # 设置文本框为只读
        hex_text.config(state=tk.DISABLED)
        ascii_text.config(state=tk.DISABLED)
        protocol_text.config(state=tk.DISABLED)

    def show_ip_fields(self, pkt, text_widget):
        """ 显示IP协议字段 """
        ip_layer = pkt.getlayer(IP)
        text_widget.insert(tk.END, f"IP Layer:\n")
        text_widget.insert(tk.END, f"  Source IP: {ip_layer.src}\n")
        text_widget.insert(tk.END, f"  Destination IP: {ip_layer.dst}\n")
        text_widget.insert(tk.END, f"  Protocol: {ip_layer.proto}\n\n")

    def show_tcp_fields(self, pkt, text_widget):
        """ 显示TCP协议字段 """
        tcp_layer = pkt.getlayer(TCP)
        text_widget.insert(tk.END, f"TCP Layer:\n")
        text_widget.insert(tk.END, f"  Source Port: {tcp_layer.sport}\n")
        text_widget.insert(tk.END, f"  Destination Port: {tcp_layer.dport}\n")
        text_widget.insert(tk.END, f"  Sequence Number: {tcp_layer.seq}\n")
        text_widget.insert(tk.END, f"  Acknowledgment Number: {tcp_layer.ack}\n")
        text_widget.insert(tk.END, f"  Flags: {tcp_layer.flags}\n\n")

    def show_udp_fields(self, pkt, text_widget):
        """ 显示UDP协议字段 """
        udp_layer = pkt.getlayer(UDP)
        text_widget.insert(tk.END, f"UDP Layer:\n")
        text_widget.insert(tk.END, f"  Source Port: {udp_layer.sport}\n")
        text_widget.insert(tk.END, f"  Destination Port: {udp_layer.dport}\n")
        text_widget.insert(tk.END, f"  Length: {udp_layer.len}\n\n")

    def show_icmp_fields(self, pkt, text_widget):
        """ 显示ICMP协议字段 """
        icmp_layer = pkt.getlayer(ICMP)
        text_widget.insert(tk.END, f"ICMP Layer:\n")
        text_widget.insert(tk.END, f"  Type: {icmp_layer.type}\n")
        text_widget.insert(tk.END, f"  Code: {icmp_layer.code}\n")
        text_widget.insert(tk.END, f"  ID: {icmp_layer.id}\n")
        text_widget.insert(tk.END, f"  Sequence: {icmp_layer.seq}\n\n")

    def show_application_layer_fields(self, pkt, text_widget):
        """ 显示应用层协议字段 """
        if pkt.haslayer(Raw):
            raw_data = pkt.getlayer(Raw).load
            try:
                # 尝试解码为UTF-8并显示应用层内容
                app_data = raw_data.decode('utf-8', errors='ignore')
                text_widget.insert(tk.END, f"Application Layer:\n{app_data}\n\n")
                # 如果是HTTP协议，提取HTTP头部信息
                if app_data.startswith("GET") or app_data.startswith("POST") or app_data.startswith("HTTP"):
                    headers = app_data.split('\r\n')
                    for header in headers:
                        if header:
                            text_widget.insert(tk.END, f"  {header}\n")
                    text_widget.insert(tk.END, "\n")
            except UnicodeDecodeError:
                text_widget.insert(tk.END, f"Application Layer: Unable to decode\n\n")

if __name__ == "__main__":
    root = tk.Tk()
    gui = PacketCaptureGUI(root)
    root.mainloop()
