from scapy.all import *
from wirecatui import *
import os
import threading
save = False


class WireCatWindows(QtWidgets.QMainWindow, Ui_Wirecat):
    start_flag = False
    stop_flag = True

    def __init__(self):
        super(WireCatWindows, self).__init__()
        self.setupUi(self)
        self.pushButton_1.clicked.connect(self.start_sniff)
        self.pushButton_2.clicked.connect(self.stop_sniff)
        self.pushButton_3.clicked.connect(self.pack_)

    def callback(self, packet1):
        proto = 'none'
        if packet1[IP].proto == 17:
            proto = 'udp'
        elif packet1[IP].proto == 6:
            proto = 'tcp'
        row_num = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_num)
        self.tableWidget.setItem(row_num, 1, QtWidgets.QTableWidgetItem(packet1[IP].src))
        self.tableWidget.setItem(row_num, 2, QtWidgets.QTableWidgetItem(packet1[IP].dst))
        self.tableWidget.setItem(row_num, 3, QtWidgets.QTableWidgetItem(proto))
        self.tableWidget.setItem(row_num, 4, QtWidgets.QTableWidgetItem(str(packet1[IP].len)))
        self.tableWidget.setItem(row_num, 5, QtWidgets.QTableWidgetItem(packet1[IP].summary()))

    def get_packet(self, filter0):
        packets = sniff(filter=filter0, prn=self.callback, stop_filter=lambda x: self.stop_flag)
        wrpcap(filter0+'.pcap', packets)

    def start_sniff(self):
        if self.start_flag:
            return
        if self.stop_flag:
            self.stop_flag = False
            self.start_flag = True
            filters = self.lineEdit_5.text()
            s = threading.Thread(target=self.get_packet, args=(filters,))
            s.start()

    def stop_sniff(self):
        self.stop_flag = True

    def pack_(self):
        global save
        save = True


if __name__ == '__main__':
    import sys
    try:
        app = QtWidgets.QApplication(sys.argv)
        ui = WireCatWindows()
        ui.show()
        sys.exit(app.exec_())
    finally:
        if not save:
            for file_name in os.listdir(os.getcwd()):
                if file_name.endswith('.pcap'):
                    os.remove(os.getcwd() + '\\' + file_name)
