import tkinter as tk
import pyshark
import platform
import subprocess
import threading
from tkinter import messagebox
from tkinter import filedialog

class PacketSnifferApp:
    def _init_(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Interface selection
        self.interface_selection = tk.StringVar()
        self.interface_label = tk.Label(root, text="Select Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=5)
        self.interface_dropdown = tk.OptionMenu(root, self.interface_selection, ())
        self.interface_dropdown.grid(row=0, column=1, padx=10, pady=5)

        # Start button
        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=1, column=0, padx=10, pady=5)

        # Stop button
        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=1, padx=10, pady=5)

        # Save button
        self.save_button = tk.Button(root, text="Save", command=self.save_capture, state=tk.DISABLED)
        self.save_button.grid(row=1, column=2, padx=10, pady=5)

        # Clear button
        self.clear_button = tk.Button(root, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

        # Output text area
        self.output_text = tk.Text(root, height=15, width=80)
        self.output_text.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

        # Populate interfaces
        self.populate_interfaces()

        # Flag to control packet capture
        self.capture_flag = threading.Event()

    def populate_interfaces(self):
        interfaces = self.list_available_interfaces()
        if interfaces:
            self.interface_selection.set(interfaces[0])
            menu = self.interface_dropdown["menu"]
            menu.delete(0, "end")
            for interface in interfaces:
                menu.add_command(label=interface, command=tk._setit(self.interface_selection, interface))

    def list_available_interfaces(self):
        interfaces = []
        system = platform.system()
        if system == "Darwin" or system == "Linux":
            try:
                ifconfig_result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                interfaces = [line.split(":")[0] for line in ifconfig_result.stdout.split("\n") if line.strip() and not line.startswith(" ")]
            except Exception as e:
                self.show_error_message(f"Error listing interfaces: {e}")
        elif system == "Windows":
            try:
                ipconfig_result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                interfaces = [line.split(":")[1].strip() for line in ipconfig_result.stdout.split("\n") if "adapter" in line]
            except Exception as e:
                self.show_error_message(f"Error listing interfaces: {e}")
        else:
            self.show_error_message("Unsupported platform.")
        return interfaces

    def analyze_packet(self, packet):
        packet_str = str(packet)
        if packet_str.startswith("IP") or packet_str.startswith("TCP") or packet_str.startswith("UDP"):
            self.output_text.insert(tk.END, packet_str + "\n")
            self.output_text.see(tk.END)

    def start_capture(self):
        if self.capture_flag.is_set():
            self.show_error_message("Capture already in progress.")
            return
        interface = self.interface_selection.get()
        if not interface:
            self.show_error_message("Please select an interface.")
            return
        self.capture_flag.set()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
        capture_thread.start()

    def capture_packets(self, interface):
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=-1):
            if not self.capture_flag.is_set():
                break
            self.analyze_packet(packet)

    def stop_capture(self):
        self.capture_flag.clear()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

    def save_capture(self):
        capture_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if capture_file:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Capture saved to {capture_file}\n")
            with open(capture_file, "w") as f:
                for packet in self.captured_packets:
                    f.write(str(packet) + "\n")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def show_error_message(self, message):
        messagebox.showerror("Error", message)

def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if _name_ == "_main_":
    main()