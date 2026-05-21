from pathlib import Path
from threading import Event, Thread
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ipaddress
from scapy.all import conf, get_if_list

try:
	from scapy.arch.windows import get_windows_if_list
except Exception:
	get_windows_if_list = None

from replay import load_pcap, start_replay_thread


class gui:
	def __init__(self, root: tk.Tk) -> None:
		self.root = root
		# try to set window icon from sender.png (case-insensitive)
		try:
			icon_path = Path(__file__).parent / "sender.png"
			if not icon_path.exists():
				icon_path = Path(__file__).parent / "Sender.png"
			if icon_path.exists():
				_img = tk.PhotoImage(file=str(icon_path))
				self.root.iconphoto(True, _img)
				# keep reference to avoid garbage collection
				self._icon_image = _img
		except Exception:
			# ignore icon loading issues
			self._icon_image = None
		self.root.title("TcpReplaPy")
		self.root.geometry("640x300")

		self.pcap_path: Path | None = None
		self.packets = None
		self.stop_event = Event()
		self.worker: Thread | None = None

		self.interfaces = get_if_list()
		self.iface_display_to_value: dict[str, str] = {}

		self._build_ui()
		self._refresh_interfaces()
		self._set_status("Pronto")

		self.root.protocol("WM_DELETE_WINDOW", self.on_close)

	def _build_ui(self) -> None:
		frame = ttk.Frame(self.root, padding=12)
		frame.pack(fill="both", expand=True)

		ttk.Label(frame, text="Arquivo pcap/pcapng").grid(row=0, column=0, sticky="w")
		self.file_var = tk.StringVar()
		ttk.Entry(frame, textvariable=self.file_var, width=60, state="readonly").grid(
			row=1, column=0, sticky="ew", padx=(0, 8)
		)
		self.select_btn = ttk.Button(frame, text="Selecionar", command=self.select_file)
		self.select_btn.grid(row=1, column=1)

		ttk.Label(frame, text="Interface de rede").grid(row=2, column=0, sticky="w", pady=(12, 0))
		self.iface_combo = ttk.Combobox(frame, state="readonly", width=58)
		self.iface_combo.grid(row=3, column=0, sticky="ew", padx=(0, 8))
		ttk.Button(frame, text="Atualizar", command=self._refresh_interfaces).grid(row=3, column=1)

		buttons = ttk.Frame(frame)
		buttons.grid(row=4, column=0, columnspan=2, pady=(18, 8), sticky="w")
		self.start_btn = ttk.Button(buttons, text="Iniciar", command=self.start_replay)
		self.start_btn.pack(side="left", padx=(0, 8))
		self.stop_btn = ttk.Button(buttons, text="Parar", command=self.stop_replay, state="disabled")
		self.stop_btn.pack(side="left")

		self.status_var = tk.StringVar()
		ttk.Label(frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=2, sticky="w")

		frame.columnconfigure(0, weight=1)

	def _set_status(self, text: str) -> None:
		self.status_var.set(f"Status: {text}")

	def _add_valid_ipv4(self, source: list[str], candidate) -> None:
		if not isinstance(candidate, str):
			return

		ip_text = candidate.strip()
		if "." not in ip_text:
			return

		try:
			ip_obj = ipaddress.ip_address(ip_text)
		except Exception:
			return

		if ip_obj.version == 4 and ip_text not in source:
			source.append(ip_text)

	def _refresh_interfaces(self) -> None:
		atual = self.iface_combo.get().strip()
		self.interfaces = get_if_list()
		self.iface_display_to_value = {}

		windows_info = []
		if sys.platform.startswith("win") and get_windows_if_list is not None:
			try:
				windows_info = get_windows_if_list()
			except Exception:
				windows_info = []

		displays = []
		used = set()
		for iface in self.interfaces:
			display = iface
			ipv4s = []
			iface_obj = None

			for item in windows_info:
				guid = (item.get("guid") or "").upper()
				name = item.get("name") or ""
				network_name = item.get("network_name") or ""

				if (
					(guid and guid in iface.upper())
					or network_name == iface
					or name == iface
				):
					display = name or network_name or iface
					for ip in item.get("ips", []):
						self._add_valid_ipv4(ipv4s, ip)
					break

			try:
				iface_obj = conf.ifaces[iface]
			except Exception:
				iface_obj = None

			if iface_obj is not None:
				for candidate in [getattr(iface_obj, "ip", None), *list(getattr(iface_obj, "ips", []) or [])]:
					self._add_valid_ipv4(ipv4s, candidate)

			if not ipv4s:
				continue

			for ip in ipv4s:
				option = f"{display} - {ip}"
				base = option
				contador = 2
				while option in used:
					option = f"{base} ({contador})"
					contador += 1

				used.add(option)
				displays.append(option)
				self.iface_display_to_value[option] = iface

		self.iface_combo["values"] = displays
		if displays:
			if atual in displays:
				self.iface_combo.set(atual)
			else:
				self.iface_combo.current(0)
			self._set_status(f"{len(displays)} opcoes com IPv4 encontradas")
		else:
			self.iface_combo.set("")
			self._set_status("Nenhuma interface com IPv4 encontrada")

	def select_file(self) -> None:
		path = filedialog.askopenfilename(
			title="Selecione um arquivo de captura",
			filetypes=[("Capturas", "*.pcap *.pcapng"), ("Todos os arquivos", "*.*")],
		)
		if not path:
			return

		p = Path(path)
		if p.suffix.lower() not in {".pcap", ".pcapng"}:
			messagebox.showerror("Erro", "Selecione um arquivo .pcap ou .pcapng")
			return

		self.pcap_path = p
		self.file_var.set(str(p))
		self._set_status("Arquivo selecionado")

	def start_replay(self) -> None:
		if self.worker is not None and self.worker.is_alive():
			self._set_status("Replay ja em execucao")
			return

		if self.pcap_path is None:
			messagebox.showwarning("Atencao", "Selecione um arquivo antes de iniciar")
			return

		iface_display = self.iface_combo.get().strip()
		if not iface_display:
			messagebox.showwarning("Atencao", "Selecione uma interface")
			return

		iface = self.iface_display_to_value.get(iface_display, iface_display)

		try:
			self.packets = load_pcap(self.pcap_path)
		except Exception as exc:
			messagebox.showerror("Erro ao ler arquivo", str(exc))
			return

		if len(self.packets) == 0:
			messagebox.showwarning("Atencao", "Arquivo sem pacotes")
			return

		self.stop_event.clear()
		self.worker = start_replay_thread(
			self.packets,
			iface,
			self.stop_event,
			lambda exc: self.root.after(0, lambda: messagebox.showerror("Erro durante replay", str(exc))),
			lambda: self.root.after(0, self._on_replay_finished),
		)

		self.start_btn.configure(state="disabled")
		self.stop_btn.configure(state="normal")
		self.select_btn.configure(state="disabled")
		self._set_status(f"Enviando pacotes em loop na interface: {iface_display}")

	def _on_replay_finished(self) -> None:
		self.start_btn.configure(state="normal")
		self.stop_btn.configure(state="disabled")
		self.select_btn.configure(state="normal")
		if self.stop_event.is_set():
			self._set_status("Replay parado")
		else:
			self._set_status("Replay finalizado")

	def stop_replay(self) -> None:
		self.stop_event.set()
		self._set_status("Parando replay...")

	def on_close(self) -> None:
		self.stop_event.set()
		self.root.destroy()


