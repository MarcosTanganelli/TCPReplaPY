from pathlib import Path
from threading import Event, Thread
from typing import Callable 

from scapy.all import rdpcap, sendp

ReplayErrorCallback = Callable[[Exception], None]
ReplayFinishedCallback = Callable[[], None]


def load_pcap(path: Path):
    """Load packets from a pcap or pcapng file."""
    return rdpcap(str(path))


def _replay_loop(packets, iface: str, stop_event: Event, on_error: ReplayErrorCallback, on_finished: ReplayFinishedCallback) -> None:
    try:
        while not stop_event.is_set():
            for pkt in packets:
                if stop_event.is_set():
                    break
                sendp(pkt, iface=iface, verbose=False)
    except Exception as exc:
        on_error(exc)
    finally:
        on_finished()


def start_replay_thread(packets, iface: str, stop_event: Event, on_error: ReplayErrorCallback, on_finished: ReplayFinishedCallback) -> Thread:
    """Start packet replay in a background thread."""
    worker = Thread(target=_replay_loop, args=(packets, iface, stop_event, on_error, on_finished), daemon=True)
    worker.start()
    return worker
