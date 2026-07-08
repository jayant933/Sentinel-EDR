"""
file_monitor.py
-----------------
Module 2 - File Monitoring.

Uses the `watchdog` library to watch a set of folders for create /
modify / delete / rename events. Events are pushed onto a thread-safe
queue that the behavior engine drains to detect "rapid file
modification" bursts (many changes in a short window).

Note: raw filesystem events on most OSes do not carry a PID, so this
module attributes bursts to "filesystem activity" as a whole rather
than to a specific process. This is a known simplification of a
basic/educational EDR - a production EDR would use OS-level file
activity APIs (e.g. ETW on Windows, fanotify/auditd on Linux) to get
true process attribution.
"""

import queue
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

event_queue = queue.Queue()


class _Handler(FileSystemEventHandler):
    def _push(self, event_type, path):
        event_queue.put({"type": event_type, "path": path, "time": time.time()})

    def on_created(self, event):
        if not event.is_directory:
            self._push("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._push("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._push("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._push("renamed", f"{event.src_path} -> {event.dest_path}")


def start_watching(paths):
    """
    Start a watchdog Observer on the given list of folder paths.
    Returns the Observer instance so the caller can stop() it later.
    """
    observer = Observer()
    handler = _Handler()
    watched_any = False
    for path in paths:
        try:
            observer.schedule(handler, path, recursive=True)
            watched_any = True
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
    if watched_any:
        observer.start()
    return observer


def drain_events():
    """Pull all currently-queued file events off the queue."""
    events = []
    while True:
        try:
            events.append(event_queue.get_nowait())
        except queue.Empty:
            break
    return events
