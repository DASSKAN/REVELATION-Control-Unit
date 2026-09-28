"""
In-process publish/subscribe used to push live updates to browsers over
Server-Sent Events (dashboard and handheld pages).

Kept deliberately small so it can be swapped for an MQTT broker later
without changing the message model (see protocol doc section 21).
"""
import json
import queue
import threading


class Bus:
    def __init__(self):
        self.lock = threading.Lock()
        self.subs = []   # list of (queue, filter_fn)

    def subscribe(self, filter_fn=None):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.subs.append((q, filter_fn))
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subs = [(s, f) for (s, f) in self.subs if s is not q]

    def publish(self, kind, data):
        msg = {"type": kind, "data": data}
        with self.lock:
            subs = list(self.subs)
        for q, f in subs:
            if f is None or f(msg):
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass   # slow client; it will resync from REST on reconnect

    @staticmethod
    def sse(msg):
        return f"event: {msg['type']}\ndata: {json.dumps(msg['data'], default=str)}\n\n"
