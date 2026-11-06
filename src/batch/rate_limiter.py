import threading
import time

class RateLimiter:
    def __init__(self, max_calls: int, time_window: int) -> None:
        self._lock = threading.Lock()
        self._max_calls = max_calls
        self._time_window = time_window
        self._call_timestamps = []

        def wait_if_needed(self) -> None:
            with self._lock:
                current_time = time.time()
                # Remove timestamps that are outside the time window
                self._call_timestamps = [t for t in self._call_timestamps if current_time - t < self._time_window]

                if len(self._call_timestamps) >= self._max_calls:
                    sleep_time = self._time_window - (current_time - self._call_timestamps[0])
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                        current_time = time.time()
                    self._call_timestamps.append(current_time)
