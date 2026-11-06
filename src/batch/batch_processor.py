import typing
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.batch.batch_item import BatchItem
from src.batch.rate_limiter import RateLimiter  
from src.managers.ai_manager import AIManager
from src.managers.logic_manager import LogicManager 
from src.models.submission import Submission
from src.models.evidence import ThreadEvidence

class BatchProcessor:
    def __init__(self, ai_manager: AIManager, logic_manager: LogicManager, rate_limiter: RateLimiter, max_workers: int = 5) -> None:
        self._ai_manager = ai_manager
        self._logic_manager = logic_manager
        self._rate_limiter = rate_limiter
        self._max_workers = max_workers
        self._cancel_event = threading.Event()

    def process_batch(self, items: typing.List[BatchItem]) -> typing.List[BatchItem]:
        results = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = [executor.submit(self._worker_task, item) for item in items]

            for future in futures:
                results.append(future.result())
        return results
