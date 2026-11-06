import typing
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.batch.batch_item import BatchItem
from src.batch.rate_limiter import RateLimiter  
from src.managers.ai_manager import AIManager
from src.managers.logic_manager import LogicManager 
from src.models.submission import Submission
from src.models.evidence import ThreatEvidence

class BatchProcessor:
    _print_lock = threading.Lock()
    def __init__(self, ai_manager: AIManager, logic_manager: LogicManager, rate_limiter: RateLimiter, max_workers: int = 5) -> None:
        self._ai_manager = ai_manager
        self._logic_manager = logic_manager
        self._rate_limiter = rate_limiter
        self._max_workers = max_workers
        self._cancel_event = threading.Event()


    def process_batch(self, items: typing.List[BatchItem]) -> typing.List[BatchItem]:
        results = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_item = {executor.submit(self._worker_task, item): item for item in items}
            for future in as_completed(future_to_item):
                try:
                    res_item = future.result()
                    results.append(res_item)
                except Exception as exc:
                    item = future_to_item[future]
                    item.mark_failed(str(exc))
                    results.append(item)
        return results


    def _worker_task(self, item: BatchItem) -> BatchItem:
        thread_name = threading.current_thread().name
        
        with self._print_lock:
            print(f"Worker {thread_name} started processing email {item.item_id}")

        if self._cancel_event.is_set():
            item.mark_failed("Task cancelled")
            return item

        item.mark_processing()
        try:
            self._rate_limiter.wait_if_needed()
            ai_result = self._ai_manager.analyze_message(
                item.email_content,
                interaction="unknown",
                include_scenarios=True,
            )
            
            if not isinstance(ai_result, dict) or "error" in ai_result:
                raise ValueError(ai_result.get("error", "AI analysis failed."))

            item.mark_completed(None, ai_result=ai_result)

        except Exception as e:
            item.mark_failed(str(e))

        with self._print_lock:
            print(f"Worker {thread_name} finished processing email {item.item_id}")

        return item

    
    def cancel(self) -> None:
        self._cancel_event.set()

