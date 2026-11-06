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

    def _worker_task(self, item: BatchItem) -> BatchItem:
        if self._cancel_event.is_set():
            item.mark_failed("Task cancelled")
            return item

        item.mark_processing()
        try:
            submission = Submission(
                input_type="text",
                input_value=item.email_content,
                data_origin="batch",
                dataset_batch_id=item.batch_id,
            )

            self._rate_limiter.wait_if_needed()
            ai_result = self._ai_manager.analyze_message(
                item.email_content,
                interaction="unknown",
                include_scenarios=True,
            )

            indicators = ai_result.get("indicators", [])
            for ind in indicators:
                if ind.get("present") is True:
                    evidence = ThreatEvidence(indicator=ind)
                    submission.create_evidence(evidence)

            self._logic_manager.evaluate_text_threat(submission, ai_result)
            item.mark_completed(submission)

        except Exception as e:
            item.mark_failed(str(e))

        return item

    def cancel(self) -> None:
        self._cancel_event.set()

        