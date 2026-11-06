import logging
import threading
import typing
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from src.batch.batch_item import BatchItem
from src.batch.rate_limiter import RateLimiter
from src.managers.ai_manager import AIManager

LOGGER = logging.getLogger(__name__)


class BatchProcessor:
    """Analyse many emails at once with a pool of worker threads.

    Workers only call the AI (through the shared RateLimiter) and record the
    answer on their BatchItem. They never print or touch the database: the
    progress bar is drawn by the main thread, and EngineCoordinator saves and
    assesses every result on the main thread afterwards.

    Aggregation: the AIManager and RateLimiter are injected and shared.
    """

    def __init__(self, ai_manager: AIManager, rate_limiter: RateLimiter, max_workers: int = 5) -> None:
        self._ai_manager = ai_manager
        self._rate_limiter = rate_limiter
        self._max_workers = max_workers
        self._cancel_event = threading.Event()

    def process_batch(self, items: typing.List[BatchItem]) -> typing.List[BatchItem]:
        """Analyse every item concurrently and return them all.

        Ctrl+C while the batch runs calls cancel(): emails still waiting in
        the queue are skipped instead of being sent to the AI, then the
        interrupt is passed on so the application can end cleanly.
        """
        self._cancel_event.clear()
        results = []
        executor = ThreadPoolExecutor(max_workers=self._max_workers)
        try:
            future_to_item = {executor.submit(self._worker_task, item): item for item in items}
            with tqdm(total=len(items), desc="Analyzing Emails") as pbar:
                for future in as_completed(future_to_item):
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        item = future_to_item[future]
                        item.mark_failed(str(exc))
                        results.append(item)
                    finally:
                        pbar.update(1)
        except KeyboardInterrupt:
            self.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        finally:
            executor.shutdown(wait=True)
        return results

    def _worker_task(self, item: BatchItem) -> BatchItem:
        """Runs in a worker thread: ask the AI about one email (no output)."""
        if self._cancel_event.is_set():
            item.mark_failed("Task cancelled")
            return item

        item.mark_processing()
        LOGGER.debug("%s analysing email %s", threading.current_thread().name, item.item_id)
        try:
            self._rate_limiter.wait_if_needed()
            ai_result = self._ai_manager.analyze_message(
                item.email_content,
                interaction="unknown",
                include_scenarios=True,
            )

            if not isinstance(ai_result, dict) or "error" in ai_result:
                error = ai_result.get("error") if isinstance(ai_result, dict) else None
                raise ValueError(error or "AI analysis failed.")

            item.mark_completed(None, ai_result=ai_result)

        except Exception as error:
            item.mark_failed(str(error))

        return item

    def cancel(self) -> None:
        """Stop the batch: workers that have not started yet skip their email."""
        self._cancel_event.set()
