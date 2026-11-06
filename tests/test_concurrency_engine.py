"""Unit tests for the concurrency engine: BatchItem, RateLimiter and BatchProcessor.

Written as unittest.TestCase classes so that `python run_tests.py`, CI and
`python -m unittest` all discover and run them. All tests are offline: the AI
manager is a fake, tqdm output is silenced and the rate limiter's clock is
mocked, so no test sleeps for real.
"""

import threading
import unittest
from unittest import mock

from src.batch.batch_item import BatchItem
from src.batch.batch_processor import BatchProcessor
from src.batch.rate_limiter import RateLimiter

AI_RESULT = {"message_classification": "scam", "indicators": {}}


class FakeAIManager:
    """Stands in for AIManager; records each call and returns a fixed answer."""

    def __init__(self, result=None, raise_error=None):
        self._result = AI_RESULT if result is None else result
        self._raise_error = raise_error
        self.calls = []
        self._lock = threading.Lock()

    def analyze_message(self, text, **kwargs):
        with self._lock:
            self.calls.append((text, kwargs))
        if self._raise_error is not None:
            raise self._raise_error
        return self._result(text) if callable(self._result) else self._result


def make_items(count, batch_id="BATCH-999"):
    return [BatchItem(f"ITEM-{n:03d}", f"email body {n}", batch_id) for n in range(1, count + 1)]


class BatchItemTests(unittest.TestCase):
    def test_new_item_is_pending_with_its_ids(self):
        item = BatchItem("ITEM-001", "test email content", "BATCH-123")

        self.assertEqual(item.status, "pending")
        self.assertEqual(item.item_id, "ITEM-001")
        self.assertEqual(item.batch_id, "BATCH-123")
        self.assertEqual(item.email_content, "test email content")
        self.assertIsNone(item.ai_result)
        self.assertIsNone(item.error_message)

    def test_processing_then_failed_keeps_the_error(self):
        item = BatchItem("ITEM-001", "body", "BATCH-123")

        item.mark_processing()
        self.assertEqual(item.status, "processing")

        item.mark_failed("API Timeout")
        self.assertEqual(item.status, "failed")
        self.assertEqual(item.error_message, "API Timeout")

    def test_completed_item_carries_the_ai_result(self):
        item = BatchItem("ITEM-001", "body", "BATCH-123")

        item.mark_completed(None, ai_result=AI_RESULT)

        self.assertEqual(item.status, "completed")
        self.assertEqual(item.ai_result, AI_RESULT)


class RateLimiterTests(unittest.TestCase):
    """The clock is mocked, so these check the exact wait without sleeping."""

    @mock.patch("src.batch.rate_limiter.time.sleep")
    @mock.patch("src.batch.rate_limiter.time.time")
    def test_calls_within_the_limit_do_not_wait(self, fake_time, fake_sleep):
        fake_time.side_effect = [0.0, 0.1]
        limiter = RateLimiter(max_calls=2, time_window=1)

        limiter.wait_if_needed()
        limiter.wait_if_needed()

        fake_sleep.assert_not_called()

    @mock.patch("src.batch.rate_limiter.time.sleep")
    @mock.patch("src.batch.rate_limiter.time.time")
    def test_call_over_the_limit_waits_until_the_window_frees_up(self, fake_time, fake_sleep):
        # Calls at t=0.0 and t=0.1 fill the 1-second window; the third call at
        # t=0.2 must wait until the first call is 1 second old (0.8 s more).
        fake_time.side_effect = [0.0, 0.1, 0.2, 1.0]
        limiter = RateLimiter(max_calls=2, time_window=1)

        for _ in range(3):
            limiter.wait_if_needed()

        fake_sleep.assert_called_once()
        self.assertAlmostEqual(fake_sleep.call_args.args[0], 0.8)

    @mock.patch("src.batch.rate_limiter.time.sleep")
    @mock.patch("src.batch.rate_limiter.time.time")
    def test_old_calls_leave_the_window(self, fake_time, fake_sleep):
        # By t=5.0 both earlier calls are outside the 1-second window.
        fake_time.side_effect = [0.0, 0.1, 5.0]
        limiter = RateLimiter(max_calls=2, time_window=1)

        for _ in range(3):
            limiter.wait_if_needed()

        fake_sleep.assert_not_called()


class BatchProcessorTests(unittest.TestCase):
    def setUp(self):
        # Silence the progress bar and worker log lines during tests.
        patcher = mock.patch("src.batch.batch_processor.tqdm")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.limiter = mock.Mock(spec=RateLimiter)

    def make_processor(self, ai_manager, max_workers=2):
        return BatchProcessor(ai_manager, mock.Mock(), self.limiter, max_workers=max_workers)

    def test_every_item_is_analysed_and_completed(self):
        ai = FakeAIManager()
        items = make_items(4)

        results = self.make_processor(ai).process_batch(items)

        self.assertEqual(len(results), 4)
        self.assertEqual({item.item_id for item in results}, {item.item_id for item in items})
        for item in results:
            with self.subTest(item=item.item_id):
                self.assertEqual(item.status, "completed")
                self.assertEqual(item.ai_result, AI_RESULT)
                self.assertEqual(item.batch_id, "BATCH-999")

    def test_ai_is_asked_about_each_email_with_unknown_interaction(self):
        ai = FakeAIManager()

        self.make_processor(ai).process_batch(make_items(3))

        self.assertEqual(
            sorted(text for text, _ in ai.calls),
            ["email body 1", "email body 2", "email body 3"],
        )
        for _, kwargs in ai.calls:
            self.assertEqual(kwargs, {"interaction": "unknown", "include_scenarios": True})

    def test_rate_limiter_is_checked_once_per_email(self):
        self.make_processor(FakeAIManager()).process_batch(make_items(5))

        self.assertEqual(self.limiter.wait_if_needed.call_count, 5)

    def test_ai_error_fails_only_that_email(self):
        def answer(text):
            return {"error": "quota exceeded"} if text == "email body 2" else AI_RESULT

        results = self.make_processor(FakeAIManager(result=answer)).process_batch(make_items(3))
        by_id = {item.item_id: item for item in results}

        self.assertEqual(by_id["ITEM-002"].status, "failed")
        self.assertEqual(by_id["ITEM-002"].error_message, "quota exceeded")
        self.assertEqual(by_id["ITEM-001"].status, "completed")
        self.assertEqual(by_id["ITEM-003"].status, "completed")

    def test_ai_exception_is_caught_and_recorded(self):
        ai = FakeAIManager(raise_error=ConnectionError("network down"))

        results = self.make_processor(ai).process_batch(make_items(2))

        self.assertEqual([item.status for item in results], ["failed", "failed"])
        self.assertEqual({item.error_message for item in results}, {"network down"})

    def test_cancelled_batch_skips_the_ai(self):
        ai = FakeAIManager()
        processor = self.make_processor(ai)

        processor.cancel()
        results = processor.process_batch(make_items(3))

        self.assertEqual(ai.calls, [])
        self.assertTrue(all(item.status == "failed" for item in results))
        self.assertTrue(all(item.error_message == "Task cancelled" for item in results))

    def test_workers_really_run_at_the_same_time(self):
        # Each call waits at a barrier until a second worker arrives. With two
        # threads both calls meet and pass; if emails were processed one at a
        # time the barrier would time out and the items would fail.
        barrier = threading.Barrier(2, timeout=5)
        thread_names = set()

        def answer(_text):
            thread_names.add(threading.current_thread().name)
            barrier.wait()
            return AI_RESULT

        results = self.make_processor(FakeAIManager(result=answer), max_workers=2).process_batch(make_items(2))

        self.assertEqual([item.status for item in results], ["completed", "completed"])
        self.assertEqual(len(thread_names), 2)


if __name__ == "__main__":
    unittest.main()
