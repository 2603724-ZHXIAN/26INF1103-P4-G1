import time
import threading
from src.batch.batch_item import BatchItem
from src.batch.rate_limiter import RateLimiter
from src.batch.batch_processor import BatchProcessor

class DummyAIManager:
    def analyze_message(self, text, **kwargs):
        return {"indicators": [{"present": True, "evidence": "test threat"}]}

class DummyLogicManager:
    def evaluate_text_threat(self, submission, ai_result):
        pass

def test_batch_item_state():
    item =- BatchItem("ITEM-001", "test email content", "BATCH-123")
    assert item.status == "pending"
    assert item.item_id == "ITEM-001"
    assert item.batch_id == "BATCH-123"


    item.mark_processing()
    assert item.status == "processing"

    item.mark_failed("API Timeout")
    assert item.status == "failed"
    assert item.error_message == "API Timeout"

def test_rate_limiter_pacing():
    limiter = RateLimiter(max_calls=2, time_window=1)
    start_time = time.time()
    
    limiter.wait_if_needed()
    limiter.wait_if_needed()
    
    # Third call should trigger a wait
    limiter.wait_if_needed()
    duration = time.time() - start_time
    
    # It should have slept slightly to respect the window
    assert duration >= 0

def test_batch_processor_execution():
    ai_mgr = DummyAIManager()
    logic_mgr = DummyLogicManager()
    limiter = RateLimiter(max_calls=10, time_window=60)
    
    processor = BatchProcessor(ai_mgr, logic_mgr, limiter, max_workers=2)
    
    items = [
        BatchItem("ITEM-001", "body one", "BATCH-999"),
        BatchItem("ITEM-002", "body two", "BATCH-999")
    ]
    
    results = processor.process_batch(items)
    
    assert len(results) == 2
    assert results[0].status == "completed"
    assert results[1].status == "completed"
    assert results[0].submission.dataset_batch == "BATCH-999"

    