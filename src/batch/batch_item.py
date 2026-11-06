import typing
from src.models.submission import Submission

class BatchItem:
    def __init__(self, item_id: str, email_content: str, batch_id: str) -> None:
        self._item_id = item_id
        self._email_content = email_content
        self._batch_id = batch_id
        self._status = "pending"
        self._submission = None
        self._error_message = None

    @property
    def item_id(self) -> str:
        return self._item_id

    @property
    def email_content(self) -> str:
        return self._email_content

    @property
    def batch_id(self) -> str:
        return self._batch_id

    @property
    def status(self) -> str:
        return self._status

    @property
    def submission(self) -> typing.Optional[Submission]:
        return self._submission

    @property
    def error_message(self) -> typing.Optional[str]:
        return self._error_message

    def mark_processing(self) -> None:
        self._status = "processing"

    def mark_completed(self, submission: Submission, ai_result: typing.Optional[dict] = None) -> None:
        self._status = "completed"
        self._submission = submission
        self._ai_result = ai_result

    @property
    def ai_result(self) -> typing.Optional[dict]:
        return getattr(self, "_ai_result", None)

    def mark_failed(self, error_message: str) -> None:
        self._status = "failed"
        self._error_message = error_message