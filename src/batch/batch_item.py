import typing
from src.models.submission import Submission

class BatchItem:
    def init(self, item_id: str, email_content: str, batch_id: str) -> None:
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

    def set_status(self, status: str) -> None:
        self._status = status

    def set_submission(self, submission: Submission) -> None:
        self._submission = submission

    def set_error_message(self, error_message: str) -> None:
        self._error_message = error_message


        