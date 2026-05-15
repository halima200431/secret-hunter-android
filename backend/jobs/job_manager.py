import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class JobRecord:
    analysis_id: str
    status: str = "pending"
    progress: int = 0
    message: str = "Analyse en attente."
    metadata: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "analysisId": self.analysis_id,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "metadata": self.metadata,
            "error": self.error,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class JobManager:
    def __init__(self):
        self._jobs: Dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def create_job(self, analysis_id: str, metadata: Optional[Dict[str, Any]] = None) -> JobRecord:
        with self._lock:
            job = JobRecord(
                analysis_id=analysis_id,
                metadata=metadata or {},
            )
            self._jobs[analysis_id] = job
            return job

    def get_job(self, analysis_id: str) -> Optional[JobRecord]:
        with self._lock:
            return self._jobs.get(analysis_id)

    def update_job(
        self,
        analysis_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        message: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Optional[JobRecord]:
        with self._lock:
            job = self._jobs.get(analysis_id)

            if job is None:
                return None

            if status is not None:
                job.status = status

            if progress is not None:
                job.progress = max(0, min(100, progress))

            if message is not None:
                job.message = message

            if result is not None:
                job.result = result

            if error is not None:
                job.error = error

            job.updated_at = utc_now()
            return job

    def start_job(self, analysis_id: str, target: Callable, **kwargs) -> None:
        thread = threading.Thread(
            target=self._run_job_safely,
            args=(analysis_id, target, kwargs),
            daemon=True,
        )
        thread.start()

    def _run_job_safely(self, analysis_id: str, target: Callable, kwargs: Dict[str, Any]) -> None:
        try:
            self.update_job(
                analysis_id,
                status="running",
                progress=10,
                message="Analyse démarrée.",
            )

            result = target(analysis_id=analysis_id, **kwargs)

            self.update_job(
                analysis_id,
                status="completed",
                progress=100,
                message="Analyse terminée.",
                result=result,
            )

        except Exception as error:
            traceback.print_exc()

            self.update_job(
                analysis_id,
                status="failed",
                progress=100,
                message="Analyse échouée.",
                error=str(error),
            )


job_manager = JobManager()