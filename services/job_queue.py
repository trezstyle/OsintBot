"""Async job queue for long-running operations (scan, report)."""
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from services.notifier import send_message_sync

log = logging.getLogger("cyber_volt.job_queue")


class JobStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Job:
    id: str
    chat_id: int
    description: str
    fn: Callable[[], Any]
    status: JobStatus = JobStatus.QUEUED
    result: Optional[str] = None
    created: float = field(default_factory=time.monotonic)


_JOBS_MAX = 100
_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()
_jobs_cond = threading.Condition(_jobs_lock)
_worker_thread: Optional[threading.Thread] = None


def _worker():
    while True:
        job = None
        with _jobs_cond:
            while True:
                for j in _jobs.values():
                    if j.status == JobStatus.QUEUED:
                        j.status = JobStatus.RUNNING
                        job = j
                        break
                if job is not None:
                    break
                _jobs_cond.wait()
        try:
            log.info("Running job %s: %s", job.id, job.description)
            result = job.fn()
            with _jobs_lock:
                job.status = JobStatus.DONE
                job.result = str(result) if result else "Done"
            send_message_sync(
                job.chat_id,
                f"✅ *Job Complete: {job.description}*\n`{job.id}`",
                parse_mode="Markdown",
            )
        except Exception as e:
            log.exception("Job %s failed: %s", job.id, e)
            with _jobs_lock:
                job.status = JobStatus.FAILED
                job.result = str(e)
            send_message_sync(
                job.chat_id,
                f"❌ *Job Failed: {job.description}*\n```\n{e}\n```",
                parse_mode="Markdown",
            )


def submit(chat_id: int, description: str, fn: Callable[[], Any]) -> str:
    global _worker_thread
    job_id = uuid.uuid4().hex[:12]
    job = Job(id=job_id, chat_id=chat_id, description=description, fn=fn)
    with _jobs_cond:
        # Evict completed jobs when over limit
        if len(_jobs) >= _JOBS_MAX:
            done_ids = [jid for jid, j in _jobs.items()
                        if j.status in (JobStatus.DONE, JobStatus.FAILED)]
            for jid in done_ids[:len(done_ids) - _JOBS_MAX // 2]:
                del _jobs[jid]
        _jobs[job_id] = job
        _jobs_cond.notify()
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(target=_worker, daemon=True)
        _worker_thread.start()
    return job_id


def get_status(job_id: str) -> Optional[Job]:
    with _jobs_lock:
        return _jobs.get(job_id)


def format_job_status(job_id: str) -> str:
    job = get_status(job_id)
    if job is None:
        return f"❌ Job `{job_id}` not found."
    emoji = {
        JobStatus.QUEUED: "⏳",
        JobStatus.RUNNING: "🔄",
        JobStatus.DONE: "✅",
        JobStatus.FAILED: "❌",
    }
    status_line = f"{emoji[job.status]} *Job `{job.id}`*\nDescription: `{job.description}`\nStatus: `{job.status.value}`"
    if job.status in (JobStatus.DONE, JobStatus.FAILED) and job.result:
        status_line += f"\n\n```\n{job.result[:500]}\n```"
    return status_line
