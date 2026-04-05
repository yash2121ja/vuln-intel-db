"""Celery worker — runs advisory collectors on schedule."""

from celery import Celery
from celery.schedules import crontab
from src.config import get_settings

settings = get_settings()

app = Celery("vulnintel", broker=settings.CELERY_BROKER_URL, backend=settings.REDIS_URL)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    task_routes={
        "src.worker.*": {"queue": "collectors"},
    },
)


# ── Collector tasks ──────────────────────────────────────────────────────

@app.task(name="src.worker.sync_debian")
def sync_debian():
    from src.collectors.debian import DebianCollector
    return DebianCollector().run()


@app.task(name="src.worker.sync_alpine")
def sync_alpine():
    from src.collectors.alpine import AlpineCollector
    return AlpineCollector().run()


@app.task(name="src.worker.sync_ghsa")
def sync_ghsa():
    from src.collectors.ghsa import GhsaCollector
    return GhsaCollector().run()


@app.task(name="src.worker.sync_nvd")
def sync_nvd():
    from src.collectors.nvd import NvdCollector
    return NvdCollector().run()


@app.task(name="src.worker.sync_epss")
def sync_epss():
    from src.collectors.epss import EpssCollector
    return EpssCollector().run()


@app.task(name="src.worker.sync_kev")
def sync_kev():
    from src.collectors.kev import KevCollector
    return KevCollector().run()


@app.task(name="src.worker.sync_govuln")
def sync_govuln():
    from src.collectors.govuln import GoVulnCollector
    return GoVulnCollector().run()


@app.task(name="src.worker.sync_rustsec")
def sync_rustsec():
    from src.collectors.rustsec import RustSecCollector
    return RustSecCollector().run()


@app.task(name="src.worker.sync_all")
def sync_all():
    """Run all collectors sequentially."""
    results = {}
    for name, fn in [
        ("debian", sync_debian),
        ("alpine", sync_alpine),
        ("ghsa", sync_ghsa),
        ("nvd", sync_nvd),
        ("kev", sync_kev),
        ("epss", sync_epss),
        ("govuln", sync_govuln),
        ("rustsec", sync_rustsec),
    ]:
        try:
            results[name] = fn()
        except Exception as exc:
            results[name] = {"error": str(exc)}
    return results


# ── Beat schedule ────────────────────────────────────────────────────────

app.conf.beat_schedule = {
    "sync-debian": {
        "task": "src.worker.sync_debian",
        "schedule": crontab(minute=0, hour="*/3"),
    },
    "sync-alpine": {
        "task": "src.worker.sync_alpine",
        "schedule": crontab(minute=15, hour="*/3"),
    },
    "sync-ghsa": {
        "task": "src.worker.sync_ghsa",
        "schedule": crontab(minute=30, hour="*/2"),
    },
    "sync-nvd": {
        "task": "src.worker.sync_nvd",
        "schedule": crontab(minute=45, hour="*/6"),
    },
    "sync-kev": {
        "task": "src.worker.sync_kev",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "sync-epss": {
        "task": "src.worker.sync_epss",
        "schedule": crontab(minute=0, hour=4),  # daily at 04:00 UTC
    },
    "sync-govuln": {
        "task": "src.worker.sync_govuln",
        "schedule": crontab(minute=10, hour="*/4"),
    },
    "sync-rustsec": {
        "task": "src.worker.sync_rustsec",
        "schedule": crontab(minute=20, hour="*/6"),
    },
}
