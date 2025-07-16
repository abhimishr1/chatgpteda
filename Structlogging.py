# log_wrapper.py

import scrubadub
import structlog

scrubber = scrubadub.Scrubber()

def redact_pii(_, __, event_dict):
    redacted = {}
    for key, value in event_dict.items():
        if isinstance(value, str):
            redacted[key] = scrubber.clean(value)
        else:
            redacted[key] = value
    return redacted


def setup_logger():
    import logging

    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
        force=True
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            redact_pii,  # 👈 PII sanitizer placed before rendering
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger()
