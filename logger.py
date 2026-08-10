import logging
import os


def setup_logging():

    os.makedirs(
        "logs",
        exist_ok=True
    )

    logging.basicConfig(
        filename="logs/monitor.log",
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(message)s"
        )
    )


def log_event(message):
    logging.info(message)