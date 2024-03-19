import os
import logging
from datetime import datetime

def setup_logging():
    log_dir = 'log'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_logger = logging.getLogger("session")
    session_handler = logging.FileHandler(f"{log_dir}/session_{timestamp}.log")
    session_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    session_handler.setFormatter(session_formatter)
    session_logger.addHandler(session_handler)
    session_logger.setLevel(logging.INFO)

    error_logger = logging.getLogger("error")
    error_handler = logging.FileHandler(f"{log_dir}/error_{timestamp}.log")
    error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - ERROR - %(message)s')
    error_handler.setFormatter(error_formatter)
    error_logger.addHandler(error_handler)
    error_logger.setLevel(logging.ERROR)

    return session_logger, error_logger
