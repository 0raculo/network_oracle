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

    debug_logger = logging.getLogger("debug")
    debug_handler = logging.FileHandler(f"{log_dir}/debug_{timestamp}.log")
    debug_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    debug_handler.setFormatter(debug_formatter)
    debug_logger.addHandler(debug_handler)
    debug_logger.setLevel(logging.DEBUG)

    error_logger = logging.getLogger("error")
    error_handler = logging.FileHandler(f"{log_dir}/error_{timestamp}.log")
    error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - ERROR - %(message)s')
    error_handler.setFormatter(error_formatter)
    error_logger.addHandler(error_handler)
    error_logger.setLevel(logging.ERROR)

    return session_logger, error_logger, debug_logger
