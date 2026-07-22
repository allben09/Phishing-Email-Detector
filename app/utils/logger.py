from loguru import logger
import sys
import os
from datetime import datetime

# Remove default handler
logger.remove()

# Add console handler
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)

# Add file handler
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

logger.add(
    f"{log_dir}/phishing_detector_{datetime.now().strftime('%Y%m%d')}.log",
    rotation="500 MB",
    retention="30 days",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level="DEBUG"
)

# Add error file handler
logger.add(
    f"{log_dir}/errors_{datetime.now().strftime('%Y%m%d')}.log",
    rotation="100 MB",
    retention="30 days",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level="ERROR"
)

# Export logger
__all__ = ["logger"]
