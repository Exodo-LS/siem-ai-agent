# agent/retry.py
import time
import logging

logger = logging.getLogger(__name__)

def with_retry(fn, max_attempts=3, base_delay=2):
    """
    Retry a function with exponential backoff.
    Raises the last exception if all attempts fail.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as e:
            if attempt == max_attempts:
                logger.error(f"All {max_attempts} attempts failed. Last error: {e}")
                raise
            delay = base_delay ** attempt
            logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay}s...")
            print(f"    [retry] Attempt {attempt} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)
