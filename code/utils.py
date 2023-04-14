# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import functools
import signal
import threading
import logging

class TimeoutExpiredError(Exception):
    pass

def timeout(seconds: int=1):
    logger = logging.getLogger("TimeoutDecoratorLogger")
    def decorator(func):
        def _handler(signum, frame):
            raise TimeoutExpiredError(f'Function {func.__name__} timed out after {seconds} seconds.',func.__name__, seconds)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGALRM, _handler)
                signal.alarm(seconds)
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)
            else:
                logger.warning('Running inside non-main thread. Timeout is not available in this context.')
                result = func(*args, **kwargs)
            return result
        
        return wrapper

    return decorator