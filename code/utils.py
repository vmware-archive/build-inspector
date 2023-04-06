# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import functools
import signal

class TimeoutExpiredError(Exception):
    pass

def timeout(seconds: int=1):
    def decorator(func):
        def _handler(signum, frame):
            raise TimeoutExpiredError((f'Function {func.__name__} timed out after {seconds} seconds.',func.__name__, seconds))
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        
        return wrapper

    return decorator