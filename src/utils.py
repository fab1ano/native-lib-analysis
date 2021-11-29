#!/usr/bin/env python
import fnmatch
import os
from pathlib import Path


def find(pattern, path):
    """Finds all files in path matching pattern."""
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(Path(root) / name)
    return result
