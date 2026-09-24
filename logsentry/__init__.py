"""
LogSentry, a small command line tool for spotting suspicious activity
in SSH auth logs and web access logs.

This is version 0.1, the first working pass. No automated tests yet,
thresholds are not configurable from the command line yet, and the
brute force detector uses a simpler fixed window approach instead of
a true sliding window. Those are all things I want to add next.
"""

__version__ = "0.1.0"
