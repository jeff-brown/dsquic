"""Reference endpoints: the package's I/O boundary.

Everything directly under dsquic/ is sans-IO. Modules in this subpackage
are the only code in the package permitted to touch sockets, files, and
the clock. They drive the protocol core in connection.py and contain no
protocol logic.
"""
