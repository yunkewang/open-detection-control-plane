"""ODCP web dashboard server.

Start the dashboard::

    odcp serve report.json --port 8080

Or programmatically::

    from odcp.server import create_app, ReportStore

    store = ReportStore("report.json")
    app = create_app(store)

Requires the ``server`` extra::

    pip install 'odcp[server]'
"""

from odcp.server.app import create_app
from odcp.server.state import ReportStore

__all__ = ["create_app", "ReportStore"]
