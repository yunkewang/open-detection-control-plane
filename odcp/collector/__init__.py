"""ODCP distributed collection agents.

A collector agent runs on any host with access to a security platform,
periodically scans its local detection content, and pushes the resulting
``ScanReport`` to a central ODCP server.

Quickstart::

    # Start a collector (blocks; use a systemd service or Docker in production)
    odcp collector start \\
        --platform splunk \\
        --scan-path /opt/splunk/etc/apps/security_app \\
        --central-url http://odcp-server:8080 \\
        --environment "Production SIEM" \\
        --interval 300

    # Or use a YAML config file
    odcp collector start --config agent.yaml

    # View fleet status from any machine
    odcp collector list --central-url http://odcp-server:8080
"""

from odcp.collector.agent import CollectionAgent
from odcp.collector.push_client import PushClient
from odcp.collector.registry import AgentRegistry

__all__ = ["AgentRegistry", "CollectionAgent", "PushClient"]
