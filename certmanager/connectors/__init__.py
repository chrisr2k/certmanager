"""CA Connector implementations.

Each connector implements the CAConnector ABC defined in base.py.
The connector factory (get_connector) creates the appropriate connector
from a CA configuration record, following the pattern used by entra-pentest's
LLMProvider.get_llm() factory.
"""
