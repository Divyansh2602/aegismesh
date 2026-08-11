"""aegis-api — the public HTTP surface (Phase 5).

Kept separate from ``aegis.proxy`` on purpose. The proxy sits in front of a real agent
and must stay a faithful passthrough; this app serves strangers on the internet a
sandbox. Conflating them would put a public attack surface on the interception path.
"""
