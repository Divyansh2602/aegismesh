"""Trusted tool registry.

A tool's output is only P2 (trusted-tool) if the tool is pinned here *and* its advertised
description still hashes to the pinned value. Everything else is P3.

This is control C-4/C-5 from THREAT_MODEL.md. It is what stops tool poisoning: a malicious
MCP server that rewrites its tool description to smuggle instructions changes the hash, so
it silently drops out of the trusted set instead of silently gaining influence.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.common.hashing import hash_text


class TrustedTool(BaseModel):
    """A pinned tool: identified by name, bound to a description hash."""

    name: str
    origin: str
    description_hash: str
    """Hash of the tool description as reviewed and approved."""

    relays_external_content: bool = True
    """True if this tool's *responses* carry data from outside the trust boundary.

    Tool integrity and content provenance are different properties, and conflating them
    is a live vulnerability. Pinning ``invoice_reader`` establishes that it faithfully
    parses a PDF -- it says nothing about whether the *supplier who wrote that PDF* is
    honest. A conduit tool (PDF reader, web fetcher, email client, search) is trusted to
    do its job and its responses are still attacker-controlled by design, so they stay P3.

    Only closed-world tools -- ones returning operator-controlled data such as an internal
    database lookup -- may set this False and have their responses classed P2.

    Defaults to True because the safe assumption for an unreviewed tool is that it touches
    the outside world.
    """

    note: str = ""


class DriftEvent(BaseModel):
    """Recorded when a pinned tool's description no longer matches its pin."""

    tool_name: str
    expected_hash: str
    observed_hash: str


class ToolRegistry:
    """Pinned tools, and the drift observed against them.

    Drift is accumulated rather than raised. A description change is not necessarily an
    attack -- vendors do update tools -- but it must never pass silently, and it must
    downgrade the tool's trust until a human re-pins it.
    """

    def __init__(self, tools: list[TrustedTool] | None = None) -> None:
        self._tools: dict[str, TrustedTool] = {t.name: t for t in (tools or [])}
        self._drift: list[DriftEvent] = []

    def pin(
        self,
        name: str,
        origin: str,
        description: str,
        relays_external_content: bool = True,
        note: str = "",
    ) -> TrustedTool:
        tool = TrustedTool(
            name=name,
            origin=origin,
            description_hash=hash_text(description),
            relays_external_content=relays_external_content,
            note=note,
        )
        self._tools[name] = tool
        return tool

    def response_is_trusted(self, name: str) -> bool:
        """Whether a *response* from this tool may be classed P2.

        Distinct from ``is_trusted``, which governs the tool's own declaration. A pinned
        conduit tool passes ``is_trusted`` (its description is authentic) while failing
        this (its payload is not).
        """
        tool = self._tools.get(name)
        return tool is not None and not tool.relays_external_content

    def get(self, name: str) -> TrustedTool | None:
        return self._tools.get(name)

    def is_trusted(self, name: str, description: str | None = None) -> bool:
        """True only if the tool is pinned and its description matches the pin.

        A pinned tool whose description is not supplied is treated as trusted: the caller
        had no description to check, which happens for tool *responses* where only the
        name is in scope. Description verification happens at declaration time, in
        ``check_declarations``.
        """
        tool = self._tools.get(name)
        if tool is None:
            return False
        if description is None:
            return True
        return hash_text(description) == tool.description_hash

    def check_declarations(self, declared: dict[str, str]) -> list[DriftEvent]:
        """Verify a batch of advertised tool descriptions against their pins.

        ``declared`` maps tool name to the description the server advertised right now.
        Returns drift events for pinned tools whose description changed. Unpinned tools
        are not drift -- they were never trusted to begin with.
        """
        events: list[DriftEvent] = []
        for name, description in declared.items():
            tool = self._tools.get(name)
            if tool is None:
                continue
            observed = hash_text(description)
            if observed != tool.description_hash:
                events.append(
                    DriftEvent(
                        tool_name=name,
                        expected_hash=tool.description_hash,
                        observed_hash=observed,
                    )
                )
        self._drift.extend(events)
        return events

    @property
    def drift(self) -> list[DriftEvent]:
        return list(self._drift)

    def descriptions_hash_input(self) -> list[str]:
        """Sorted pinned hashes, for the warrant's ``tool_descriptions_hash`` field."""
        return sorted(t.description_hash for t in self._tools.values())


class MandateContext(BaseModel):
    """The authenticated human instruction this request derives authority from.

    The proxy needs the verbatim instruction text (or its hash) to recognise which part of
    a user turn is genuinely the principal speaking. Agent frameworks routinely paste
    retrieved documents into user-role messages, so role alone cannot establish P0 --
    treating every user message as human intent would hand an attacker the highest trust
    class for free.
    """

    mandate_id: str
    principal: str
    instruction: str
    instruction_hash: str = ""

    def model_post_init(self, _context: object) -> None:
        if not self.instruction_hash:
            object.__setattr__(self, "instruction_hash", hash_text(self.instruction))


class ProxyPolicy(BaseModel):
    """Static configuration governing classification."""

    registry_tools: list[TrustedTool] = Field(default_factory=list)
    treat_unpinned_tools_as_untrusted: bool = True
