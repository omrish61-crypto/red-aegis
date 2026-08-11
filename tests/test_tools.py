"""Safe mode gate tests — non-destructive enforcement for active exploitation tools."""

import pytest

from intected.tools import (
    SAFE_TOOLS,
    ToolError,
    execute,
    execute_streaming,
    validate_params,
)
from intected.supervisor import validate_tool_call


# ── SAFE_TOOLS set integrity ────────────────────────────────────────────────

def test_safe_tools_includes_recon_tools():
    """Every current registry tool that is recon/passive must be in SAFE_TOOLS."""
    expected = {
        "nmap_ports", "nmap_services", "http_headers", "nikto",
        "ffuf_content", "whatweb", "wafw00f", "dig", "gobuster",
        "dnsenum", "fierce", "dmitry", "snmpwalk",
    }
    assert SAFE_TOOLS == expected, f"SAFE_TOOLS mismatch: {SAFE_TOOLS}"


def test_safe_tools_no_exploitation_tools():
    """SAFE_TOOLS must NOT contain any exploitation / brute-force tool names."""
    exploitation = {"sqlmap", "msfconsole", "john", "hashcat", "hydra",
                    "medusa", "ncrack", "msfvenom", "beef", "searchsploit"}
    assert SAFE_TOOLS.isdisjoint(exploitation), \
        f"exploitation tools in SAFE_TOOLS: {SAFE_TOOLS & exploitation}"


# ── execute() safe mode gate ─────────────────────────────────────────────────

def test_execute_rejects_exploitation_tool_in_safe_mode():
    """Calling execute() with a non-SAFE_TOOLS tool must raise ToolError."""
    with pytest.raises(ToolError, match="active exploitation blocked"):
        execute("sqlmap", {"target": "127.0.0.1"}, safety_mode=True)


def test_execute_allows_exploitation_tool_when_safety_mode_false():
    """When safety_mode=False, exploit tools are passed through to WSL (which
    will likely fail, but the gate itself must not block)."""
    # sqlmap is not in the registry, so validate_params will fail first —
    # but that is expected. The point is the SAFE_TOOLS gate does NOT block.
    with pytest.raises(ToolError, match="unknown tool"):
        execute("sqlmap", {"target": "127.0.0.1"}, safety_mode=False)


def test_execute_allows_safe_tool_in_safe_mode():
    """A recon tool must pass through the safe mode gate without issue."""
    # This will fail at WSL level (no kali image), but the Python gate is tested.
    try:
        execute("nmap_ports", {"target": "127.0.0.1"}, safety_mode=True)
    except ToolError as e:
        # WSL not available is fine — the gate itself didn't block
        assert "active exploitation blocked" not in str(e)


def test_execute_defaults_to_safe_mode():
    """The default value for safety_mode in execute() must be True."""
    with pytest.raises(ToolError, match="active exploitation blocked"):
        execute("sqlmap", {"target": "127.0.0.1"})


# ── execute_streaming() safe mode gate ───────────────────────────────────────

def test_execute_streaming_rejects_exploitation_tool_in_safe_mode():
    """Calling execute_streaming() with a non-SAFE_TOOLS tool must raise."""
    with pytest.raises(ToolError, match="active exploitation blocked"):
        execute_streaming("sqlmap", {"target": "127.0.0.1"}, safety_mode=True)


def test_execute_streaming_allows_exploitation_tool_when_safety_mode_false():
    """When safety_mode=False, the safe-tools gate is not applied."""
    with pytest.raises(ToolError, match="unknown tool"):
        execute_streaming("sqlmap", {"target": "127.0.0.1"}, safety_mode=False)


def test_execute_streaming_defaults_to_safe_mode():
    """The default value for safety_mode in execute_streaming() must be True."""
    with pytest.raises(ToolError, match="active exploitation blocked"):
        execute_streaming("sqlmap", {"target": "127.0.0.1"})


# ── supervisor validate_tool_call safe mode gate ─────────────────────────────

def test_supervisor_rejects_non_safe_tool_with_safety_mode():
    """validate_tool_call must reject exploitation tools when safety_mode=True,
    even if operator_approved=True."""
    with pytest.raises(ValueError, match="active exploitation blocked"):
        validate_tool_call(
            "sqlmap", {"target": "127.0.0.1"}, ["127.0.0.1"],
            operator_approved=True, safety_mode=True,
        )


def test_supervisor_allows_non_safe_tool_with_safety_mode_false():
    """When safety_mode=False, the safe-tools gate is skipped."""
    # sqlmap is not in the tool registry, so validate_params fails.
    with pytest.raises(ToolError, match="unknown tool"):
        validate_tool_call(
            "sqlmap", {"target": "127.0.0.1"}, ["127.0.0.1"],
            operator_approved=True, safety_mode=False,
        )


def test_supervisor_allows_safe_tool_with_safety_mode():
    """A recon tool passes the supervisor gate when safety_mode=True."""
    # This will pass scope check (127.0.0.1 is in allowed_hosts)
    result = validate_tool_call(
        "nmap_ports", {"target": "127.0.0.1"}, ["127.0.0.1"],
        safety_mode=True,
    )
    assert result["ok"] is True
    assert result["supervisor"] == "approved"


def test_supervisor_defaults_to_safe_mode_true():
    """When safety_mode is omitted, it must default to True."""
    with pytest.raises(ValueError, match="active exploitation blocked"):
        validate_tool_call(
            "sqlmap", {"target": "127.0.0.1"}, ["127.0.0.1"],
        )
