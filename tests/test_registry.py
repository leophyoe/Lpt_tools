"""Unit tests for ToolRegistry."""

from core.registry import ToolMetadata, ToolRegistry


def test_tool_registry_discovers_nmap():
    registry = ToolRegistry()
    nmap = registry.get_tool("nmap")
    assert nmap is not None
    assert nmap.is_installed is True
    assert nmap.binary_path is not None
    assert nmap.version is not None
    assert "Nmap version" in nmap.version
    assert registry.is_available("nmap") is True


def test_tool_registry_handles_missing_tool():
    custom_tool = ToolMetadata(
        name="nonexistent_sec_tool_12345",
        display_name="Fake Tool",
        binary_name="nonexistent_sec_tool_12345",
        category="custom",
    )
    registry = ToolRegistry(tools=[custom_tool])
    tool = registry.get_tool("nonexistent_sec_tool_12345")
    assert tool is not None
    assert tool.is_installed is False
    assert tool.binary_path is None
    assert registry.is_available("nonexistent_sec_tool_12345") is False


def test_tool_registry_sqlmap_and_wafw00f_execution():
    """Verify sqlmap and wafw00f wrappers execute with code 0 without SyntaxError."""
    registry = ToolRegistry()
    sqlmap = registry.get_tool("sqlmap")
    assert sqlmap is not None
    assert sqlmap.is_installed is True
    ok, out, code = registry.test_tool("sqlmap")
    assert ok is True
    assert code == 0
    assert "SyntaxError" not in out
    assert "1.10" in out or "sqlmap" in out.lower()

    wafw00f = registry.get_tool("wafw00f")
    assert wafw00f is not None
    assert wafw00f.is_installed is True
    ok_w, out_w, code_w = registry.test_tool("wafw00f")
    assert ok_w is True
    assert code_w == 0
    assert "SyntaxError" not in out_w
    assert "WAFW00F" in out_w


def test_tool_registry_truthfully_reports_dependency_failures():
    """Verify tools with missing system dependencies (like nikto missing XML::Writer) are not marked functional."""
    registry = ToolRegistry()
    nikto = registry.get_tool("nikto")
    assert nikto is not None
    # On this environment, libxml-writer-perl is absent, so nikto must NOT be claimed as installed
    assert nikto.is_installed is False
    assert nikto.error_message is not None
    assert "XML::Writer" in nikto.error_message

    ok, out, code = registry.test_tool("nikto")
    assert ok is False
    assert code == 127
    assert "XML::Writer" in out
    assert "sudo apt install" in out

