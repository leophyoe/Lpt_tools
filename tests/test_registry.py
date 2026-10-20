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
