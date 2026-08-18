import pytest

from blackarch_ai_mcp.subprocess_utils import ToolNotInstalledError, run_tool


def test_run_tool_executes_arg_list():
    result = run_tool(["echo", "hello world"])
    assert result.returncode == 0
    assert "hello world" in result.stdout


def test_run_tool_rejects_empty_args():
    with pytest.raises(ValueError):
        run_tool([])


def test_run_tool_raises_for_missing_binary():
    with pytest.raises(ToolNotInstalledError):
        run_tool(["definitely-not-a-real-binary-xyz"])


def test_run_tool_never_uses_shell_semantics():
    # If shell=True were used, this arg would be interpreted by a shell and
    # `;` would separate commands. With shell=False it must be passed through
    # literally as a single argument to `echo`.
    result = run_tool(["echo", "a; echo b"])
    assert result.stdout.strip() == "a; echo b"


def test_run_tool_times_out():
    result = run_tool(["sleep", "5"], timeout=1)
    assert result.timed_out is True
