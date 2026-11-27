"""Download diagnostics and repeatable setup, without network access."""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_reach import __version__
from agent_reach.runtime import tools
from agent_reach.runtime.result import TIMEOUT, ReachError


def _no_proxy(monkeypatch):
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(tools, "extend_path", lambda: None)


def test_package_version_matches_runtime_version():
    # The package metadata and --version must describe the same release.
    import re

    project = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', project, re.MULTILINE).group(1) == __version__


def test_download_env_copies_system_proxy_for_both_install_stages(monkeypatch):
    _no_proxy(monkeypatch)
    monkeypatch.setattr(tools.urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:8899", "no": "localhost"})
    env = tools.install_env()
    assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == "http://127.0.0.1:8899"
    assert env["NO_PROXY"] == "localhost"
    assert "HTTPS_PROXY" not in os.environ


@pytest.mark.parametrize("key", ["https_proxy", "HTTP_PROXY", "ALL_PROXY"])
def test_explicit_proxy_is_kept_without_consulting_system(monkeypatch, key):
    _no_proxy(monkeypatch)
    monkeypatch.setenv(key, "http://127.0.0.1:7788")
    monkeypatch.setattr(tools.urllib.request, "getproxies", lambda: pytest.fail("explicit proxy must win"))
    env = tools.install_env()
    assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == "http://127.0.0.1:7788"


def test_pip_timeout_names_stage_and_redacts_proxy(monkeypatch):
    monkeypatch.setattr(tools, "_install_env", lambda: {"HTTPS_PROXY": "http://user:secret@127.0.0.1:7788"})

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(tools.subprocess, "run", timeout)
    with pytest.raises(ReachError) as err:
        tools._run(["python", "-m", "pip"], timeout=1, stage="cloakbrowser:pip_packages")
    assert err.value.code == TIMEOUT
    assert "cloakbrowser:pip_packages" in err.value.message
    assert "configured proxy" in err.value.hint
    assert "secret" not in str(err.value) + err.value.hint


def test_install_failure_scrubs_upstream_url_credentials(monkeypatch):
    monkeypatch.setattr(tools, "_install_env", lambda: {})
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout="", stderr="Could not connect to https://user:secret@example.com/download?token=abc"))
    with pytest.raises(ReachError) as err:
        tools._run(["pip", "install", "cloakbrowser"], stage="cloakbrowser:pip_packages")
    assert "secret" not in str(err.value)
    assert "token=abc" not in str(err.value)
    assert "direct network" in err.value.hint


def test_rerunning_pip_setup_preserves_partial_environment(monkeypatch, tmp_path):
    tool = tools.TOOLS["cloakbrowser"]
    monkeypatch.setattr(tools, "tool_dir", lambda name: tmp_path / name)
    venv = tmp_path / tool.name / "venv"
    py = venv / ("Scripts/python.exe" if tools._WIN else "bin/python")
    py.parent.mkdir(parents=True)
    py.write_text("already installed interpreter")
    marker = venv / "partially-installed-package"
    marker.write_text("keep")
    calls = []
    monkeypatch.setattr(tools, "_run", lambda argv, **kwargs: calls.append((argv, kwargs)) or "")
    tools._install_pip(tool)
    assert marker.read_text() == "keep"
    assert len(calls) == 1
    assert calls[0][0][:4] == [str(py), "-m", "pip", "install"]
    assert calls[0][1]["stage"] == "cloakbrowser:pip_packages"
    assert "cloakbrowser==0.6.3" in calls[0][0]


def test_opencli_uses_pristine_compatible_release_without_install_hooks(monkeypatch, tmp_path):
    from agent_reach.runtime import tools
    calls=[]
    monkeypatch.setattr(tools,"_npm_cmd",lambda:"npm")
    monkeypatch.setattr(tools,"_run",lambda argv,**kwargs:calls.append(argv) or "")
    tools._install_npm(tools.TOOLS["opencli"],global_prefix=tmp_path/"npm")
    assert "--ignore-scripts" in calls[0]
    assert calls[0][-1]=="@jackwener/opencli@2.0.3"
    assert not tools.allowed(tools.TOOLS["opencli"],"1.8.8")


def test_install_uv_uses_hash_verified_wheel_without_remote_scripts(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, "tool_dir", lambda name: tmp_path / name)
    venv = tmp_path / "uv" / "venv"
    venv_bin = venv / ("Scripts" if tools._WIN else "bin")
    venv_bin.mkdir(parents=True)
    py = venv_bin / ("python.exe" if tools._WIN else "python")
    py.write_text("python", encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        # Simulate pip creating uv and uvx inside the private venv.
        for cmd in ("uv", "uvx"):
            (venv_bin / tools._exe(cmd)).write_text("bin", encoding="utf-8")
        if "-r" in argv:
            req_text = Path(argv[argv.index("-r") + 1]).read_text(encoding="utf-8")
            assert f"uv=={tools._UV_VERSION}" in req_text
            assert "--hash=sha256:" in req_text
        return ""

    monkeypatch.setattr(tools, "_run", fake_run)
    tools._install_uv(tools.TOOLS["uv"])

    assert len(calls) == 1
    argv = calls[0][0]
    joined = " ".join(argv).lower()
    assert "irm" not in joined and "iex" not in joined and "astral.sh" not in joined
    assert "--only-binary" in argv and "--require-hashes" in argv
    assert tools._private_bin(tools.TOOLS["uv"], "uv").is_file()
    assert tools._private_bin(tools.TOOLS["uv"], "uvx").is_file()


def test_npm_ignore_scripts_applies_to_all_packages(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(tools, "_npm_cmd", lambda: "npm")
    monkeypatch.setattr(tools, "_run", lambda argv, **kwargs: calls.append(argv) or "")
    other_npm = tools.Tool("mcporter", "npm", "mcporter", ("mcporter",))
    tools._install_npm(other_npm, global_prefix=tmp_path / "npm")
    assert "--ignore-scripts" in calls[0]


def test_boss_agent_cli_pip_install_pins_sha256(monkeypatch, tmp_path):
    tool = tools.TOOLS["boss-agent-cli"]
    monkeypatch.setattr(tools, "tool_dir", lambda name: tmp_path / name)
    py = tmp_path / tool.name / "venv" / ("Scripts/python.exe" if tools._WIN else "bin/python")
    py.parent.mkdir(parents=True)
    py.write_text("py", encoding="utf-8")
    calls = []
    monkeypatch.setattr(tools, "_run", lambda argv, **kwargs: calls.append(argv) or "")
    tools._install_pip(tool)
    assert any(f"#sha256={tools.BOSS_ARCHIVE_SHA256}" in arg for arg in calls[0])


def test_safe_extract_rejects_zip_slip_and_tar_slip(tmp_path):
    import io
    import tarfile
    import zipfile

    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../escape.txt", "x")
    with pytest.raises(ReachError, match="unsafe path"):
        tools._safe_extract_zip(bad_zip, tmp_path / "zout")

    bad_tar = tmp_path / "bad.tar.gz"
    with tarfile.open(bad_tar, "w:gz") as tf:
        info = tarfile.TarInfo("../escape.txt")
        data = b"x"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(Exception):
        tools._safe_extract_tar(bad_tar, tmp_path / "tout")
