import os

import pytest

from app import config, sources


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "home"
    cluster = root / "kubertinus"
    (cluster / "patch").mkdir(parents=True)
    (cluster / "_out").mkdir()
    (cluster / ".git").mkdir()
    (cluster / "_out" / "controlplane.yaml").write_text("version: v1alpha1\n")
    (cluster / "patch" / "a.yaml").write_text("machine: {}\n")
    (cluster / ".git" / "HEAD").write_text("x")
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_text("private")
    (root / "other").mkdir()
    (tmp_path / "outside.yaml").write_text("secret")
    (cluster / "escape.yaml").symlink_to(tmp_path / "outside.yaml")
    (cluster / "ssh").symlink_to(root / ".ssh")
    monkeypatch.setattr(config, "CONFIG_DIR", root)
    state = {"base_dir": "kubertinus"}
    monkeypatch.setattr(sources, "base_dir", lambda cid: state["base_dir"])
    return state


def test_list_files_skips_hidden_and_escapes(home):
    files = sources.list_files("c1")
    assert "_out/controlplane.yaml" in files and "patch/a.yaml" in files
    assert not any(f.startswith(".git") or f.startswith("ssh") for f in files)
    assert "escape.yaml" not in files


def test_read_inside_base(home):
    assert sources.read("c1", "patch/a.yaml") == b"machine: {}\n"


@pytest.mark.parametrize(
    "rel", ["../outside.yaml", "escape.yaml", "/etc/passwd", "patch", "nope.yaml", "../.ssh/id_ed25519", "ssh/id_ed25519", "../other"]
)
def test_read_refuses_escape_hidden_and_missing(home, rel):
    with pytest.raises(sources.SourceError):
        sources.read("c1", rel)


def test_no_base_means_nothing(home):
    home["base_dir"] = ""
    assert sources.list_files("c1") == []
    with pytest.raises(sources.SourceError):
        sources.read("c1", "_out/controlplane.yaml")


def test_list_dirs(home):
    top = sources.list_dirs("")
    assert [d["name"] for d in top["dirs"]] == ["kubertinus", "other"]
    assert top["parent"] is None
    assert next(d for d in top["dirs"] if d["name"] == "kubertinus")["talos"]
    sub = sources.list_dirs("kubertinus")
    assert sub["parent"] == "" and {d["name"] for d in sub["dirs"]} == {"_out", "patch"}
    for bad in ("../", ".ssh", "kubertinus/ssh"):
        with pytest.raises(sources.SourceError):
            sources.list_dirs(bad)


def test_mount_root_as_base(home):
    home["base_dir"] = "."
    files = sources.list_files("c1")
    assert "kubertinus/patch/a.yaml" in files
    assert not any(f.startswith(".ssh") or "/.git" in f for f in files)
    assert sources.read("c1", "kubertinus/patch/a.yaml") == b"machine: {}\n"
    with pytest.raises(sources.SourceError):
        sources.read("c1", ".ssh/id_ed25519")


def test_unreadable_file_gives_clear_error(home, tmp_path):
    f = tmp_path / "home" / "kubertinus" / "patch" / "a.yaml"
    f.chmod(0)
    try:
        if os.access(f, os.R_OK):
            pytest.skip("running as root")
        with pytest.raises(sources.SourceError, match="not readable"):
            sources.read("c1", "patch/a.yaml")
    finally:
        f.chmod(0o644)


def test_write_rewrites_in_place_and_creates_new(home, tmp_path):
    f = tmp_path / "home" / "kubertinus" / "patch" / "a.yaml"
    f.chmod(0o640)
    inode = f.stat().st_ino
    sources.write("c1", "patch/a.yaml", b"machine: {x: 1}\n")
    assert f.read_bytes() == b"machine: {x: 1}\n"
    assert f.stat().st_ino == inode and f.stat().st_mode & 0o777 == 0o640
    sources.write("c1", "patch/new/b.yaml", b"machine: {}\n")
    assert (tmp_path / "home" / "kubertinus" / "patch" / "new" / "b.yaml").read_bytes() == b"machine: {}\n"


@pytest.mark.parametrize("rel", ["../outside.yaml", "escape.yaml", "../.ssh/x.yaml", "ssh/x.yaml", ".git/x.yaml", "patch", "."])
def test_write_refuses_escape_and_hidden(home, tmp_path, rel):
    with pytest.raises(sources.SourceError):
        sources.write("c1", rel, b"x: 1\n")
    assert (tmp_path / "outside.yaml").read_text() == "secret"


def test_check_new_file(home):
    sources.check_new_file("c1", "patch/new.yaml")
    for bad in ("patch/a.yaml", "patch/new.txt", "../x.yaml", ".hidden/x.yaml"):
        with pytest.raises(sources.SourceError):
            sources.check_new_file("c1", bad)


def test_delete_file_only_inside_base(home, tmp_path):
    f = tmp_path / "home" / "kubertinus" / "patch" / "a.yaml"
    sources.delete_file("c1", "patch/a.yaml")
    assert not f.exists()
    for bad in ("escape.yaml", "../outside.yaml", "ssh/id_ed25519", "patch/a.yaml"):
        with pytest.raises(sources.SourceError):
            sources.delete_file("c1", bad)
    assert (tmp_path / "outside.yaml").exists() and (tmp_path / "home" / ".ssh" / "id_ed25519").exists()
