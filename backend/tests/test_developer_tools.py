import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_documentation_checker_detects_a_broken_local_link(tmp_path):
    checker = load('lantern_docs', 'check_docs.py')
    (tmp_path / 'README.md').write_text('[broken](missing.md)\n')
    (tmp_path / 'AGENTS.md').write_text('Instructions\n')
    errors, _ = checker.check(tmp_path)
    assert any('missing.md' in error for error in errors)
    (tmp_path / 'missing.md').write_text('Resolved\n')
    assert checker.check(tmp_path)[0] == []


def test_skill_installation_is_idempotent_and_preserves_unrelated_skills(tmp_path):
    installer = load('lantern_skills', 'install-project-skills.py')
    target = tmp_path / 'skills'
    installer.install(target)
    installer.install(target)
    for name in installer.NAMES:
        assert (target / name).is_symlink()
        assert (target / name / 'SKILL.md').is_file()
    collision = tmp_path / 'collision'
    protected = collision / installer.NAMES[0]
    protected.mkdir(parents=True)
    (protected / 'mine.txt').write_text('user-owned skill')
    with pytest.raises(SystemExit):
        installer.install(collision)
    assert (protected / 'mine.txt').read_text() == 'user-owned skill'
    assert not (collision / installer.NAMES[1]).exists()


def test_lab_preserves_retained_database_when_matching_keys_are_missing(tmp_path,monkeypatch):
    from types import SimpleNamespace
    lab=load('suro_lab','lab.py')
    monkeypatch.setattr(lab,'DATA',tmp_path/'data');monkeypatch.setattr(lab,'ENV',tmp_path/'lab.env')
    monkeypatch.setattr(lab.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout='lantern-lab_postgres_data\n'))
    with pytest.raises(SystemExit,match='Retained lab database'):
        lab.prepare()
    assert not lab.ENV.exists() and not lab.DATA.exists()


def test_lab_requires_storage_check_before_generating_keys(tmp_path,monkeypatch):
    from types import SimpleNamespace
    lab=load('suro_lab_offline','lab.py')
    monkeypatch.setattr(lab,'DATA',tmp_path/'data');monkeypatch.setattr(lab,'ENV',tmp_path/'lab.env')
    monkeypatch.setattr(lab.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout=''))
    with pytest.raises(SystemExit,match='Cannot inspect retained lab storage'):
        lab.prepare()
    assert not lab.ENV.exists() and not lab.DATA.exists()
