from pathlib import Path

import jinja2
import pytest

TEMPLATES = Path(__file__).parent.parent / "app" / "templates"


@pytest.mark.parametrize("name", sorted(p.name for p in TEMPLATES.glob("*.html")))
def test_template_compiles(name):
    jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES)).get_template(name)
