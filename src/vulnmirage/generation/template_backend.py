"""Jinja2 template backend with strict, minimal context binding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from ..errors import GenerationError
from ..paths import safe_join


class TemplateBackend:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.environment = Environment(
            loader=FileSystemLoader(str(self.base_dir)),
            undefined=StrictUndefined,
            autoescape=False,
            keep_trailing_newline=True,
            trim_blocks=False,
            lstrip_blocks=False,
        )

    def render(self, template_file: str, context: dict[str, Any]) -> str:
        safe_join(self.base_dir, template_file)
        try:
            template = self.environment.get_template(template_file)
            return template.render(**context)
        except TemplateError as exc:
            raise GenerationError(
                f"template rendering failed: {exc}",
                details={"template": template_file},
            ) from exc

    def render_string(self, source: str, context: dict[str, Any]) -> str:
        try:
            return self.environment.from_string(source).render(**context)
        except TemplateError as exc:
            raise GenerationError(f"template rendering failed: {exc}") from exc
