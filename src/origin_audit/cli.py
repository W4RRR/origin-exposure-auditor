"""Typer command-line interface."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from origin_audit import LEGAL_NOTICE, __version__
from origin_audit.config import AppConfig, load_config, load_environment, validate_config_file
from origin_audit.exceptions import OriginAuditError
from origin_audit.logging_config import configure_logging
from origin_audit.models import Target
from origin_audit.networking.external_httpx import find_projectdiscovery_httpx
from origin_audit.orchestrator import ScanOptions, ScanOrchestrator
from origin_audit.providers import provider_registry
from origin_audit.reporting import render_existing_report, write_reports
from origin_audit.scope import load_scope
from origin_audit.utils.domains import normalize_domain

app = typer.Typer(
    name="origin-audit",
    help=f"Defensive origin exposure assessment.\n\n{LEGAL_NOTICE}",
    no_args_is_help=True,
)
providers_app = typer.Typer(help="List providers and inspect local availability.")
config_app = typer.Typer(help="Validate application configuration.")
scope_app = typer.Typer(help="Validate authorization scope files.")
app.add_typer(providers_app, name="providers")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")


@dataclass
class Runtime:
    """Resolved global CLI settings."""

    config: AppConfig
    environment: dict[str, str]
    no_cache: bool
    non_interactive: bool


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _provider_data_path() -> Path:
    repository_data = Path(__file__).resolve().parents[2] / "data" / "providers.yml"
    if repository_data.exists():
        return repository_data
    return Path(__file__).resolve().parent / "data" / "providers.yml"


@app.callback()
def main(
    context: typer.Context,
    config_path: Annotated[
        Path | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    env_file: Annotated[
        Path | None, typer.Option("--env-file", exists=True, dir_okay=False)
    ] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    cache_dir: Annotated[Path | None, typer.Option("--cache-dir")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache")] = False,
    timeout: Annotated[float | None, typer.Option("--timeout", min=1, max=60)] = None,
    concurrency: Annotated[int | None, typer.Option("--concurrency", min=1, max=20)] = None,
    rate_limit: Annotated[float | None, typer.Option("--rate-limit", min=0.1, max=20)] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent")] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="DEBUG, INFO, WARNING, or ERROR")
    ] = "INFO",
    quiet: Annotated[bool, typer.Option("--quiet")] = False,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    json_logs: Annotated[bool, typer.Option("--json-logs")] = False,
    non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
) -> None:
    """Resolve global settings before executing a subcommand."""
    try:
        config = load_config(config_path)
    except OriginAuditError as exc:
        _fail(str(exc))
    if output_dir:
        config.output_dir = output_dir
    if cache_dir:
        config.cache_dir = cache_dir
    if timeout is not None:
        config.timeout_seconds = timeout
    if concurrency is not None:
        config.concurrency = concurrency
    if rate_limit is not None:
        config.rate_limit = rate_limit
    if user_agent is not None:
        config.user_agent = user_agent
    if verbose:
        log_level = "DEBUG"
    if log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        _fail("Invalid --log-level")
    configure_logging(log_level, json_logs=json_logs, quiet=quiet)
    context.obj = Runtime(
        config=config,
        environment=load_environment(env_file),
        no_cache=no_cache,
        non_interactive=non_interactive,
    )


@app.command()
def scan(
    context: typer.Context,
    domain: Annotated[str, typer.Argument(help="Authorized domain or HTTP(S) URL")],
    providers: Annotated[
        str, typer.Option("--providers", help="Comma-separated provider names or all")
    ] = "all",
    formats: Annotated[
        str, typer.Option("--format", help="json,csv,markdown,html")
    ] = "json,csv,markdown,html",
    scan_output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    passive_only: Annotated[bool, typer.Option("--passive-only")] = False,
    active_validate: Annotated[bool, typer.Option("--active-validate")] = False,
    authorized_scope: Annotated[
        Path | None, typer.Option("--authorized-scope", exists=True, dir_okay=False)
    ] = None,
    authorized_ack: Annotated[bool, typer.Option("--i-understand-and-am-authorized")] = False,
    include_non_public: Annotated[bool, typer.Option("--include-non-public")] = False,
    legacy_ip_list: Annotated[bool, typer.Option("--legacy-ip-list")] = False,
    save_raw_responses: Annotated[bool, typer.Option("--save-raw-responses")] = False,
    use_projectdiscovery_httpx: Annotated[
        bool, typer.Option("--use-projectdiscovery-httpx")
    ] = False,
    submit_urlscan: Annotated[bool, typer.Option("--submit-urlscan")] = False,
    urlscan_visibility: Annotated[
        str, typer.Option("--urlscan-visibility", help="public, unlisted, or private")
    ] = "unlisted",
    accept_urlscan_privacy_risk: Annotated[
        bool, typer.Option("--accept-urlscan-privacy-risk")
    ] = False,
) -> None:
    """Collect passive evidence and optionally perform scope-gated validation."""
    runtime: Runtime = context.obj
    try:
        normalized = normalize_domain(domain)
    except OriginAuditError as exc:
        _fail(str(exc))
    if passive_only and active_validate:
        _fail("--passive-only and --active-validate are mutually exclusive")
    scope = None
    if active_validate:
        if not authorized_scope or not authorized_ack:
            _fail(
                "Active validation requires --authorized-scope and --i-understand-and-am-authorized"
            )
        try:
            scope = load_scope(authorized_scope)
            if not scope.allow_active_validation or not scope.domain_is_authorized(normalized):
                _fail("The scope file does not authorize active validation for this domain")
        except OriginAuditError as exc:
            _fail(str(exc))
    elif authorized_scope or authorized_ack:
        _fail("Scope and authorization flags require --active-validate")
    if submit_urlscan:
        if urlscan_visibility not in {"public", "unlisted", "private"}:
            _fail("Invalid --urlscan-visibility")
        warning = (
            "Submitting to urlscan.io discloses the target to a third party; visibility "
            f"will be {urlscan_visibility}."
        )
        typer.secho(f"Privacy warning: {warning}", fg=typer.colors.YELLOW, err=True)
        if runtime.non_interactive and not accept_urlscan_privacy_risk:
            _fail("--submit-urlscan in non-interactive mode requires --accept-urlscan-privacy-risk")
        if (
            not runtime.non_interactive
            and not accept_urlscan_privacy_risk
            and not typer.confirm("Submit exactly one URL to urlscan.io?")
        ):
            _fail("URLScan submission was not accepted")
    selected = {item.strip().lower() for item in providers.split(",") if item.strip()}
    requested_formats = {
        "markdown" if item.strip().lower() == "md" else item.strip().lower()
        for item in formats.split(",")
        if item.strip()
    }
    options = ScanOptions(
        providers=selected,
        formats=requested_formats,
        output_dir=scan_output_dir or runtime.config.output_dir,
        include_non_public=include_non_public,
        active_validate=active_validate,
        authorization_acknowledged=authorized_ack,
        scope=scope,
        scope_file=authorized_scope,
        no_cache=runtime.no_cache,
        save_raw_responses=save_raw_responses,
        submit_urlscan=submit_urlscan,
        urlscan_visibility=urlscan_visibility,
        use_projectdiscovery_httpx=use_projectdiscovery_httpx,
        command_summary=(
            f"origin-audit scan {normalized} --providers {providers} --format {formats}"
            + (" --active-validate" if active_validate else " --passive-only")
        ),
    )
    orchestrator = ScanOrchestrator(
        runtime.config,
        runtime.environment,
        provider_data_path=_provider_data_path(),
    )
    try:
        outcome = asyncio.run(orchestrator.scan(Target(domain=normalized), options))
        written = write_reports(
            outcome.directory,
            outcome.report,
            requested_formats,
            legacy_ip_list=legacy_ip_list,
            legacy_path=Path(f"{normalized}_ips.txt") if legacy_ip_list else None,
        )
    except (OriginAuditError, ValueError, OSError) as exc:
        _fail(str(exc), code=1)
    typer.echo(f"Assessment complete: {outcome.directory}")
    typer.echo(f"Candidates retained: {len(outcome.report.candidates)}")
    for result in outcome.report.providers:
        message = f": {result.message}" if result.message else ""
        typer.echo(f"[{str(result.state).upper()}] {result.provider}{message}")
    typer.echo(f"Files written: {len(written) + 1} (including audit.log)")


@providers_app.command("list")
def providers_list() -> None:
    """List built-in providers."""
    for name in provider_registry():
        typer.echo(name)


@providers_app.command("status")
def providers_status(context: typer.Context) -> None:
    """Show credentials and optional local-tool status without revealing secrets."""
    runtime: Runtime = context.obj
    for name, provider in provider_registry().items():
        required = provider.required_environment
        configured = all(runtime.environment.get(item) for item in required)
        requirement = ",".join(required) if required else "none"
        typer.echo(
            f"{name:20} {'configured' if configured or not required else 'missing':10} "
            f"credential={requirement}"
        )
    path = shutil.which("wafw00f")
    typer.echo(f"{'wafw00f':20} {'installed' if path else 'not installed'}")
    projectdiscovery = find_projectdiscovery_httpx()
    typer.echo(
        f"{'projectdiscovery-httpx':20} {'installed' if projectdiscovery else 'not installed'}"
    )


@config_app.command("validate")
def config_validate(
    context: typer.Context,
    path: Annotated[Path | None, typer.Argument(exists=True, dir_okay=False)] = None,
) -> None:
    """Validate a YAML configuration or the already loaded settings."""
    try:
        config = validate_config_file(path) if path else context.obj.config
    except OriginAuditError as exc:
        _fail(str(exc))
    typer.echo(f"Configuration is valid (concurrency={config.concurrency})")


@scope_app.command("validate")
def scope_validate(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Validate an authorization scope file."""
    try:
        scope = load_scope(path)
    except OriginAuditError as exc:
        _fail(str(exc))
    typer.echo(
        f"Scope is valid (active={scope.allow_active_validation}, "
        f"domains={len(scope.authorized_domains)}, networks={len(scope.authorized_ips)})"
    )


@app.command("report")
def report_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    formats: Annotated[str, typer.Option("--format")] = "markdown,html",
) -> None:
    """Re-render an existing report.json."""
    requested = {
        "markdown" if item.strip().lower() == "md" else item.strip().lower()
        for item in formats.split(",")
        if item.strip()
    }
    try:
        written = render_existing_report(path, requested)
    except (OSError, ValueError) as exc:
        _fail(str(exc), code=1)
    typer.echo(f"Rendered {len(written)} files beside {path}")


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)
