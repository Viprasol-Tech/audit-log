"""Command-line interface for Audit Log.

``audit-log demo`` builds a small hash-chained log, prints the chain, then
simulates tampering with a middle entry and shows that verification catches it
— all offline, no external services.

Part of Audit Log by Viprasol Tech Private Limited (https://viprasol.com).
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from audit_log import __version__
from audit_log.log import AuditLog, Entry
from audit_log.verify import verify_chain

app = typer.Typer(add_completion=False, help="Audit Log — by Viprasol Tech.")
console = Console()


def _short(value: str, width: int = 12) -> str:
    """Abbreviate a long hex hash for compact display."""
    return value if len(value) <= width else f"{value[:width]}..."


def _print_chain(entries: tuple[Entry, ...]) -> None:
    """Render the chain as a table of entries with truncated hashes."""
    table = Table(title="Audit chain", show_lines=False)
    table.add_column("idx", justify="right", style="cyan")
    table.add_column("actor")
    table.add_column("action")
    table.add_column("target")
    table.add_column("prev_hash", style="dim")
    table.add_column("hash", style="green")
    for entry in entries:
        table.add_row(
            str(entry.index),
            entry.actor,
            entry.action,
            entry.target,
            _short(entry.prev_hash),
            _short(entry.hash),
        )
    console.print(table)


@app.command()
def version() -> None:
    """Print the installed version."""
    console.print(f"audit-log [bold cyan]{__version__}[/] - by Viprasol Tech")


@app.command()
def demo() -> None:
    """Build a chain, print it, tamper with it, and detect the tampering."""
    log = AuditLog()
    log.append("alice", "login", "console", {"ip": "10.0.0.1"})
    log.append("alice", "create", "record:42", {"fields": 3})
    log.append("bob", "update", "record:42", {"amount": 100})
    log.append("bob", "delete", "record:42", {"reason": "cleanup"})

    console.print(f"Appended [bold]{len(log)}[/] entries (head {_short(log.head)}).\n")
    entries = log.entries
    _print_chain(entries)

    intact = verify_chain(entries)
    console.print(f"\nVerify intact chain: [bold green]ok={intact.ok}[/]")

    # Simulate tampering: forge a new entry 2 with an altered amount, keeping
    # its (now stale) prev_hash. The store is append-only, so we rebuild the
    # sequence the way an attacker editing persisted records would.
    forged = entries[2].model_copy(update={"metadata": {"amount": 999_999}})
    tampered = (*entries[:2], forged, *entries[3:])

    result = verify_chain(tampered)
    console.print(
        "Verify tampered chain: "
        f"[bold red]ok={result.ok}[/] "
        f"first_tampered_index=[bold]{result.first_tampered_index}[/]"
    )
    console.print(f"Reason: [yellow]{result.reason}[/]")

    if result.first_tampered_index == 2:
        console.print("\n[bold green]Tampering detected at the expected index.[/]")
    else:  # pragma: no cover - defensive
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
