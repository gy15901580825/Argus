"""argus-probe web-login: log in to a chat page by hand and save the session for a web_chat target."""
from __future__ import annotations

import json
import os
import sys

import click

_INSTALL_HINT = "web-login needs Playwright: pip install 'argus-probe[web]' && playwright install chromium"


@click.command("web-login")
@click.argument("url")
@click.option("--out", "out", required=True, type=click.Path(dir_okay=False),
              help="Where to write the Playwright storage_state JSON (the web_chat storage_state field)")
@click.option("--force", is_flag=True, help="Overwrite --out if it exists")
def cmd_web_login(url: str, out: str, force: bool) -> None:
    """Open URL in a visible Chromium, wait while you log in, then save the session cookies to --out."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        click.echo(_INSTALL_HINT, err=True)
        sys.exit(2)
    # Checked before the browser opens, so nobody logs in only to have the save refused.
    if os.path.lexists(out) and not force:
        raise click.ClickException(f"{out} exists; pass --force to overwrite it")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url)
            click.prompt("Log in in the browser window, then press Enter here",
                         default="", show_default=False, prompt_suffix=" ")
            state = context.storage_state()
            browser.close()
    except PlaywrightError as e:
        first = (str(e).strip().splitlines() or [type(e).__name__])[0]
        raise click.ClickException(
            f"browser step failed: {first}. If Chromium is missing, run `playwright install chromium`")

    if force and os.path.lexists(out):
        # O_CREAT keeps an existing file's mode, so remove it to get a fresh 0600 file.
        os.unlink(out)
    try:
        # Created 0600 in one step, so the cookies are never readable by other users.
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise click.ClickException(f"{out} appeared while you were logging in; pass --force to overwrite it")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    click.echo(f"Saved the browser session to {out}. Point the web_chat target's storage_state at it.")
    click.echo(f"Warning: {out} holds session cookies for {url}. Anyone with the file can use the session. "
               "Do not commit it.", err=True)
