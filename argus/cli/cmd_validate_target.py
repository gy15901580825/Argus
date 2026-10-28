"""argus-probe validate-target — quick reachability check on a target endpoint."""

from pathlib import Path

import click
import httpx
import yaml


@click.command()
@click.option("--target", "target_file", type=click.Path(exists=True), required=True)
def cmd_validate_target(target_file: str):
    """POST a tiny chat-completions probe to the target and report reachability + shape compliance."""
    spec = yaml.safe_load(Path(target_file).read_text())
    url = spec["endpoint_url"]
    headers = {}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    body = {"model": spec["model"], "messages": [{"role": "user", "content": "ping"}], "max_tokens": 10}
    try:
        resp = httpx.post(url, headers=headers, json=body, timeout=15.0)
    except httpx.RequestError as e:
        raise click.ClickException(f"network error: {e}")
    if resp.status_code != 200:
        raise click.ClickException(f"target returned {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as e:
        raise click.ClickException(f"target response shape invalid: {e}")
    click.echo(f"OK — target {url} replied with {len(text)} chars")
