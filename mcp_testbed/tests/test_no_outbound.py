"""testbed 包不得具备出网能力。

一个真能连出去的 MCP testbed 就是一个真能被滥用的 MCP 代理。这条
约束靠人自觉守不住 —— 某次调试临时 import 一下 httpx 就破了,而且
没有任何测试会因此变红。所以这里有一条。
"""
import pathlib, re

BANNED = re.compile(r"^\s*(?:import|from)\s+(httpx|requests|aiohttp|urllib|socket)\b", re.M)


def test_testbed_package_imports_no_outbound_client():
    for f in (pathlib.Path(__file__).resolve().parent.parent / "testbed").rglob("*.py"):
        hits = BANNED.findall(f.read_text())
        assert not hits, f"{f.name} imports an outbound client: {hits}"


TRAP_BANNED = re.compile(
    r"^\s*(?:import|from)\s+(httpx2?|requests|aiohttp|urllib|socket|smtplib|ftplib|http\.client|websockets|mcp\.client)\b"
    r"|^\s*from\s+mcp\s+import\s+.*\bClient\b", re.M)

def test_mcp_trap_server_package_imports_no_outbound_client():
    trap = pathlib.Path(__file__).resolve().parents[2] / "argus" / "mcp_trap" / "trap"
    assert trap.is_dir(), f"{trap} is missing; this guard cannot check what it cannot read"
    for f in trap.rglob("*.py"):
        hits = TRAP_BANNED.findall(f.read_text())
        assert not hits, f"{f.name} imports an outbound client: {hits}"


def test_mcp_scan_fixture_servers_import_no_outbound_client():
    fixtures = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "mcp_scan"
    files = list(fixtures.rglob("*.py"))
    assert files, f"{fixtures} has no servers; this guard cannot check what it cannot read"
    for f in files:
        hits = TRAP_BANNED.findall(f.read_text())
        assert not hits, f"{f.name} imports an outbound client: {hits}"


def test_gateway_fixture_package_imports_no_outbound_client():
    import ast

    fixtures = pathlib.Path(__file__).resolve().parents[2] / "argus" / "gateway_fixtures"
    files = list(fixtures.rglob("*.py"))
    assert files, f"{fixtures} is missing; this guard cannot check what it cannot read"
    assert fixtures.joinpath('foreign_oauth.py').is_file(), 'foreign OAuth handler is missing'
    forbidden = {"httpx", "httpx2", "requests", "socket", "smtplib", "ftplib", "websockets"}
    for path in files:
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for module in modules:
                assert module.split(".")[0] not in forbidden, f"{path.name}: {module}"
                assert not module.startswith(("http.client", "mcp.client")), f"{path.name}: {module}"
                assert not module.startswith("urllib") or module == "urllib.parse", f"{path.name}: {module}"
                assert not module.startswith("aiohttp") or module == "aiohttp.web", f"{path.name}: {module}"
            if isinstance(node, ast.ImportFrom) and node.module == "mcp":
                assert all("Client" not in alias.name for alias in node.names), path.name
