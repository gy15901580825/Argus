import ast
from pathlib import Path


def test_testbed_package_imports_no_http_client():
    forbidden={'httpx','requests','aiohttp','urllib.request'}
    for path in (Path(__file__).resolve().parents[1]/'testbed').glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node,ast.Import):assert all(alias.name not in forbidden for alias in node.names)
            if isinstance(node,ast.ImportFrom):assert node.module not in forbidden and node.module!='argus'
