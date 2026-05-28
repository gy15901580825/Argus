import httpx
from bs4 import BeautifulSoup
import json
import logging
from urllib.parse import urljoin, urlparse

from ai_crawler import crawl_for_apis
import asyncio

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def _probe_openapi(client: httpx.AsyncClient, base_url: str, extracted_links: list[str]) -> dict | None:
    """
    Attempt to discover and fetch OpenAPI/Swagger specification.
    """
    common_paths = [
        "/v2/swagger.json",
        "/v3/api-docs",
        "/api/docs",
        "/swagger/v1/swagger.json",
        "/openapi.json",
        "/api/v3/openapi.json",
        "/swagger.json"
    ]
    
    candidate_urls = []
    
    # Check extracted links for API spec patterns
    for link in extracted_links:
        path = urlparse(link).path
        if path.endswith(('.json', '.yaml', '.yml')) and ('swagger' in path or 'api' in path or 'openapi' in path):
            candidate_urls.append(link)
            
    # Add common paths
    for path in common_paths:
        candidate_urls.append(urljoin(base_url, path))
        
    candidate_urls = list(set(candidate_urls))
    
    # Try fetching each candidate URL
    for url in candidate_urls:
        try:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "openapi" in data or "swagger" in data:
                        return {"url": url, "spec": data}
                except json.JSONDecodeError:
                    continue
        except Exception:
            continue
            
    return None

async def fetch_internal_page_impl(url: str, cookie: str = None, token: str = None) -> str:
    """
    Fetch and analyze web page structure.
    
    Returns JSON containing:
    - text: page text content
    - links: all links
    - scripts: all script URLs
    - api_spec: discovered OpenAPI/Swagger spec (if any)
    - metadata: title and other metadata
    """
    headers = {
        "User-Agent": "MCP-Agent/1.0"
    }

    if cookie:
        headers["Cookie"] = cookie

    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    result = {
        "text": "",
        "links": [],
        "scripts": [],
        "api_spec": None,
        "crawled_apis": [],
        "metadata": {}
    }

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            result["metadata"]["status_code"] = response.status_code
            result["metadata"]["url"] = str(response.url)
            
            if response.status_code >= 400:
                return json.dumps(result, ensure_ascii=False)

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract metadata
            if soup.title:
                result["metadata"]["title"] = soup.title.string
            
            # Extract links
            links = set()
            for a in soup.find_all('a', href=True):
                full_url = urljoin(str(response.url), a['href'])
                links.add(full_url)
            result["links"] = list(links)
            
            # Extract scripts
            scripts = set()
            for script in soup.find_all('script', src=True):
                full_url = urljoin(str(response.url), script['src'])
                scripts.add(full_url)
            result["scripts"] = list(scripts)
            
            # Clean text content
            for tag in soup(["script", "style"]):
                tag.decompose()
            
            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            result["text"] = '\n'.join(chunk for chunk in chunks if chunk)
            
            # Probe for OpenAPI spec
            try:
                data = response.json()
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    result["api_spec"] = {"url": str(response.url), "spec": data}
                    result["text"] = "Fetched content is a JSON API Specification."
            except json.JSONDecodeError:
                spec_found = await _probe_openapi(client, str(response.url), result["links"])
                if spec_found:
                    result["api_spec"] = spec_found
                else:
                    # Fallback: AI Crawler
                    # Run in thread because playwright sync API is blocking
                    try:
                        crawled_data = await asyncio.to_thread(crawl_for_apis, str(response.url), max_steps=30, max_depth=5)
                        result["crawled_apis"] = crawled_data
                        if crawled_data:
                            result["text"] += f"\n\n[AI Crawler Discovered {len(crawled_data)} APIs]"
                    except Exception as e:
                        result["error_crawler"] = str(e)

        except Exception as e:
            result["error"] = str(e)
    
    # Log the detailed return result
    logger.info("=" * 60)
    logger.info(f"FETCH RESULT for: {url}")
    logger.info("=" * 60)
    logger.info(f"  Status: {result.get('metadata', {}).get('status_code', 'N/A')}")
    logger.info(f"  Title: {result.get('metadata', {}).get('title', 'N/A')}")
    logger.info(f"  Links found: {len(result.get('links', []))}")
    logger.info(f"  Scripts found: {len(result.get('scripts', []))}")
    logger.info(f"  API Spec found: {'Yes' if result.get('api_spec') else 'No'}")
    
    crawled_apis = result.get('crawled_apis', [])
    logger.info(f"  Crawled APIs: {len(crawled_apis)}")
    
    if crawled_apis:
        logger.info("\n API List:")
        for i, api in enumerate(crawled_apis, 1):
            method = api.get('method', '?')
            endpoint = api.get('endpoint', '?')
            domain = api.get('domain', '?')
            status = api.get('status', '?')
            logger.info(f"    {i}. [{method}] {domain}{endpoint} -> {status}")
    
    logger.info("=" * 60)
            
    return json.dumps(result, ensure_ascii=False, indent=2)
