import os
import time
import json
import logging
import hashlib
from urllib.parse import urlparse
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright
import google.generativeai as genai

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load env
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

if not GOOGLE_API_KEY:
    logger.error("GOOGLE_API_KEY not found in .env")
    # We don't exit here to allow import, but methods might fail if called.

else:
    genai.configure(api_key=GOOGLE_API_KEY)

# --- Configuration ---
# Defaults
DEFAULT_MODEL_SMART_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-3-pro-preview")
DEFAULT_MODEL_FAST_NAME = os.getenv("GEMINI_MODEL_FLASH_NAME", "gemini-2.5-flash")


class BrowserManager:
    def __init__(self, target_url: str, allowed_domains: list[str], max_depth: int = 3):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.captured_apis = []
        self._seen_apis = set()
        
        # Depth Tracking
        self.start_url = target_url
        self.max_depth = max_depth
        self.allowed_domains = allowed_domains
        
        # Auto-discover related domains (e.g., API subdomains)
        # This will be populated as we discover API calls to related domains
        self.discovered_domains = set(allowed_domains)
        
        # Extract base domain for intelligent subdomain matching
        # e.g., "www.primary.health" -> "primary.health"
        self.base_domain = self._extract_base_domain(target_url)
        
        self.url_depths = {target_url: 0} # URL -> Depth
        self.current_depth = 0
    
    def _extract_base_domain(self, url: str) -> str:
        """
        Extract base domain from URL.
        e.g., "https://www.primary.health/" -> "primary.health"
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Simple heuristic: remove common prefixes
        for prefix in ['www.', 'app.', 'api.', 'my.', 'portal.', 'signin.']:
            if domain.startswith(prefix):
                return domain[len(prefix):]
        
        return domain
    
    def _is_related_domain(self, domain: str) -> bool:
        """
        Check if a domain is related to the target domain.
        Returns True if:
        1. Domain is in allowed_domains
        2. Domain is in discovered_domains
        3. Domain shares the same base domain (e.g., my.primary.health and www.primary.health)
        """
        if domain in self.allowed_domains or domain in self.discovered_domains:
            return True
        
        # Check if it's a subdomain of the base domain
        if self.base_domain and domain.endswith(self.base_domain):
            logger.info(f"Discovered related domain: {domain} (base: {self.base_domain})")
            self.discovered_domains.add(domain)
            return True
        
        return False

    def start(self):
        self.playwright = sync_playwright().start()
        # Headless=False for visibility during dev, but maybe True for production service?
        # Keeping False as per original but it might be better configurable.
        # For a service, we probably want headless=True by default or configurable.
        # Let's make it True for broader compatibility unless debugging.
        # Actually user might want to see it. Let's keep it False for now as per original
        # but consider making it an option.
        self.browser = self.playwright.chromium.launch(headless=True) # Changed to True for service usage
        self.context = self.browser.new_context(
            viewport={'width': 1280, 'height': 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        self.context.on("response", self._handle_response)
        self.context.on("page", self._on_page) # Monitor new pages
        self.page = self.context.new_page()
        self._update_depth() # Init

    def _on_page(self, page):
        self.page = page
        self._update_depth()

    def _update_depth(self):
        """Calculates depth based on URL history logic"""
        if not self.page: return
        
        current_url = self.page.url
        
        if current_url in self.url_depths:
            self.current_depth = self.url_depths[current_url]
        else:
            # We assume we came from the self.current_depth page
            new_depth = self.current_depth + 1
            self.url_depths[current_url] = new_depth
            self.current_depth = new_depth
        
        logger.info(f"Current Depth: {self.current_depth} (URL: {current_url})")

    def stop(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def _handle_response(self, response):
        try:
            request = response.request
            url = request.url
            resource_type = request.resource_type
            content_type = response.headers.get('content-type', '').lower()

            # Filter irrelevant resources by type
            if resource_type in ['image', 'stylesheet', 'font', 'media', 'manifest', 'other', 'script']:
                logger.debug(f"Ignored resource type: {resource_type} ({url})")
                return
            parsed = urlparse(url)
            
            # Filter static file extensions (removed .js since we filter by resource_type)
            # Filter static file extensions
            static_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.webp', '.mp4', '.mp3', '.pdf', '.js', '.mjs')
            if parsed.path.endswith(static_extensions):
                logger.debug(f"Ignored static extension: {url}")
                return

            # Filter infrastructure / well-known prefixes that are not application APIs:
            # Cloudflare internal (/cdn-cgi/*), RFC 8615 well-known URIs, analytics beacons, etc.
            # These return 200/204/404 regardless of auth and pollute security test generation.
            infra_prefixes = ('/cdn-cgi/', '/.well-known/', '/__cf_', '/beacon', '/pixel', '/collect', '/track')
            path_lower = parsed.path.lower()
            if any(path_lower.startswith(p) for p in infra_prefixes):
                logger.debug(f"Ignored infrastructure path: {url}")
                return
            
            # Enhanced API detection
            # 1. Check content-type (expanded to include more API response types)
            is_data = any(t in content_type for t in ['json', 'xml', 'text/plain', 'application/octet-stream'])
            
            # 2. Check request type
            is_xhr = resource_type in ['xhr', 'fetch']
            
            # 3. Check URL path patterns for common API endpoints
            api_path_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/rpc/', '/services/']
            is_api_path = any(pattern in parsed.path.lower() for pattern in api_path_patterns)
            
            # 4. Check if subdomain indicates API (e.g., api.example.com, my.example.com)
            api_subdomain_prefixes = ['api.', 'my.', 'gateway.', 'backend.', 'services.', 'signin.', 'auth.', 'login.', 'id.']
            is_api_subdomain = any(parsed.netloc.startswith(prefix) for prefix in api_subdomain_prefixes)
            
            # Additional check: Exclude document navigations unless they return data OR are explicit APIs/Auth flows
            if resource_type == 'document' and not (is_data or is_api_path or is_api_subdomain):
                logger.info(f"Ignored document nav (not API/Auth): {url}")
                return
            
            # Accept if any API indicator is present
            if not (is_data or is_xhr or is_api_path or is_api_subdomain):
                logger.debug(f"Ignored non-API request: {url} [Type: {resource_type}, CT: {content_type}]")
                return

            # Auto-discover related domains from API calls
            # This allows capturing APIs from subdomains like my.primary.health
            if parsed.netloc and not self._is_related_domain(parsed.netloc):
                logger.info(f"Skipping API from unrelated domain: {parsed.netloc}")
                return

            # Use full URL as key to avoid conflicts between different domains
            # e.g., www.primary.health/api/users vs my.primary.health/api/users
            # For GraphQL: include payload hash to distinguish different queries to same endpoint
            key = (request.method, url)
            if request.post_data and '/graphql' in url.lower():
                payload_hash = hashlib.md5(request.post_data.encode()).hexdigest()[:8]
                key = (request.method, url, payload_hash)
            if key not in self._seen_apis:
                self._seen_apis.add(key)
                
                # Capture payload
                payload = None
                if request.post_data:
                    try:
                        payload = json.loads(request.post_data)
                    except:
                        payload = request.post_data

                # Construct base URL for this API
                base_url = f"{parsed.scheme}://{parsed.netloc}"

                api_info = {
                    "method": request.method,
                    "endpoint": parsed.path,  # Keep path for backward compatibility
                    "full_url": url,  # NEW: Store complete URL
                    "base_url": base_url,  # NEW: Store base URL for pytest
                    "domain": parsed.netloc,  # NEW: Store domain
                    "query": parsed.query if parsed.query else None,  # NEW: Store query params
                    "payload": payload,
                    "status": response.status
                }
                self.captured_apis.append(api_info)
                logger.info(f"Captured API: {request.method} {url}")

        except Exception as e:
            pass

    def get_page_state(self):
        """
        Distills the page using Playwright's Accessibility Tree.
        """
        self._update_depth()
        
        try:
            # Try accessibility snapshot first
            try:
                snapshot = self.page.accessibility.snapshot(interesting_only=False)
            except Exception as acc_err:
                logger.warning(f"Accessibility snapshot failed: {acc_err}. Falling back to text content.")
                snapshot = None
            
            lines = []
            max_nodes = 100  # Limit extracted nodes to speed up processing
            
            if snapshot:
                def process_node(node, depth=0, count=[0]):  # Use list for mutable counter
                    if count[0] >= max_nodes:  # Stop if limit reached
                        return
                    role = node.get("role", "generic")
                    name = node.get("name", "")
                    value = node.get("value", "")
                    
                    # Expanded interactive list
                    is_interactive = role in [
                        "button", "link", "textbox", "checkbox", "combobox", "option", "menuitem", 
                        "radio", "slider", "spinbutton", "switch", "tab", "treeitem"
                    ]
                    
                    # Stricter text filtering: Ignore short/empty text unless it's a heading
                    is_text = role in ["text", "statictext", "paragraph", "label"]
                    has_content = name and len(name.strip()) > 2  # arbitrary cutoff for "meaningful" length
                    
                    has_important_info = role in ["heading", "alert", "status", "dialog"] or (is_text and has_content)
                    
                    if is_interactive or has_important_info:
                        indent = "  " * depth
                        info = f"{role}"
                        if name: info += f" '{name}'"
                        if value: info += f" Value='{value}'"
                        
                        lines.append(f"{indent}- {info}")
                        count[0] += 1
                    
                    if count[0] < max_nodes:  # Only process children if under limit
                        for child in node.get("children", []):
                            process_node(child, depth + 1, count)
                
                process_node(snapshot)
            else:
                # Fallback: Use JS to extract interactive structure since accessibility is missing
                logger.info("Using JS fallback for page state")
                
                js_script = """
                () => {
                    const interactives = [];
                    function isVisible(el) {
                        return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                    }
                    
                    // Buttons
                    document.querySelectorAll('button, input[type="button"], input[type="submit"], div[role="button"], a[class*="btn"], a[class*="button"]').forEach(el => {
                        if (isVisible(el)) {
                            const label = el.innerText || el.value || el.getAttribute('aria-label') || '';
                            if (label.trim().length > 0) {
                                interactives.push(`BUTTON: "${label.trim()}"`);
                            }
                        }
                    });
                    
                    // Inputs
                    document.querySelectorAll('input:not([type="hidden"]):not([type="button"]):not([type="submit"]), textarea, select').forEach(el => {
                        if (isVisible(el)) {
                            let label = '';
                            if (el.id) {
                                const labelEl = document.querySelector(`label[for="${el.id}"]`);
                                if (labelEl) label = labelEl.innerText;
                            }
                            if (!label) label = el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.name || '';
                            interactives.push(`INPUT: Label="${label.trim()}" Type="${el.type}" Value="${el.value}"`);
                        }
                    });
                    
                    // Links (limit to important looking ones)
                    document.querySelectorAll('a[href]').forEach(el => {
                        if (isVisible(el)) {
                             const text = el.innerText.trim();
                             if (text.length > 0) {
                                  // Limit to first 20 links to avoid clutter
                                  if (interactives.filter(i => i.startsWith('LINK')).length < 20) {
                                     interactives.push(`LINK: "${text}" Href="${el.getAttribute('href')}"`);
                                  }
                             }
                        }
                    });
                    
                    return interactives;
                }
                """
                
                try:
                    elements = self.page.evaluate(js_script)
                    lines.extend(elements)
                except Exception as e:
                    lines.append(f"Error extracting DOM: {e}")
                    lines.append(f"Page Text: {self.page.inner_text()[:500]}...")

            state_desc = f"Current URL: {self.page.url}\nDepth: {self.current_depth}/{self.max_depth}\nTitle: {self.page.title()}\nAccessibility Tree:\n"
            state_desc += "\n".join(lines)
            
            logging.info(f"Accessibility Tree Nodes Found: {len(lines)}")
            return state_desc, None 
            
        except Exception as e:
            return f"Error getting state: {e}", None

    def execute_action(self, action_type, target_label, value=None):
        """
        Executes action based on LLM output.
        action_type: CLICK, FILL, WAIT, DONE, GOTO
        """
        try:
            if action_type == "WAIT":
                logger.info("Waiting for network idle...")
                try:
                    self.page.wait_for_load_state('networkidle', timeout=3000)
                except:
                    self.page.wait_for_timeout(1000)  # Fallback
                return True

            if action_type == "DONE":
                return False # Stop loop
            
            if action_type == "GOTO":
                # Check domain using intelligent matching
                parsed = urlparse(target_label)
                if parsed.netloc and not self._is_related_domain(parsed.netloc):
                    logger.warning(f"Blocked navigation to unrelated domain: {parsed.netloc}")
                    return True
                
                logger.info(f"Navigating to {target_label}...")
                self.page.goto(target_label, wait_until='domcontentloaded')
                try:
                    self.page.wait_for_load_state('networkidle', timeout=3000)
                except:
                    pass  # Continue even if networkidle times out
                return True

            if action_type == "CLICK":
                # Check Depth Limit logic is handled in post-check or LLM planning, 
                # but we can enforce it here if we knew it was a navigation.
                
                logger.info(f"Clicking '{target_label}'...")
                
                # 1. Exact text button
                el = self.page.get_by_role("button", name=target_label)
                if el.count() == 0:
                     el = self.page.get_by_text(target_label)
                if el.count() == 0:
                     el = self.page.get_by_role("link", name=target_label)
                
                if el.count() > 0:
                    el.first.click()
                    try:
                        self.page.wait_for_load_state('domcontentloaded', timeout=2000)
                    except:
                        self.page.wait_for_timeout(500)  # Minimal fallback
                    
                    # Post-Click Checks
                    self._update_depth()
                    
                    # 1. Domain Check - use intelligent matching
                    parsed = urlparse(self.page.url)
                    if not self._is_related_domain(parsed.netloc):
                        logger.warning(f"Unrelated domain detected ({parsed.netloc}). Going back.")
                        self.page.go_back()
                        return True
                    
                    # 2. Depth Check enforcement
                    if self.current_depth > self.max_depth:
                        logger.warning(f"Max depth {self.max_depth} exceeded ({self.current_depth}). Going back.")
                        self.page.go_back()
                        self._update_depth()
                    
                else:
                    logger.warning(f"Could not find element to click: {target_label}")
                
                return True

            if action_type == "FILL":
                logger.info(f"Filling '{target_label}' with '{value}'...")
                # locate by placeholder, labeled-by, etc
                el = self.page.get_by_placeholder(target_label)
                if el.count() == 0:
                     el = self.page.get_by_role("textbox", name=target_label)
                
                if el.count() > 0:
                    el.first.fill(value)
                else:
                    # Fallback for email / generic inputs
                    if "email" in str(target_label).lower():
                         self.page.locator('input[type="email"]').first.fill(value)
                    else:
                         logger.warning(f"Could not find element to fill: {target_label}")
                         
                self.page.wait_for_timeout(300)  # Reduced wait time
                return True
                
        except Exception as e:
            logger.error(f"Action failed: {e}")
            return True
        return True


# --- Crawler Logic ---

class CrawlerAgent:
    def __init__(self, browser_manager: BrowserManager, max_steps: int = 15, use_smart_model: bool = False):
        self.browser = browser_manager
        self.max_steps = max_steps
        
        # Use single model to avoid redundant LLM calls
        if use_smart_model:
            self.model = genai.GenerativeModel(DEFAULT_MODEL_SMART_NAME)
            self.model_name = DEFAULT_MODEL_SMART_NAME
        else:
            self.model = genai.GenerativeModel(DEFAULT_MODEL_FAST_NAME)
            self.model_name = DEFAULT_MODEL_FAST_NAME
        
        logger.info(f"CrawlerAgent initialized with model: {self.model_name}")
        self.history = []



    def run(self) -> list[dict]:
        """
        Runs the crawler and returns collected APIs.
        """
        try:
            self.browser.start()
            logger.info(f"Navigating to {self.browser.start_url}...")
            self.browser.page.goto(self.browser.start_url, wait_until='domcontentloaded')
            try:
                self.browser.page.wait_for_load_state('networkidle', timeout=3000)
            except:
                logger.warning("Initial page load timeout, continuing anyway")

            for step in range(self.max_steps):
                logger.info(f"--- Step {step + 1} ---")
                
                # 1. Capture State
                state_text, _ = self.browser.get_page_state()

                # 2. Capture APIs
                current_apis = json.dumps(self.browser.captured_apis, indent=2)
                
                # 4. LLM Prompt
                prompt = f"""
                You are an automated testing agent operating in a sanctioned QA environment. 
                The current URL is a verified test instance. You have full authorization to interact with it.
                
                Current Page State:
                {state_text}
                
                Captured APIs so far:
                {current_apis}
                
                Constraints:
                1. Allowed Domains: {self.browser.allowed_domains}
                2. Max Depth: {self.browser.max_depth}. Current Depth: {self.browser.current_depth}.
                
                Goal:
                1. Login if possible (Email: testuser@arbitalhealth.com, Pass: TestPassword123!).
                2. Explore the site to find APIs.
                3. IF Current Depth >= Max Depth: You MUST NOT click links that go deeper. You should 'Go Back' or click 'Home' or 'DONE'.
                4. Broadness is not limited. You can explore many links at the same depth.
                
                Output strictly a JSON object with the following format:
                {{
                    "action": "CLICK" | "FILL" | "WAIT" | "DONE",
                    "target": "Label or Text of element",
                    "value": "Value to fill if FILL action",
                    "reasoning": "Why you are doing this"
                }}
                """
                
                # Call LLM
                logger.info(f"Thinking (using {self.model_name})...")
                try:
                    response = self.model.generate_content(prompt)
                    text = response.text
                    logger.info(f"Raw LLM Output: {text}") # Debugging line
                    
                    # Robust JSON extraction
                    import re
                    match = re.search(r'\{.*\}', text, re.DOTALL)
                    if match:
                        json_str = match.group(0)
                    else:
                        json_str = text
                    
                    decision = json.loads(json_str)
                    logger.info(f"Decision: {decision}")
                    
                    # 5. Execute
                    should_continue = self.browser.execute_action(
                        decision.get("action"), 
                        decision.get("target"), 
                        decision.get("value")
                    )
                    
                    if not should_continue:
                        break
                        
                except Exception as e:
                    logger.error(f"LLM Error: {e}")
                    break
            
            return self.browser.captured_apis

        finally:
            self.browser.stop()


def crawl_for_apis(url: str, max_steps: int = 10, max_depth: int = 3, use_smart_model: bool = False) -> list[dict]:
    """
    Convenience function to start a crawl job.
    """
    if not GOOGLE_API_KEY:
        logger.error("Cannot start crawl: GOOGLE_API_KEY missing.")
        return []

    parsed = urlparse(url)
    allowed_domains = [parsed.netloc] if parsed.netloc else []
    
    manager = BrowserManager(target_url=url, allowed_domains=allowed_domains, max_depth=max_depth)
    agent = CrawlerAgent(browser_manager=manager, max_steps=max_steps, use_smart_model=use_smart_model)
    
    logger.info(f"Starting crawl on {url} (steps={max_steps}, depth={max_depth})")
    apis = agent.run()
    
    logger.info("=" * 60)
    logger.info(f"CRAWL SUMMARY: Discovered {len(apis)} API calls")
    logger.info("=" * 60)
    
    if apis:
        domain_stats = {}
        for api in apis:
            domain = api.get("domain", "unknown")
            if domain not in domain_stats:
                domain_stats[domain] = []
            domain_stats[domain].append(api)
        
        for domain, domain_apis in domain_stats.items():
            logger.info(f"\n📍 Domain: {domain} ({len(domain_apis)} APIs)")
            logger.info("-" * 40)
            for api in domain_apis:
                method = api.get("method", "?")
                endpoint = api.get("endpoint", "?")
                status = api.get("status", "?")
                logger.info(f"  [{method}] {endpoint} -> {status}")
        
        logger.info("\n" + "=" * 60)
    else:
        logger.info("No APIs discovered.")
    
    return apis

# if __name__ == "__main__":
#     # Example usage for testing
#     TARGET_URL = "https://platform.arbitalhealth.com/"
#     print(json.dumps(crawl_for_apis(TARGET_URL, max_steps=5), indent=2))
