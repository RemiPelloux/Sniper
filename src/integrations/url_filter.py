"""
URL Filter Module

This module provides functionality to filter URLs during crawling operations.
It helps exclude irrelevant URLs, normalize URLs, and apply exclusion rules to 
focus crawling on relevant parts of web applications.
"""

from typing import List, Pattern, Set, Optional
import re
from urllib.parse import urlparse, parse_qs, urljoin
import logging

log = logging.getLogger(__name__)

class UrlFilter:
    """
    Provides URL filtering capabilities for web crawlers.
    
    This class helps:
    1. Filter out irrelevant URLs during crawling
    2. Normalize URLs to prevent duplicate crawling
    3. Focus crawling on relevant parts of web applications
    4. Exclude URLs matching specific patterns
    """
    
    # Common file extensions to exclude (static files, irrelevant content)
    DEFAULT_EXCLUDED_EXTENSIONS = {
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp',
        # Archives
        '.zip', '.rar', '.tar', '.gz', '.7z',
        # Audio/Video
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
        # Other static content
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.map',
        # Data files
        '.xml', '.json', '.csv', '.rss', '.atom'
    }
    
    # Common URL patterns to exclude
    DEFAULT_EXCLUDED_PATTERNS = [
        # Logout URLs (to avoid logging out during crawl)
        r'logout', r'sign-?out', r'log-?out',
        # Common anti-pattern endpoints
        r'delete', r'remove', r'/trash/', r'/cancel/',
        # Calendar URLs with specific dates (to avoid crawling each day)
        r'/calendar/\d{4}/\d{1,2}(/\d{1,2})?',
        # Printer-friendly versions
        r'print=', r'printable=', r'/print/', 
        # Language or locale-specific duplicates
        r'/locale/\w+/', r'/language/\w+/',
        # Common infinite-loop patterns
        r'sort=.*&sort=', r'page=\d+&page=',
        # AJAX and API calls that might duplicate content
        r'/ajax/', r'/service-worker\.js',
        # Common third-party paths
        r'/wp-content/plugins/', r'/wp-content/themes/',
        # Parameter patterns that create infinite loops
        r'utm_', r'fb_', r'share=', r'ref=',
    ]
    
    def __init__(self, 
                 max_query_params: int = 8,
                 max_path_segments: int = 10,
                 max_url_length: int = 2000,
                 excluded_extensions: Optional[Set[str]] = None,
                 excluded_patterns: Optional[List[str]] = None,
                 include_only_same_domain: bool = True,
                 include_subdomains: bool = True,
                 respect_robots_txt: bool = True):
        """
        Initialize the URL filter with configuration settings.
        
        Args:
            max_query_params: Maximum number of query parameters allowed
            max_path_segments: Maximum number of path segments allowed
            max_url_length: Maximum allowed URL length
            excluded_extensions: Set of file extensions to exclude
            excluded_patterns: List of regex patterns to exclude
            include_only_same_domain: Only include URLs from the same domain
            include_subdomains: Include subdomains of the base domain
            respect_robots_txt: Whether to respect robots.txt directives
        """
        self.max_query_params = max_query_params
        self.max_path_segments = max_path_segments
        self.max_url_length = max_url_length
        self.include_only_same_domain = include_only_same_domain
        self.include_subdomains = include_subdomains
        self.respect_robots_txt = respect_robots_txt
        
        # Set up excluded extensions (combine defaults with custom)
        self.excluded_extensions = self.DEFAULT_EXCLUDED_EXTENSIONS.copy()
        if excluded_extensions:
            self.excluded_extensions.update(excluded_extensions)
            
        # Set up excluded patterns (combine defaults with custom)
        self.excluded_patterns = self.DEFAULT_EXCLUDED_PATTERNS.copy()
        if excluded_patterns:
            self.excluded_patterns.extend(excluded_patterns)
            
        # Compile patterns for efficiency
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.excluded_patterns]
        
        # Keep track of base domain for filtering
        self.base_domain = None
    
    def set_base_url(self, base_url: str) -> None:
        """
        Set the base URL for domain-based filtering.
        
        Args:
            base_url: The base URL to use for filtering
        """
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
    
    def is_allowed(self, url: str, source_url: str = None) -> bool:
        """
        Check if a URL is allowed based on filtering rules.
        
        Args:
            url: The URL to check
            source_url: The source URL where this URL was found
            
        Returns:
            bool: True if the URL is allowed, False otherwise
        """
        # If no base domain is set, set it from the URL
        if not self.base_domain and source_url:
            self.set_base_url(source_url)
        
        # Basic URL validation
        if not url or len(url) > self.max_url_length:
            return False
            
        # Parse URL
        try:
            parsed_url = urlparse(url)
        except Exception as e:
            log.debug(f"Failed to parse URL {url}: {str(e)}")
            return False
            
        # Filter out URLs with no netloc (like javascript: links)
        if not parsed_url.netloc:
            return False
            
        # Check domain constraints
        if self.include_only_same_domain:
            # Extract domain from URL
            url_domain = parsed_url.netloc
            
            # Check exact domain match
            if self.base_domain and url_domain != self.base_domain:
                # If subdomains are allowed, check if it's a subdomain of the base domain
                if self.include_subdomains:
                    if not url_domain.endswith(f".{self.base_domain}") and url_domain != self.base_domain:
                        return False
                else:
                    return False
        
        # Check file extension
        path = parsed_url.path.lower()
        if any(path.endswith(ext) for ext in self.excluded_extensions):
            return False
            
        # Check for excessive query parameters
        query_params = parse_qs(parsed_url.query)
        if len(query_params) > self.max_query_params:
            return False
            
        # Check for excessive path segments
        path_segments = [segment for segment in path.split('/') if segment]
        if len(path_segments) > self.max_path_segments:
            return False
            
        # Check excluded patterns
        for pattern in self.compiled_patterns:
            if pattern.search(url):
                return False
                
        # Check for fragments (avoid crawling multiple fragment URLs)
        if parsed_url.fragment:
            # Only allow fragment URLs if they provide an actual navigation target
            # (not just linking to an anchor on the same page)
            if source_url:
                source_parsed = urlparse(source_url)
                # If everything else in the URL is the same, it's just a fragment link
                if (parsed_url.netloc == source_parsed.netloc and
                    parsed_url.path == source_parsed.path and
                    parsed_url.params == source_parsed.params and
                    parsed_url.query == source_parsed.query):
                    return False
        
        return True
    
    def normalize_url(self, url: str, base_url: str = None) -> str:
        """
        Normalize a URL to prevent duplicate crawling.
        
        Args:
            url: The URL to normalize
            base_url: The base URL for resolving relative URLs
            
        Returns:
            str: Normalized URL
        """
        # Handle special schemes like javascript:
        if url and (url.startswith('javascript:') or url.startswith('data:') or url.startswith('mailto:')):
            return url
            
        # Resolve relative URLs if base_url is provided
        if base_url:
            url = urljoin(base_url, url)
            
        try:
            parsed = urlparse(url)
            
            # Skip normalization for non-HTTP(S) schemes
            if parsed.scheme and parsed.scheme not in ('http', 'https'):
                return url
            
            # Lowercase the scheme and netloc
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            
            # Remove default ports (80 for HTTP, 443 for HTTPS)
            if ':' in netloc:
                domain, port = netloc.split(':', 1)
                if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                    netloc = domain
            
            # Ensure path ends with '/' if it's empty
            path = parsed.path
            if not path:
                path = '/'
                
            # Remove empty query parameters and sort them
            query_parts = []
            if parsed.query:
                query_params = parse_qs(parsed.query)
                # Filter out empty parameters
                query_params = {k: v for k, v in query_params.items() if v}
                # Sort parameters by key for consistency
                for key in sorted(query_params.keys()):
                    values = query_params[key]
                    # Sort values if there are multiple
                    if len(values) > 1:
                        values.sort()
                    for value in values:
                        query_parts.append(f"{key}={value}")
            
            # Rebuild query string
            query = '&'.join(query_parts)
            
            # Remove fragment (anchors) as they don't affect content
            fragment = ''
            
            # Rebuild the URL
            normalized = f"{scheme}://{netloc}{path}"
            if query:
                normalized += f"?{query}"
            
            return normalized
            
        except Exception as e:
            log.debug(f"Failed to normalize URL {url}: {str(e)}")
            return url
    
    def prioritize_urls(self, urls: List[str]) -> List[str]:
        """
        Prioritize URLs based on their potential value for vulnerability scanning.
        
        Args:
            urls: List of URLs to prioritize
            
        Returns:
            List[str]: Prioritized list of URLs
        """
        # Define value patterns (in descending order of priority)
        high_value_patterns = [
            # Authentication-related
            r'/login', r'/register', r'/signup', r'/password', r'/reset', r'/forgot',
            # Admin or privileged interfaces
            r'/admin', r'/dashboard', r'/console', r'/manage', r'/control',
            # Data input and manipulation
            r'/upload', r'/import', r'/export', r'/search', r'/query', r'/filter',
            # User-generated content
            r'/comment', r'/post', r'/submit', r'/create', r'/edit', r'/delete',
            # APIs and integrations
            r'/api/', r'/rest/', r'/ajax/', r'/service/', r'/callback/',
            # File operations
            r'/file', r'/download', r'/view', r'/open', r'/show',
            # User account related
            r'/account', r'/profile', r'/user', r'/settings', r'/preferences',
            # E-commerce
            r'/cart', r'/basket', r'/checkout', r'/payment', r'/order',
        ]
        
        medium_value_patterns = [
            # Lists and data views
            r'/list', r'/browse', r'/category', r'/tag', r'/topic',
            # Content pages
            r'/page', r'/article', r'/content', r'/news', r'/blog',
            # Other functionalities
            r'/report', r'/contact', r'/feedback', r'/survey', r'/form',
        ]
        
        high_value = []
        medium_value = []
        low_value = []
        
        # Check for URLs with query parameters (always high value)
        for url in urls:
            parsed = urlparse(url)
            
            # URLs with query parameters are high value
            if parsed.query:
                high_value.append(url)
                continue
                
            # Check against high-value patterns
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in high_value_patterns):
                high_value.append(url)
            # Check against medium-value patterns
            elif any(re.search(pattern, url, re.IGNORECASE) for pattern in medium_value_patterns):
                medium_value.append(url)
            # Everything else is low value
            else:
                low_value.append(url)
        
        # Combine the lists in priority order
        return high_value + medium_value + low_value 