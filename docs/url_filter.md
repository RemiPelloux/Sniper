# URL Filter for Web Application Scanning

## Overview

The URL Filter module provides intelligent filtering, normalization, and prioritization of URLs during web application scanning. It helps focus crawling on relevant parts of web applications and optimizes the scanning process by:

1. Filtering out irrelevant URLs (static files, logout links, etc.)
2. Normalizing URLs to prevent duplicate crawling
3. Prioritizing high-value URLs for vulnerability scanning
4. Applying configurable exclusion rules to control crawling scope

## Features

### URL Filtering

The filter excludes URLs based on several criteria:

- **File Extensions**: Static files like images, documents, stylesheets, and other non-vulnerable resource types
- **Excessive Parameters**: URLs with too many query parameters (configurable)
- **Path Depth**: URLs with too many path segments (configurable)
- **URL Length**: Excessively long URLs (configurable)
- **Domain Constraints**: Limiting crawling to the same domain or allowing subdomains
- **Excluded Patterns**: Common patterns to avoid (logout, delete, etc.)
- **Fragment Handling**: Intelligent handling of URL fragments to avoid duplicate content

### URL Normalization

The normalizer standardizes URLs to prevent duplicate crawling:

- Resolves relative URLs
- Lowercases scheme and host
- Removes default ports (80 for HTTP, 443 for HTTPS)
- Ensures path ends with '/' if empty
- Sorts and filters query parameters
- Removes fragments (anchors) that don't affect content
- Handles special schemes (javascript:, mailto:, etc.)

### URL Prioritization

The URL prioritizer ensures high-value targets are scanned first:

- **High Priority URLs**:
  - URLs with query parameters
  - Authentication endpoints (login, register, password reset)
  - Admin interfaces
  - Data input endpoints (search, forms, uploads)
  - API endpoints
  - User account pages

- **Medium Priority URLs**:
  - Content pages
  - List views
  - Category pages

- **Low Priority URLs**:
  - Static content
  - Information pages
  - Other non-interactive pages

## Usage

### Basic Usage

```python
from src.integrations.url_filter import UrlFilter

# Create a filter instance
url_filter = UrlFilter()

# Set the base URL for domain filtering
url_filter.set_base_url("https://example.com")

# Check if a URL is allowed
is_allowed = url_filter.is_allowed("https://example.com/login")  # True
is_allowed = url_filter.is_allowed("https://example.com/image.jpg")  # False

# Normalize a URL
normalized = url_filter.normalize_url("https://EXAMPLE.com/page?b=2&a=1")
# Result: "https://example.com/page?a=1&b=2"

# Prioritize a list of URLs
urls = [
    "https://example.com/about",
    "https://example.com/search?q=test",
    "https://example.com/admin"
]
prioritized = url_filter.prioritize_urls(urls)
# Result will have admin and search URLs first
```

### Configuration Options

The `UrlFilter` class accepts several configuration parameters:

```python
url_filter = UrlFilter(
    max_query_params=8,           # Maximum number of query parameters allowed
    max_path_segments=10,         # Maximum number of path segments allowed
    max_url_length=2000,          # Maximum allowed URL length
    excluded_extensions=None,     # Custom set of file extensions to exclude
    excluded_patterns=None,       # Custom list of regex patterns to exclude
    include_only_same_domain=True,# Only include URLs from the same domain
    include_subdomains=True,      # Include subdomains of the base domain
    respect_robots_txt=True       # Respect robots.txt directives
)
```

## Custom Excluded Extensions

You can add custom extensions to exclude beyond the default set:

```python
# Create a filter that also excludes .phtml and .aspx files
custom_filter = UrlFilter(excluded_extensions={'.phtml', '.aspx'})
```

The default excluded extensions include:

- Images: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.svg`, `.ico`, `.webp`
- Documents: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.ods`, `.odp`
- Archives: `.zip`, `.rar`, `.tar`, `.gz`, `.7z`
- Audio/Video: `.mp3`, `.mp4`, `.avi`, `.mov`, `.wmv`, `.flv`, `.wav`, `.ogg`
- Static content: `.css`, `.js`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.map`
- Data files: `.xml`, `.json`, `.csv`, `.rss`, `.atom`

## Custom Excluded Patterns

You can add custom patterns to exclude beyond the default set:

```python
# Create a filter that also excludes URLs with "private" or "restricted" in the path
custom_filter = UrlFilter(excluded_patterns=[r'/private/', r'/restricted/'])
```

The default excluded patterns include:

- Logout URLs: `logout`, `sign-?out`, `log-?out`
- Destructive actions: `delete`, `remove`, `/trash/`, `/cancel/`
- Calendar dates: `/calendar/\d{4}/\d{1,2}(/\d{1,2})?`
- Printer versions: `print=`, `printable=`, `/print/`
- Language duplicates: `/locale/\w+/`, `/language/\w+/`
- Infinite loops: `sort=.*&sort=`, `page=\d+&page=`
- AJAX/Service workers: `/ajax/`, `/service-worker\.js`
- Common third-party paths: `/wp-content/plugins/`, `/wp-content/themes/`
- Tracking parameters: `utm_`, `fb_`, `share=`, `ref=`

## Integration with Vulnerability Scanner

The URL Filter module is fully integrated with the Vulnerability Scanner, improving crawler efficiency and scan focus. The integration provides several benefits:

1. **Reduced Scan Time**: By focusing on relevant URLs, the scanner spends less time on low-value targets
2. **Improved Discovery**: The prioritization ensures high-value endpoints are discovered early in the scan
3. **Better Performance**: Filtering out static resources and duplicate URLs reduces the load on the scanner
4. **More Complete Coverage**: By avoiding crawling traps (infinite loops, logout links), the scanner can more effectively cover the application

## Testing

The URL Filter module has comprehensive unit tests that verify its functionality:

- Basic URL filtering
- File extension filtering
- Pattern exclusion
- Subdomain handling
- Fragment URL handling
- URL normalization
- URL prioritization
- Custom configuration handling
- Error handling

## Performance Considerations

- The URL Filter is designed to be lightweight and efficient
- Patterns are compiled once for faster matching
- URL normalization is optimized to reduce resource consumption
- The prioritization algorithm efficiently categorizes URLs based on their potential value

## Future Enhancements

- **robots.txt Integration**: Full support for respecting robots.txt directives
- **Crawling Limits by Directory**: Configure different depth limits for different directories
- **Regex-based URL Transformation**: Allow custom regular expressions for URL transformations
- **Machine Learning Integration**: Use ML to learn which URLs have higher vulnerability potential
- **Site Structure Awareness**: Understand site structure to make more intelligent crawling decisions