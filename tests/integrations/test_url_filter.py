"""
Test the URL filtering functionality
"""

import unittest
from src.integrations.url_filter import UrlFilter

class TestUrlFilter(unittest.TestCase):
    """Tests for the URL Filter module"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.filter = UrlFilter()
        self.filter.set_base_url("http://example.com")
    
    def test_is_allowed_basic(self):
        """Test basic URL filtering"""
        # Valid URLs should be allowed
        self.assertTrue(self.filter.is_allowed("http://example.com/about"))
        self.assertTrue(self.filter.is_allowed("http://example.com/products"))
        self.assertTrue(self.filter.is_allowed("http://example.com/search?q=test"))
        
        # URLs from different domains should be blocked
        self.assertFalse(self.filter.is_allowed("http://attacker.com/page"))
        
        # URLs with excessive parameters should be blocked
        long_url = "http://example.com/page?" + "&".join([f"param{i}=value{i}" for i in range(20)])
        self.assertFalse(self.filter.is_allowed(long_url))
        
        # URLs with excessive path segments should be blocked
        deep_url = "http://example.com/" + "/".join([f"segment{i}" for i in range(15)])
        self.assertFalse(self.filter.is_allowed(deep_url))
    
    def test_is_allowed_file_extensions(self):
        """Test filtering of file extensions"""
        # Static file extensions should be blocked
        self.assertFalse(self.filter.is_allowed("http://example.com/image.jpg"))
        self.assertFalse(self.filter.is_allowed("http://example.com/styles.css"))
        self.assertFalse(self.filter.is_allowed("http://example.com/script.js"))
        self.assertFalse(self.filter.is_allowed("http://example.com/document.pdf"))
        
        # Valid page URLs should be allowed
        self.assertTrue(self.filter.is_allowed("http://example.com/about.php"))
        self.assertTrue(self.filter.is_allowed("http://example.com/products.html"))
        self.assertTrue(self.filter.is_allowed("http://example.com/search.aspx"))
    
    def test_is_allowed_excluded_patterns(self):
        """Test filtering of URLs with excluded patterns"""
        # Logout URLs should be blocked to avoid logging out during crawl
        self.assertFalse(self.filter.is_allowed("http://example.com/logout"))
        self.assertFalse(self.filter.is_allowed("http://example.com/sign-out"))
        
        # Destructive action URLs should be blocked
        self.assertFalse(self.filter.is_allowed("http://example.com/delete/123"))
        self.assertFalse(self.filter.is_allowed("http://example.com/remove/user"))
        
        # Calendar date URLs should be blocked to avoid crawling each day
        self.assertFalse(self.filter.is_allowed("http://example.com/calendar/2023/10/15"))
        
        # URL with UTM parameters should be blocked
        self.assertFalse(self.filter.is_allowed("http://example.com/page?utm_source=newsletter"))
    
    def test_is_allowed_subdomains(self):
        """Test filtering based on subdomains"""
        # Create a filter allowing subdomains
        filter_with_subdomains = UrlFilter(include_subdomains=True)
        filter_with_subdomains.set_base_url("http://example.com")
        
        # Valid subdomain should be allowed
        self.assertTrue(filter_with_subdomains.is_allowed("http://blog.example.com/post"))
        self.assertTrue(filter_with_subdomains.is_allowed("http://store.example.com/product"))
        
        # Create a filter disallowing subdomains
        filter_without_subdomains = UrlFilter(include_subdomains=False)
        filter_without_subdomains.set_base_url("http://example.com")
        
        # Subdomains should be blocked
        self.assertFalse(filter_without_subdomains.is_allowed("http://blog.example.com/post"))
        self.assertFalse(filter_without_subdomains.is_allowed("http://store.example.com/product"))
    
    def test_is_allowed_fragments(self):
        """Test filtering based on URL fragments"""
        # Fragment URLs that actually navigate to a different page should be allowed
        self.assertTrue(self.filter.is_allowed("http://example.com/page1#section", "http://example.com/page2"))
        
        # Fragment URLs that just link to a different section of the same page should be blocked
        self.assertFalse(self.filter.is_allowed("http://example.com/page#section", "http://example.com/page"))
    
    def test_normalize_url(self):
        """Test URL normalization"""
        # Test scheme and host normalization (case insensitive)
        self.assertEqual(
            self.filter.normalize_url("HTTP://EXAMPLE.COM/page"),
            "http://example.com/page"
        )
        
        # Test parameter sorting
        self.assertEqual(
            self.filter.normalize_url("http://example.com/page?b=2&a=1"),
            "http://example.com/page?a=1&b=2"
        )
        
        # Test default port removal
        self.assertEqual(
            self.filter.normalize_url("http://example.com:80/page"),
            "http://example.com/page"
        )
        self.assertEqual(
            self.filter.normalize_url("https://example.com:443/page"),
            "https://example.com/page"
        )
        
        # Test empty path normalization
        self.assertEqual(
            self.filter.normalize_url("http://example.com"),
            "http://example.com/"
        )
        
        # Test relative URL resolution
        self.assertEqual(
            self.filter.normalize_url("page.html", "http://example.com/dir/"),
            "http://example.com/dir/page.html"
        )
        self.assertEqual(
            self.filter.normalize_url("../about", "http://example.com/dir/"),
            "http://example.com/about"
        )
    
    def test_prioritize_urls(self):
        """Test URL prioritization"""
        # Define test URLs of different priorities
        test_urls = [
            "http://example.com/about",             # Low priority
            "http://example.com/search?q=test",     # High priority (has query)
            "http://example.com/admin",             # High priority (admin pattern)
            "http://example.com/product/123",       # Low priority
            "http://example.com/contact",           # Medium priority
            "http://example.com/login",             # High priority (login pattern)
            "http://example.com/article/news",      # Medium priority
        ]
        
        # Prioritize the URLs
        prioritized = self.filter.prioritize_urls(test_urls)
        
        # High priority URLs should come first
        self.assertIn("http://example.com/search?q=test", prioritized[:3])
        self.assertIn("http://example.com/admin", prioritized[:3])
        self.assertIn("http://example.com/login", prioritized[:3])
        
        # Medium priority URLs should come next
        self.assertIn("http://example.com/contact", prioritized[3:5])
        self.assertIn("http://example.com/article/news", prioritized[3:5])
        
        # Low priority URLs should come last
        self.assertIn("http://example.com/about", prioritized[5:])
        self.assertIn("http://example.com/product/123", prioritized[5:])
    
    def test_custom_excluded_extensions(self):
        """Test adding custom excluded extensions"""
        # Create a filter with custom excluded extensions
        custom_filter = UrlFilter(excluded_extensions={'.phtml', '.aspx'})
        custom_filter.set_base_url("http://example.com")
        
        # Custom extensions should be blocked
        self.assertFalse(custom_filter.is_allowed("http://example.com/page.phtml"))
        self.assertFalse(custom_filter.is_allowed("http://example.com/page.aspx"))
        
        # Default extensions should still be blocked
        self.assertFalse(custom_filter.is_allowed("http://example.com/image.jpg"))
        self.assertFalse(custom_filter.is_allowed("http://example.com/styles.css"))
    
    def test_custom_excluded_patterns(self):
        """Test adding custom excluded patterns"""
        # Create a filter with custom excluded patterns
        custom_filter = UrlFilter(excluded_patterns=[r'/private/', r'/restricted/'])
        custom_filter.set_base_url("http://example.com")
        
        # Custom patterns should be blocked
        self.assertFalse(custom_filter.is_allowed("http://example.com/private/data"))
        self.assertFalse(custom_filter.is_allowed("http://example.com/restricted/access"))
        
        # Default patterns should still be blocked
        self.assertFalse(custom_filter.is_allowed("http://example.com/logout"))
        self.assertFalse(custom_filter.is_allowed("http://example.com/delete/123"))
    
    def test_is_allowed_url_length(self):
        """Test filtering based on URL length"""
        # Create a filter with a small max URL length
        short_url_filter = UrlFilter(max_url_length=50)
        short_url_filter.set_base_url("http://example.com")
        
        # Short URL should be allowed
        self.assertTrue(short_url_filter.is_allowed("http://example.com/page"))
        
        # Long URL should be blocked
        long_url = "http://example.com/" + "a" * 60
        self.assertFalse(short_url_filter.is_allowed(long_url))
    
    def test_handle_invalid_urls(self):
        """Test handling of invalid URLs"""
        # None or empty URL should be blocked
        self.assertFalse(self.filter.is_allowed(None))
        self.assertFalse(self.filter.is_allowed(""))
        
        # Invalid URLs should be blocked
        self.assertFalse(self.filter.is_allowed("not a url"))
        self.assertFalse(self.filter.is_allowed("javascript:alert(1)"))
        
        # Normalization should handle invalid URLs gracefully
        self.assertEqual(self.filter.normalize_url("javascript:alert(1)"), "javascript:alert(1)")

if __name__ == '__main__':
    unittest.main() 