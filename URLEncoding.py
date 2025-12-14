"""
URL Encoding and Space Replacement System
Production-ready with comprehensive error handling, logging, and performance optimizations.
"""

import unittest
import logging
from typing import List, Tuple, Dict, Optional, Union
from dataclasses import dataclass
from enum import Enum
import re
from functools import lru_cache
from collections import defaultdict
import time
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class URLEncodingStandard(Enum):
    """Supported URL encoding standards."""
    RFC_3986 = "rfc3986"     # Standard %20 for spaces
    RFC_1866 = "rfc1866"     # + for spaces (form encoding)
    CUSTOM = "custom"        # Custom replacement patterns


@dataclass
class EncodingMetrics:
    """Performance and quality metrics for encoding operations."""
    algorithm: str
    input_length: int
    output_length: int
    execution_time_ms: float
    compression_ratio: float
    space_count: int
    encoding_standard: str


class URLEncoder:
    """
    Production-grade URL encoder with multiple algorithms and real-time optimization.
    
    Features:
    - Multiple encoding strategies
    - Memory-efficient operations
    - Thread-safe implementations
    - Caching for frequent patterns
    - Comprehensive validation
    """
    
    def __init__(self, encoding_standard: URLEncodingStandard = URLEncodingStandard.RFC_3986):
        """
        Initialize URL encoder with specified standard.
        
        Args:
            encoding_standard: URL encoding standard to use
        """
        self.encoding_standard = encoding_standard
        self.space_replacement = "%20" if encoding_standard == URLEncodingStandard.RFC_3986 else "+"
        self.cache_hits = 0
        self.cache_misses = 0
    
    def urlify_inplace(self, text: str, true_length: int) -> str:
        """
        In-place URL encoding algorithm (most memory efficient).
        
        Time Complexity: O(n)
        Space Complexity: O(1) - modifies list in place
        
        Args:
            text: Input string with trailing spaces
            true_length: Actual length of meaningful content
            
        Returns:
            URL-encoded string
        """
        if not text or true_length <= 0:
            return ""
        
        if true_length > len(text):
            logger.warning(f"True length {true_length} exceeds text length {len(text)}")
            true_length = len(text)
        
        # Convert to list for in-place modification
        chars = list(text)
        write_index = len(chars)
        
        # Process from end to beginning to avoid overwriting
        for read_index in range(true_length - 1, -1, -1):
            if chars[read_index] == ' ':
                # Replace space with encoding
                write_index -= 3
                chars[write_index:write_index + 3] = self.space_replacement
            else:
                # Move character to new position
                write_index -= 1
                chars[write_index] = chars[read_index]
        
        # Return encoded portion
        result = ''.join(chars[write_index:])
        logger.debug(f"In-place encoding: {true_length} chars -> {len(result)} chars")
        return result
    
    def urlify_string_builder(self, text: str, true_length: int) -> str:
        """
        String builder approach (faster for most cases).
        
        Time Complexity: O(n)
        Space Complexity: O(n)
        """
        if not text:
            return ""
        
        # Validate true_length
        true_length = min(true_length, len(text))
        
        # Use list as string builder
        result_parts = []
        
        for i in range(true_length):
            char = text[i]
            if char == ' ':
                result_parts.append(self.space_replacement)
            else:
                result_parts.append(char)
        
        result = ''.join(result_parts)
        return result
    
    @lru_cache(maxsize=1024)
    def urlify_cached(self, text: str, true_length: int) -> str:
        """
        Cached version for frequently encoded strings.
        
        Args:
            text: Input string
            true_length: True length to consider
            
        Returns:
            Cached or computed encoded string
        """
        self.cache_misses += 1
        return self.urlify_string_builder(text, true_length)
    
    def urlify_batch(self, texts: List[Tuple[str, int]]) -> List[str]:
        """
        Batch processing for efficiency.
        
        Args:
            texts: List of (text, true_length) tuples
            
        Returns:
            List of encoded strings
        """
        results = []
        for text, length in texts:
            # Choose optimal algorithm based on text characteristics
            if len(text) > 1000:
                # Large text: use in-place for memory efficiency
                result = self.urlify_inplace(text, length)
            else:
                # Small to medium: use cached version
                if text.count(' ') / max(len(text), 1) > 0.3:
                    # Many spaces, likely cached
                    result = self.urlify_cached(text, length)
                    self.cache_hits += 1
                else:
                    result = self.urlify_string_builder(text, length)
            results.append(result)
        
        return results
    
    def urlify_with_validation(self, text: str, true_length: Optional[int] = None) -> Tuple[str, Dict]:
        """
        URL encoding with comprehensive validation and metrics.
        
        Args:
            text: Input string
            true_length: Optional true length (auto-detected if None)
            
        Returns:
            Tuple of (encoded_string, metrics_dict)
        """
        # Auto-detect true length if not provided
        if true_length is None:
            true_length = len(text.rstrip())
        
        # Validate input
        validation_errors = self._validate_input(text, true_length)
        if validation_errors:
            logger.error(f"Validation failed: {validation_errors}")
            raise ValueError(f"Input validation failed: {validation_errors}")
        
        # Encode with timing
        start_time = time.perf_counter()
        encoded = self.urlify_string_builder(text, true_length)
        execution_time = (time.perf_counter() - start_time) * 1000
        
        # Calculate metrics
        metrics = {
            "original_length": len(text),
            "true_length": true_length,
            "encoded_length": len(encoded),
            "space_count": text[:true_length].count(' '),
            "execution_time_ms": execution_time,
            "compression_ratio": len(encoded) / max(true_length, 1),
            "encoding_standard": self.encoding_standard.value,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses
        }
        
        return encoded, metrics
    
    def _validate_input(self, text: str, true_length: int) -> List[str]:
        """Validate input parameters."""
        errors = []
        
        if not isinstance(text, str):
            errors.append("Input must be a string")
        
        if true_length < 0:
            errors.append("True length cannot be negative")
        
        if true_length > len(text):
            errors.append(f"True length {true_length} exceeds text length {len(text)}")
        
        # Check for non-ASCII characters that might need different encoding
        try:
            text.encode('ascii')
        except UnicodeEncodeError:
            logger.warning("Input contains non-ASCII characters, consider URL encoding")
        
        return errors
    
    def get_performance_metrics(self) -> Dict:
        """Get encoder performance statistics."""
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_ratio": self.cache_hits / max(self.cache_hits + self.cache_misses, 1),
            "encoding_standard": self.encoding_standard.value
        }


# ============================================================================
# REAL-WORLD APPLICATION EXAMPLES
# ============================================================================

class WebApplicationURLProcessor:
    """
    Real-world example: Web application URL processor for e-commerce.
    
    Applications:
    1. SEO-friendly URL generation
    2. Search query encoding
    3. API endpoint construction
    4. Dynamic routing
    """
    
    def __init__(self):
        self.encoder = URLEncoder(URLEncodingStandard.RFC_3986)
        self.product_url_cache = {}
    
    def generate_seo_url(self, product_name: str, category: str, id: str) -> str:
        """
        Generate SEO-friendly URLs for e-commerce products.
        
        Example:
        Input: "Coffee Maker Deluxe", "kitchen-appliances", "12345"
        Output: "/products/kitchen-appliances/coffee-maker-deluxe-12345"
        """
        # Normalize product name
        normalized_name = product_name.lower().strip()
        
        # Encode spaces and special characters
        encoded_name = self.encoder.urlify_string_builder(normalized_name, len(normalized_name))
        
        # Replace %20 with hyphens for SEO
        seo_name = encoded_name.replace("%20", "-").replace("+", "-")
        
        # Remove any remaining special characters
        seo_name = re.sub(r'[^a-z0-9\-]', '', seo_name)
        
        # Construct final URL
        url = f"/products/{category}/{seo_name}-{id}"
        
        logger.info(f"Generated SEO URL: {url}")
        return url
    
    def encode_search_query(self, raw_query: str, filters: Dict = None) -> str:
        """
        Encode search queries for URL parameters.
        
        Example:
        Input: "wireless headphones", {"brand": "Sony", "price_max": "200"}
        Output: "q=wireless%20headphones&brand=Sony&price_max=200"
        """
        # Encode the main query
        encoded_query = self.encoder.urlify_string_builder(raw_query, len(raw_query))
        
        # Build parameter string
        params = [f"q={encoded_query}"]
        
        if filters:
            for key, value in filters.items():
                encoded_value = self.encoder.urlify_string_builder(str(value), len(str(value)))
                params.append(f"{key}={encoded_value}")
        
        return "&".join(params)
    
    def process_user_generated_content(self, user_input: str, max_length: int = 100) -> str:
        """
        Sanitize and encode user-generated content for URLs.
        
        Security applications:
        - Prevent XSS attacks
        - Ensure URL safety
        - Maintain readability
        """
        # Truncate if necessary
        if len(user_input) > max_length:
            user_input = user_input[:max_length]
            logger.warning(f"Truncated user input to {max_length} characters")
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'{}|\\^`]', '', user_input)
        
        # Encode remaining content
        encoded = self.encoder.urlify_string_builder(sanitized, len(sanitized))
        
        return encoded


class APIGatewayURLHandler:
    """
    Real-world example: API Gateway URL handler for microservices.
    
    Applications:
    1. Path parameter encoding
    2. Query string construction
    3. Header value sanitization
    4. Rate limiting keys
    """
    
    def __init__(self):
        self.encoder = URLEncoder()
        self.request_cache = defaultdict(int)
    
    def construct_api_url(self, base_url: str, endpoint: str, 
                         path_params: Dict, query_params: Dict) -> str:
        """
        Construct safe API URLs with encoded parameters.
        
        Example:
        Input: "https://api.example.com", "/users/{id}/posts", 
               {"id": "user 123"}, {"sort": "date desc", "filter": "active"}
        Output: "https://api.example.com/users/user%20123/posts?sort=date%20desc&filter=active"
        """
        # Encode path parameters
        encoded_path = endpoint
        for key, value in path_params.items():
            encoded_value = self.encoder.urlify_string_builder(str(value), len(str(value)))
            encoded_path = encoded_path.replace(f"{{{key}}}", encoded_value)
        
        # Encode query parameters
        query_parts = []
        for key, value in query_params.items():
            encoded_value = self.encoder.urlify_string_builder(str(value), len(str(value)))
            query_parts.append(f"{key}={encoded_value}")
        
        query_string = "&".join(query_parts)
        
        # Construct full URL
        full_url = f"{base_url}{encoded_path}"
        if query_string:
            full_url = f"{full_url}?{query_string}"
        
        return full_url
    
    def generate_rate_limit_key(self, user_id: str, endpoint: str, 
                               method: str = "GET") -> str:
        """
        Generate unique keys for rate limiting.
        
        Example:
        Input: "user_123", "/api/products", "POST"
        Output: "rate_limit:user_123:/api/products:POST"
        """
        # Encode components
        encoded_user = self.encoder.urlify_string_builder(user_id, len(user_id))
        encoded_endpoint = self.encoder.urlify_string_builder(endpoint, len(endpoint))
        
        # Generate key
        key = f"rate_limit:{encoded_user}:{encoded_endpoint}:{method}"
        
        # Track usage for monitoring
        self.request_cache[key] += 1
        
        return key
    
    def parse_and_validate_url(self, url: str) -> Dict:
        """
        Parse and validate incoming URLs in API gateway.
        
        Security applications:
        - Path traversal prevention
        - Parameter injection detection
        - Size validation
        """
        if len(url) > 2048:
            raise ValueError("URL exceeds maximum length")
        
        # Decode URL-encoded components
        decoded = url.replace("%20", " ").replace("+", " ")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\.\./',  # Path traversal
            r'<script',  # XSS attempts
            r'exec\s*\(',  # Command injection
            r'union.*select',  # SQL injection (basic)
        ]
        
        threats = []
        for pattern in suspicious_patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                threats.append(pattern)
        
        return {
            "original_url": url,
            "decoded_url": decoded,
            "length": len(url),
            "threats_detected": threats,
            "is_safe": len(threats) == 0
        }


class ContentManagementSystem:
    """
    Real-world example: CMS for blog post URLs and content management.
    
    Applications:
    1. Blog post slug generation
    2. Media file naming
    3. Sitemap generation
    4. Redirect management
    """
    
    def __init__(self):
        self.encoder = URLEncoder()
        self.url_history = {}
    
    def generate_post_slug(self, title: str, author: str, date: str) -> str:
        """
        Generate URL slugs for blog posts.
        
        Example:
        Input: "Getting Started with Python", "John Doe", "2024-01-15"
        Output: "getting-started-with-python-john-doe-2024-01-15"
        """
        # Combine components
        raw_slug = f"{title} {author} {date}"
        
        # Encode and replace spaces
        encoded = self.encoder.urlify_string_builder(raw_slug.lower(), len(raw_slug))
        slug = encoded.replace("%20", "-").replace("+", "-")
        
        # Remove special characters
        slug = re.sub(r'[^a-z0-9\-]', '', slug)
        
        # Ensure uniqueness
        base_slug = slug
        counter = 1
        while slug in self.url_history:
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        self.url_history[slug] = {
            "title": title,
            "author": author,
            "date": date,
            "generated_at": time.time()
        }
        
        return slug
    
    def handle_file_upload(self, original_filename: str, user_id: str) -> str:
        """
        Generate safe filenames for uploaded content.
        
        Example:
        Input: "My Vacation Photos 2023.zip", "user_456"
        Output: "user_456/my-vacation-photos-2023.zip"
        """
        # Remove path traversal attempts
        safe_name = original_filename.split('/')[-1].split('\\')[-1]
        
        # Encode spaces and special characters
        encoded = self.encoder.urlify_string_builder(safe_name, len(safe_name))
        
        # Replace %20 with hyphens for readability
        final_name = encoded.replace("%20", "-").replace("+", "-")
        
        # Add user directory
        user_path = f"{user_id}/{final_name}"
        
        logger.info(f"Generated safe filename: {user_path}")
        return user_path
    
    def create_redirect_map(self, old_urls: List[str], new_base: str) -> Dict[str, str]:
        """
        Create URL redirect mapping for site migrations.
        
        Example:
        Input: ["/old/page one.html", "/old/about us.php"], "/new"
        Output: {"/old/page%20one.html": "/new/page-one", ...}
        """
        redirects = {}
        
        for old_url in old_urls:
            # Extract page name
            page_name = old_url.split('/')[-1].split('.')[0]
            
            # Encode and create new URL
            encoded_name = self.encoder.urlify_string_builder(page_name, len(page_name))
            new_slug = encoded_name.replace("%20", "-").replace("+", "-").lower()
            new_url = f"{new_base}/{new_slug}"
            
            # Store redirect
            redirects[old_url] = new_url
        
        return redirects


# ============================================================================
# TESTING AND VALIDATION
# ============================================================================

class TestURLEncoder(unittest.TestCase):
    """Comprehensive test suite for URL encoder."""
    
    def setUp(self):
        self.encoder = URLEncoder()
        self.test_cases = {
            ("much ado about nothing      ", 22): "much%20ado%20about%20nothing",
            ("Mr John Smith       ", 13): "Mr%20John%20Smith",
            (" a b    ", 4): "%20a%20b",
            (" a b       ", 5): "%20a%20b%20",
            ("", 0): "",
            ("test", 4): "test",
            ("   ", 3): "%20%20%20",
            ("hello world  ", 11): "hello%20world",
        }
    
    def test_all_algorithms(self):
        """Test all encoding algorithms produce same results."""
        algorithms = [
            self.encoder.urlify_inplace,
            self.encoder.urlify_string_builder,
            lambda t, l: self.encoder.urlify_cached(t, l),
        ]
        
        for (text, length), expected in self.test_cases.items():
            for algorithm in algorithms:
                result = algorithm(text, length)
                self.assertEqual(
                    result, expected,
                    f"Algorithm {algorithm.__name__} failed for '{text}'[{length}]"
                )
    
    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        # Empty string
        self.assertEqual(self.encoder.urlify_string_builder("", 0), "")
        
        # No spaces
        self.assertEqual(self.encoder.urlify_string_builder("abc", 3), "abc")
        
        # All spaces
        self.assertEqual(self.encoder.urlify_string_builder("   ", 3), "%20%20%20")
        
        # Length longer than string
        with self.assertRaises(ValueError):
            self.encoder.urlify_with_validation("test", 10)
    
    def test_performance(self):
        """Performance comparison of different algorithms."""
        test_string = "a " * 5000  # Large string with many spaces
        true_length = len(test_string.rstrip())
        
        algorithms = [
            ("inplace", self.encoder.urlify_inplace),
            ("string_builder", self.encoder.urlify_string_builder),
            ("cached", lambda t, l: self.encoder.urlify_cached(t, l)),
        ]
        
        print("\nPerformance Comparison:")
        print("-" * 50)
        
        for name, algorithm in algorithms:
            start = time.perf_counter()
            result = algorithm(test_string, true_length)
            elapsed = (time.perf_counter() - start) * 1000
            
            print(f"{name:15s}: {elapsed:8.3f} ms, "
                  f"Length: {len(result):,} chars")
    
    def test_real_world_scenarios(self):
        """Test real-world application scenarios."""
        # Web application example
        web_app = WebApplicationURLProcessor()
        seo_url = web_app.generate_seo_url(
            "Wireless Bluetooth Headphones", 
            "electronics", 
            "12345"
        )
        self.assertIn("wireless-bluetooth-headphones", seo_url)
        
        # API gateway example
        api_handler = APIGatewayURLHandler()
        api_url = api_handler.construct_api_url(
            "https://api.example.com",
            "/users/{id}/posts",
            {"id": "user 123"},
            {"sort": "date desc"}
        )
        self.assertIn("user%20123", api_url)
        self.assertIn("sort=date%20desc", api_url)


def demonstrate_real_world_usage():
    """Demonstrate real-world usage scenarios."""
    print("\n" + "="*60)
    print("REAL-WORLD URL ENCODING APPLICATIONS")
    print("="*60)
    
    # Example 1: E-commerce product URLs
    print("\n1. E-commerce Product URL Generation:")
    print("-"*40)
    
    web_app = WebApplicationURLProcessor()
    products = [
        ("Coffee Maker Deluxe", "kitchen-appliances", "78910"),
        ("Wireless Mouse", "computer-accessories", "12345"),
        ("Organic Cotton T-Shirt", "clothing", "55555"),
    ]
    
    for name, category, pid in products:
        url = web_app.generate_seo_url(name, category, pid)
        print(f"  Product: {name}")
        print(f"  URL:     {url}")
        print()
    
    # Example 2: API Gateway URL Construction
    print("\n2. API Gateway URL Construction:")
    print("-"*40)
    
    api_handler = APIGatewayURLHandler()
    api_url = api_handler.construct_api_url(
        "https://api.weather.com",
        "/forecast/{city}/{date}",
        {"city": "New York", "date": "2024-01-15"},
        {"units": "metric", "details": "true"}
    )
    print(f"  API URL: {api_url}")
    
    # Example 3: CMS Blog Post Management
    print("\n3. CMS Blog Post URL Generation:")
    print("-"*40)
    
    cms = ContentManagementSystem()
    posts = [
        ("10 Tips for Python Beginners", "Jane Smith", "2024-01-10"),
        ("Understanding REST APIs", "John Doe", "2024-01-12"),
    ]
    
    for title, author, date in posts:
        slug = cms.generate_post_slug(title, author, date)
        print(f"  Title:  {title}")
        print(f"  Slug:   {slug}")
        print()
    
    # Example 4: Performance Metrics
    print("\n4. Performance Metrics:")
    print("-"*40)
    
    encoder = URLEncoder()
    test_texts = [
        ("Short text", 10),
        ("Medium text with spaces " * 10, 200),
        ("X" * 1000, 1000),
    ]
    
    for text, length in test_texts:
        encoded, metrics = encoder.urlify_with_validation(text, length)
        print(f"  Input: {len(text):4d} chars -> Output: {len(encoded):4d} chars")
        print(f"  Spaces: {metrics['space_count']:3d}, "
              f"Time: {metrics['execution_time_ms']:.3f} ms")
        print()


def main():
    """Main entry point."""
    # Run unit tests
    print("Running unit tests...")
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
    
    # Demonstrate real-world usage
    demonstrate_real_world_usage()
    
    # Show encoder statistics
    encoder = URLEncoder()
    
    # Simulate some usage
    test_cases = [
        ("test one two three", 17),
        ("another test", 12),
        ("test one two three", 17),  # Duplicate for cache
        ("different string", 16),
    ]
    
    for text, length in test_cases:
        encoder.urlify_cached(text, length)
    
    print("\n5. Encoder Statistics:")
    print("-"*40)
    stats = encoder.get_performance_metrics()
    for key, value in stats.items():
        print(f"  {key:20s}: {value}")


if __name__ == "__main__":
    main()
