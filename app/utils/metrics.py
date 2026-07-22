from prometheus_client import Counter, Histogram, Gauge, generate_latest
from typing import Dict
import time

# Metrics
phishing_detected = Counter(
    'phishing_detections_total',
    'Total number of phishing emails detected',
    ['risk_level']
)

analysis_duration = Histogram(
    'email_analysis_duration_seconds',
    'Time spent analyzing emails',
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

active_analyses = Gauge(
    'active_email_analyses',
    'Number of emails currently being analyzed'
)

api_requests = Counter(
    'api_requests_total',
    'Total API requests',
    ['endpoint', 'method', 'status']
)

class MetricsCollector:
    """Collect and expose application metrics."""
    
    @staticmethod
    def record_analysis(result: Dict):
        """Record analysis results."""
        phishing_detected.labels(
            risk_level=result.get('risk_level', 'unknown')
        ).inc()
    
    @staticmethod
    def measure_analysis(func):
        """Decorator to measure analysis duration."""
        def wrapper(*args, **kwargs):
            active_analyses.inc()
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                analysis_duration.observe(duration)
                active_analyses.dec()
        return wrapper
    
    @staticmethod
    def record_api_request(endpoint: str, method: str, status: int):
        """Record API request."""
        api_requests.labels(
            endpoint=endpoint,
            method=method,
            status=str(status)
        ).inc()
    
    @staticmethod
    def get_metrics():
        """Get all metrics."""
        return generate_latest()
