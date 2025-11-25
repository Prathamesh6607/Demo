import requests
import json
import logging
import sqlite3
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)

@dataclass
class CVE:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    last_modified: str
    vendors: List[str]
    products: List[str]
    references: List[str]

class CVELookup:
    def __init__(self, db_path: str = "iot_devices.db"):
        self.db_path = db_path
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_duration = timedelta(hours=24)  # Cache for 24 hours
        self._init_database()
        
    def _init_database(self):
        """Initialize CVE cache database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                search_terms TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_search_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                search_terms TEXT,
                results_count INTEGER,
                search_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def search_cves(self, search_terms: List[str], vendor: str = "", product: str = "") -> List[CVE]:
        """
        Search for CVEs using multiple strategies
        """
        all_cves = []
        
        for term in search_terms:
            if not term.strip():
                continue
                
            # Try exact product search first
            cves = self._search_nvd_with_fallback(term, vendor, product)
            all_cves.extend(cves)
            
            # Also try vendor + product combination
            if vendor and product:
                combined_term = f"{vendor} {product}"
                if combined_term not in search_terms:
                    combined_cves = self._search_nvd_with_fallback(combined_term, vendor, product)
                    all_cves.extend(combined_cves)
        
        # Remove duplicates and return
        unique_cves = {cve.cve_id: cve for cve in all_cves}.values()
        return list(unique_cves)

    def _search_nvd_with_fallback(self, search_term: str, vendor: str = "", product: str = "") -> List[CVE]:
        """
        Search NVD API with fallback to cached results
        """
        # Check cache first
        cached_cves = self._get_cached_cves(search_term)
        if cached_cves:
            logger.info(f"Using cached CVEs for: {search_term}")
            return cached_cves
        
        try:
            # Search NVD API
            cves = self._search_nvd_api(search_term, vendor, product)
            
            # Cache the results
            self._cache_cves(search_term, cves)
            
            # Log search
            self._log_search(search_term, len(cves))
            
            return cves
            
        except Exception as e:
            logger.error(f"NVD API search failed for '{search_term}': {e}")
            # Return empty list if API fails
            return []

    def _search_nvd_api(self, search_term: str, vendor: str = "", product: str = "") -> List[CVE]:
        """
        Search NVD API for CVEs
        """
        cves = []
        
        try:
            # Build search parameters
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 50
            }
            
            if vendor:
                params['vendor'] = vendor
            
            headers = {
                'User-Agent': 'IoT-Security-Scanner/1.0 (https://github.com/iot-scanner)',
                'Accept': 'application/json'
            }
            
            response = requests.get(
                self.nvd_api_base,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data, search_term)
            elif response.status_code == 403:
                logger.warning("NVD API rate limit exceeded, using cached data")
            else:
                logger.warning(f"NVD API returned status {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning("NVD API request timed out")
        except Exception as e:
            logger.error(f"NVD API request failed: {e}")
        
        return cves

    def _parse_nvd_response(self, nvd_data: Dict[str, Any], search_term: str) -> List[CVE]:
        """
        Parse NVD API response into CVE objects
        """
        cves = []
        
        if 'vulnerabilities' not in nvd_data:
            return cves
        
        for vuln in nvd_data['vulnerabilities']:
            cve_item = vuln.get('cve', {})
            
            # Extract basic CVE information
            cve_id = cve_item.get('id', '')
            descriptions = cve_item.get('descriptions', [])
            description = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No description available')
            
            # Extract metrics and CVSS score
            metrics = cve_item.get('metrics', {})
            cvss_score, severity = self._extract_cvss_metrics(metrics)
            
            # Extract dates
            published = cve_item.get('published', '')
            last_modified = cve_item.get('lastModified', '')
            
            # Extract vendors and products
            vendors, products = self._extract_vendors_products(cve_item)
            
            # Extract references
            references = cve_item.get('references', [])
            reference_urls = [ref.get('url', '') for ref in references]
            
            cve = CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published,
                last_modified=last_modified,
                vendors=vendors,
                products=products,
                references=reference_urls
            )
            
            cves.append(cve)
        
        return cves

    def _extract_cvss_metrics(self, metrics: Dict[str, Any]) -> tuple[float, str]:
        """
        Extract CVSS score and severity from metrics
        """
        cvss_score = 0.0
        severity = "UNKNOWN"
        
        # Try CVSS v3.1 first
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = metrics['cvssMetricV31'][0].get('baseSeverity', 'UNKNOWN')
        # Fall back to CVSS v3.0
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = metrics['cvssMetricV30'][0].get('baseSeverity', 'UNKNOWN')
        # Fall back to CVSS v2.0
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            # Convert v2 score to severity
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        
        return cvss_score, severity

    def _extract_vendors_products(self, cve_item: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """
        Extract vendors and products from CVE item
        """
        vendors = []
        products = []
        
        configurations = cve_item.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    cpe_uri = cpe_match.get('criteria', '')
                    # Parse CPE URI to extract vendor and product
                    cpe_parts = cpe_uri.split(':')
                    if len(cpe_parts) >= 5:
                        vendor = cpe_parts[3]
                        product = cpe_parts[4]
                        if vendor and vendor != '*' and vendor not in vendors:
                            vendors.append(vendor)
                        if product and product != '*' and product not in products:
                            products.append(product)
        
        return vendors, products

    def _get_cached_cves(self, search_term: str) -> List[CVE]:
        """
        Retrieve cached CVEs for search term
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = (datetime.now() - self.cache_duration).isoformat()
            
            cursor.execute('''
                SELECT data FROM cve_cache 
                WHERE search_terms = ? AND last_updated > ?
            ''', (search_term, cutoff_time))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                cve_data = json.loads(row[0])
                return [CVE(**cve_dict) for cve_dict in cve_data]
            
        except Exception as e:
            logger.error(f"Error retrieving cached CVEs: {e}")
        
        return []

    def _cache_cves(self, search_term: str, cves: List[CVE]):
        """
        Cache CVE search results
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cve_data = json.dumps([cve.__dict__ for cve in cves])
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_cache 
                (cve_id, data, search_terms, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (f"search_{hash(search_term)}", cve_data, search_term, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error caching CVEs: {e}")

    def _log_search(self, search_term: str, results_count: int):
        """
        Log search activity
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO cve_search_history 
                (search_terms, results_count)
                VALUES (?, ?)
            ''', (search_term, results_count))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging search: {e}")

    def get_cve_by_id(self, cve_id: str) -> Optional[CVE]:
        """
        Get specific CVE by ID
        """
        # Check cache first
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT data FROM cve_cache WHERE cve_id = ?', (cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                cve_data = json.loads(row[0])[0]  # Single CVE
                return CVE(**cve_data)
                
        except Exception as e:
            logger.error(f"Error retrieving CVE from cache: {e}")
        
        # Fetch from NVD if not in cache
        try:
            headers = {
                'User-Agent': 'IoT-Security-Scanner/1.0',
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f"{self.nvd_api_base}?cveId={cve_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data, cve_id)
                if cves:
                    # Cache the result
                    self._cache_cves(cve_id, cves)
                    return cves[0]
                    
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
        
        return None

    def search_iot_specific_cves(self, device_info: Dict[str, Any]) -> List[CVE]:
        """
        Search for IoT-specific CVEs based on device information
        """
        search_terms = []
        
        manufacturer = device_info.get('manufacturer', '')
        device_type = device_info.get('device_type', '')
        model = device_info.get('device_model', '')
        firmware = device_info.get('firmware_version', '')
        
        # Generate comprehensive search terms
        if manufacturer and device_type:
            search_terms.append(f"{manufacturer} {device_type}")
        
        if manufacturer and model:
            search_terms.append(f"{manufacturer} {model}")
        
        if model:
            search_terms.append(model)
        
        if device_type:
            search_terms.append(f"{device_type} vulnerability")
            search_terms.append(f"IoT {device_type}")
        
        # Add firmware-specific searches if available
        if firmware and firmware != "Unknown":
            if manufacturer:
                search_terms.append(f"{manufacturer} {firmware}")
            if model:
                search_terms.append(f"{model} {firmware}")
        
        # Add general IoT security terms
        search_terms.extend([
            "IoT security",
            "smart device vulnerability",
            "connected device security"
        ])
        
        return self.search_cves(search_terms, manufacturer, model)

    def get_cve_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about CVE searches and cache
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get cache statistics
            cursor.execute('SELECT COUNT(*) FROM cve_cache')
            cache_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT search_terms) FROM cve_cache')
            unique_searches = cursor.fetchone()[0]
            
            # Get search history statistics
            cursor.execute('SELECT COUNT(*) FROM cve_search_history')
            total_searches = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(results_count) FROM cve_search_history')
            avg_results = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'cache_entries': cache_count,
                'unique_searches': unique_searches,
                'total_searches': total_searches,
                'average_results_per_search': round(avg_results, 2),
                'cache_size_mb': self._get_cache_size()
            }
            
        except Exception as e:
            logger.error(f"Error getting CVE statistics: {e}")
            return {}

    def _get_cache_size(self) -> float:
        """Get cache database size in MB"""
        try:
            import os
            size_bytes = os.path.getsize(self.db_path)
            return round(size_bytes / (1024 * 1024), 2)
        except:
            return 0.0

    def clear_old_cache(self, older_than_days: int = 30) -> int:
        """
        Clear cache entries older than specified days
        Returns number of entries cleared
        """
        try:
            cutoff_time = (datetime.now() - timedelta(days=older_than_days)).isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM cve_cache WHERE last_updated < ?', (cutoff_time,))
            count_before = cursor.fetchone()[0]
            
            cursor.execute('DELETE FROM cve_cache WHERE last_updated < ?', (cutoff_time,))
            
            conn.commit()
            conn.close()
            
            return count_before
            
        except Exception as e:
            logger.error(f"Error clearing old cache: {e}")
            return 0

    def export_cve_data(self, format_type: str = "json") -> Optional[str]:
        """
        Export CVE cache data
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT cve_id, data, search_terms FROM cve_cache')
            rows = cursor.fetchall()
            conn.close()
            
            cve_data = []
            for row in rows:
                cve_id, data, search_terms = row
                cves = json.loads(data)
                for cve in cves:
                    cve_data.append({
                        'cve_id': cve_id,
                        'search_terms': search_terms,
                        'cve_details': cve
                    })
            
            if format_type == "json":
                return json.dumps(cve_data, indent=2)
            elif format_type == "csv":
                # Simple CSV export
                import io
                output = io.StringIO()
                output.write("CVE_ID,Search_Terms,Description,CVSS_Score,Severity\n")
                for item in cve_data:
                    cve = item['cve_details']
                    output.write(f"\"{item['cve_id']}\",\"{item['search_terms']}\",\"{cve['description']}\",{cve['cvss_score']},\"{cve['severity']}\"\n")
                return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error exporting CVE data: {e}")
        
        return None