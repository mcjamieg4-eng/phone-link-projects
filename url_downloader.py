#!/usr/bin/env python3
"""
APK URL Downloader
Downloads APKs from direct URLs
"""

import os
import requests
import time
from urllib.parse import urlparse

class APKDownloader:
    def __init__(self, download_dir="downloads"):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)

    def download_apk_from_url(self, url):
        """Download APK from a direct URL"""
        try:
            if not self._is_valid_url(url):
                return None, "Invalid URL format"

            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)

            if not filename.endswith('.apk'):
                filename = f"downloaded_app_{int(time.time())}.apk"

            output_path = os.path.join(self.download_dir, filename)

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = requests.get(url, headers=headers, stream=True, timeout=30)
            response.raise_for_status()

            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            if not self._verify_apk_file(output_path):
                os.remove(output_path)
                return None, "Downloaded file is not a valid APK"

            file_size = os.path.getsize(output_path)
            return output_path, f"APK downloaded successfully ({file_size / (1024*1024):.2f} MB)"

        except Exception as e:
            return None, f"Error downloading APK: {str(e)}"

    def _is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def _verify_apk_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                signature = f.read(2)
                return signature == b'PK'
        except:
            return False
