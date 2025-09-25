#!/usr/bin/env python3
"""
Ultimate APK Suite
Comprehensive APK analysis and manipulation
"""

import os
import asyncio
import time
from real_apk_toolkit import APKToolkit
from bypass_generator import BypassGenerator
from root_detector import RootDetector
from enhanced_analyzer import EnhancedAnalyzer
from url_downloader import APKDownloader

class UltimateAPKSuite:
    def __init__(self):
        self.java_path = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.8.9-hotspot\bin\java.exe"
        self.apktool_path = r"C:\Users\jamie\CrossDevice\Pixel 7a\storage\Download\APK.Tool.GUI.v3.3.1.6\Resources\apktool.jar"
        self.toolkit = APKToolkit(self.java_path, self.apktool_path)
        self.generator = BypassGenerator()
        self.root_detector = RootDetector()
        self.enhanced_analyzer = EnhancedAnalyzer()
        self.downloader = APKDownloader()

    async def ultimate_analysis(self, apk_path, analysis_type="complete"):
        """Perform comprehensive APK analysis"""
        try:
            results = {
                'summary': {},
                'recommendations': [],
                'analysis_type': analysis_type,
                'timestamp': int(time.time())
            }

            # Basic APK info
            info, msg = self.toolkit.get_apk_info(apk_path)
            if info:
                results['summary']['apk_size_mb'] = info['size_mb']
                results['summary']['file_count'] = info['file_count']

            # Decompile
            output_dir = apk_path.replace('.apk', '_ultimate_analysis')
            success, msg = self.toolkit.decompile_apk(apk_path, output_dir)

            if success:
                # Find purchase methods
                methods, msg = self.toolkit.find_purchase_methods(output_dir)
                results['summary']['purchase_methods'] = len(methods)

                # Root detection
                root_detections, msg = self.root_detector.detect_root_methods(output_dir)
                results['summary']['root_detections'] = len(root_detections)

                # Enhanced analysis
                enhanced, msg = self.enhanced_analyzer.complete_apk_analysis(apk_path, output_dir)
                if enhanced:
                    results['summary']['security_score'] = enhanced.get('security_score', 0)
                    results['summary']['complexity_assessment'] = enhanced.get('complexity', 'unknown')

                # Count classes and methods
                total_classes = 0
                total_methods = 0
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith('.smali'):
                            total_classes += 1
                            # Count methods in file
                            try:
                                with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    total_methods += content.count('.method ')
                            except:
                                pass

                results['summary']['total_classes'] = total_classes
                results['summary']['total_methods'] = total_methods
                results['summary']['bypasses_generated'] = len(methods) + len(root_detections)

                # Generate recommendations
                if len(methods) > 0:
                    results['recommendations'].append({
                        'priority': 'high',
                        'title': 'Purchase Validation Bypass Available',
                        'description': f'Found {len(methods)} purchase validation methods that can be bypassed',
                        'action': 'Generate and apply bypass patches'
                    })

                if len(root_detections) > 0:
                    results['recommendations'].append({
                        'priority': 'medium',
                        'title': 'Root Detection Methods Found',
                        'description': f'Detected {len(root_detections)} root detection mechanisms',
                        'action': 'Apply root detection bypasses'
                    })

            return results

        except Exception as e:
            return {'error': str(e), 'analysis_type': analysis_type}

    async def download_and_analyze(self, url):
        """Download APK from URL and perform ultimate analysis"""
        try:
            # Download APK
            apk_path, msg = self.downloader.download_apk_from_url(url)
            if not apk_path:
                return {'error': msg}

            # Perform ultimate analysis
            results = await self.ultimate_analysis(apk_path, "download_and_analyze")
            results['download_info'] = {
                'url': url,
                'local_path': apk_path,
                'download_message': msg
            }

            return results

        except Exception as e:
            return {'error': str(e)}