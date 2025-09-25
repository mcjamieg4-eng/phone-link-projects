#!/usr/bin/env python3
"""
Enhanced APK Analyzer
Provides detailed analysis of APK structure and security
"""

import os
import zipfile
import hashlib

class EnhancedAnalyzer:
    def __init__(self):
        pass

    def complete_apk_analysis(self, apk_path, decompiled_dir):
        try:
            analysis = {
                'security_score': self._calculate_security_score(decompiled_dir),
                'complexity': self._assess_complexity(decompiled_dir),
                'permissions': self._analyze_permissions(decompiled_dir),
                'obfuscation': self._detect_obfuscation(decompiled_dir)
            }
            return analysis, "Enhanced analysis completed"
        except Exception as e:
            return {}, f"Enhanced analysis failed: {str(e)}"

    def _calculate_security_score(self, decompiled_dir):
        # Simple scoring based on file count and structure
        try:
            total_files = sum([len(files) for r, d, files in os.walk(decompiled_dir)])
            if total_files > 1000:
                return 8
            elif total_files > 500:
                return 6
            else:
                return 4
        except:
            return 3

    def _assess_complexity(self, decompiled_dir):
        try:
            smali_count = 0
            for root, dirs, files in os.walk(decompiled_dir):
                smali_count += len([f for f in files if f.endswith('.smali')])

            if smali_count > 500:
                return "high"
            elif smali_count > 100:
                return "medium"
            else:
                return "low"
        except:
            return "unknown"

    def _analyze_permissions(self, decompiled_dir):
        try:
            manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    return len([line for line in content.split('\n') if 'uses-permission' in line])
            return 0
        except:
            return 0

    def _detect_obfuscation(self, decompiled_dir):
        try:
            obfuscated_files = 0
            for root, dirs, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith('.smali') and len(file) < 5:
                        obfuscated_files += 1
            return obfuscated_files > 10
        except:
            return False