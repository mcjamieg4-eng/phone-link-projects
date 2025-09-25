#!/usr/bin/env python3
"""
Root Detection Scanner
Finds root detection methods in APK files
"""

import os
import re

class RootDetector:
    def __init__(self):
        self.root_patterns = {
            'su_binary_check': [r'which.*su', r'/system/bin/su'],
            'superuser_apps': [r'com.noshufou.android.su', r'eu.chainfire.supersu'],
            'test_keys': [r'test-keys'],
            'build_tags': [r'ro.build.tags']
        }

    def detect_root_methods(self, decompiled_dir):
        try:
            detections = []
            smali_dirs = [d for d in os.listdir(decompiled_dir) if d.startswith('smali')]

            for smali_dir in smali_dirs:
                smali_path = os.path.join(decompiled_dir, smali_dir)
                detections.extend(self._scan_smali_directory(smali_path))

            return detections, f"Found {len(detections)} root detection methods"
        except Exception as e:
            return [], f"Root detection scan failed: {str(e)}"

    def _scan_smali_directory(self, smali_dir):
        detections = []
        for root, dirs, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    detections.extend(self._scan_smali_file(file_path))
        return detections

    def _scan_smali_file(self, file_path):
        detections = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            for detection_type, patterns in self.root_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        detections.append({
                            'type': detection_type,
                            'file': file_path,
                            'pattern': pattern,
                            'severity': 'high' if 'su' in pattern else 'medium',
                            'description': f'Detected {detection_type}'
                        })
        except:
            pass
        return detections