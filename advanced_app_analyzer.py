#!/usr/bin/env python3
"""
Advanced Application Analyzer for Reverse Engineering
Gets you as close as possible to application replication
"""

import os
import sys
import time
import json
import struct
import hashlib
import subprocess
from pathlib import Path
try:
    import pefile
except ImportError:
    print("⚠️ pefile not installed. Install with: pip install pefile")
    pefile = None

try:
    import requests
except ImportError:
    print("⚠️ requests not installed. Install with: pip install requests")
    requests = None
from collections import defaultdict

class AdvancedAppAnalyzer:
    def __init__(self):
        self.analysis_results = {}
        self.start_time = time.time()
        
    def analyze_application(self, app_path):
        """Comprehensive application analysis for replication"""
        print("🚀 Starting Advanced Application Analysis...")
        print(f"📊 Target: {app_path}")
        print("=" * 60)
        
        if not os.path.exists(app_path):
            print(f"❌ Application not found: {app_path}")
            return None
            
        # Phase 1: Deep Static Analysis
        self.deep_static_analysis(app_path)
        
        # Phase 2: PE Header Analysis
        self.pe_header_analysis(app_path)
        
        # Phase 3: Dependency Mapping
        self.dependency_mapping(app_path)
        
        # Phase 4: Resource Extraction
        self.resource_extraction(app_path)
        
        # Phase 5: String Intelligence
        self.string_intelligence(app_path)
        
        # Phase 6: Framework Detection
        self.framework_detection(app_path)
        
        # Phase 7: Architecture Analysis
        self.architecture_analysis(app_path)
        
        # Phase 8: Replication Assessment
        self.replication_assessment()
        
        return self.analysis_results
    
    def deep_static_analysis(self, app_path):
        """Deep static analysis of the executable"""
        print("🔍 Phase 1: Deep Static Analysis...")
        time.sleep(0.5)  # Simulate processing
        
        file_info = Path(app_path)
        self.analysis_results['basic_info'] = {
            'filename': file_info.name,
            'size_mb': round(file_info.stat().st_size / (1024*1024), 2),
            'creation_time': file_info.stat().st_ctime,
            'modification_time': file_info.stat().st_mtime,
            'file_hash': self.calculate_file_hash(app_path)
        }
        
        # Analyze file entropy (indicates packing/encryption)
        entropy = self.calculate_entropy(app_path)
        self.analysis_results['entropy'] = {
            'value': entropy,
            'assessment': 'High (likely packed)' if entropy > 7.5 else 'Normal'
        }
        
        print(f"  ✅ File size: {self.analysis_results['basic_info']['size_mb']} MB")
        print(f"  ✅ Entropy: {entropy:.2f} ({self.analysis_results['entropy']['assessment']})")
    
    def pe_header_analysis(self, app_path):
        """Analyze PE header for detailed information"""
        print("🔧 Phase 2: PE Header Analysis...")
        time.sleep(0.8)  # Simulate processing
        
        try:
            pe = pefile.PE(app_path)
            
            self.analysis_results['pe_info'] = {
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'sections': len(pe.sections),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem
            }
            
            # Extract imports (critical for replication)
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8'))
                    imports.append({'dll': dll_name, 'functions': functions[:10]})  # Limit for readability
            
            self.analysis_results['imports'] = imports[:20]  # Top 20 DLLs
            
            print(f"  ✅ Machine type: {self.analysis_results['pe_info']['machine_type']}")
            print(f"  ✅ Sections: {self.analysis_results['pe_info']['sections']}")
            print(f"  ✅ Imported DLLs: {len(imports)}")
            
        except Exception as e:
            print(f"  ⚠️ PE analysis failed: {e}")
            self.analysis_results['pe_info'] = {'error': str(e)}
    
    def dependency_mapping(self, app_path):
        """Map all dependencies for replication"""
        print("🔗 Phase 3: Dependency Mapping...")
        time.sleep(1.0)  # Simulate processing
        
        app_dir = Path(app_path).parent
        dependencies = {
            'local_dlls': [],
            'system_dlls': [],
            'missing_dlls': [],
            'total_files': 0
        }
        
        # Scan for local dependencies
        for file in app_dir.rglob('*.dll'):
            dependencies['local_dlls'].append({
                'name': file.name,
                'path': str(file.relative_to(app_dir)),
                'size_kb': round(file.stat().st_size / 1024, 2)
            })
        
        dependencies['total_files'] = len(list(app_dir.rglob('*')))
        self.analysis_results['dependencies'] = dependencies
        
        print(f"  ✅ Local DLLs: {len(dependencies['local_dlls'])}")
        print(f"  ✅ Total files in directory: {dependencies['total_files']}")
    
    def resource_extraction(self, app_path):
        """Extract embedded resources"""
        print("📦 Phase 4: Resource Extraction...")
        time.sleep(0.7)  # Simulate processing
        
        resources = {
            'icons': 0,
            'strings': 0,
            'version_info': {},
            'manifest': None
        }
        
        try:
            pe = pefile.PE(app_path)
            
            # Extract version information
            if hasattr(pe, 'VS_VERSIONINFO'):
                for version_info in pe.VS_VERSIONINFO:
                    if hasattr(version_info, 'StringTable'):
                        for string_table in version_info.StringTable:
                            for entry in string_table.entries.items():
                                key, value = entry
                                resources['version_info'][key.decode('utf-8')] = value.decode('utf-8')
            
            # Count resource types
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'Unknown')
                    
                    if 'ICON' in name:
                        resources['icons'] += len(resource_type.directory.entries)
                    elif 'STRING' in name:
                        resources['strings'] += len(resource_type.directory.entries)
            
        except Exception as e:
            resources['error'] = str(e)
        
        self.analysis_results['resources'] = resources
        print(f"  ✅ Icons found: {resources['icons']}")
        print(f"  ✅ String tables: {resources['strings']}")
        print(f"  ✅ Version info entries: {len(resources['version_info'])}")
    
    def string_intelligence(self, app_path):
        """Intelligent string analysis for replication clues"""
        print("🧠 Phase 5: String Intelligence...")
        time.sleep(1.2)  # Simulate processing
        
        strings_data = {
            'urls': [],
            'file_paths': [],
            'registry_keys': [],
            'error_messages': [],
            'config_keys': [],
            'api_endpoints': []
        }
        
        try:
            with open(app_path, 'rb') as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                content = f.read(chunk_size * 5)  # Read first 5MB
            
            # Convert to string and find patterns
            text = content.decode('utf-8', errors='ignore')
            
            # Extract different types of strings
            import re
            
            # URLs and domains
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
            strings_data['urls'] = list(set(urls))[:10]
            
            # File paths
            paths = re.findall(r'[A-Za-z]:\\[^<>"|?*\s]+|/[^<>"|?*\s]+', text)
            strings_data['file_paths'] = list(set(paths))[:10]
            
            # Registry keys
            reg_keys = re.findall(r'HKEY_[A-Z_]+\\[^<>"|?*\s]+', text)
            strings_data['registry_keys'] = list(set(reg_keys))[:10]
            
            # Error messages
            errors = re.findall(r'[Ee]rror[^.!?]*[.!?]|[Ff]ailed[^.!?]*[.!?]', text)
            strings_data['error_messages'] = list(set(errors))[:5]
            
            # Configuration keys
            configs = re.findall(r'[A-Za-z]+[Cc]onfig|[Ss]ettings?|[Pp]references?', text)
            strings_data['config_keys'] = list(set(configs))[:10]
            
        except Exception as e:
            strings_data['error'] = str(e)
        
        self.analysis_results['strings'] = strings_data
        print(f"  ✅ URLs found: {len(strings_data['urls'])}")
        print(f"  ✅ File paths: {len(strings_data['file_paths'])}")
        print(f"  ✅ Registry keys: {len(strings_data['registry_keys'])}")
    
    def framework_detection(self, app_path):
        """Advanced framework and technology detection"""
        print("🎯 Phase 6: Framework Detection...")
        time.sleep(0.9)  # Simulate processing
        
        frameworks = {
            'detected': [],
            'confidence': {},
            'technologies': []
        }
        
        app_dir = Path(app_path).parent
        all_files = [f.name.lower() for f in app_dir.rglob('*') if f.is_file()]
        file_content = ' '.join(all_files)
        
        # Framework detection patterns
        framework_patterns = {
            'Electron': ['electron', 'chrome', 'node.exe', 'resources.pak'],
            'Qt': ['qt5', 'qt6', 'qtcore', 'qtgui', 'qtwidgets'],
            '.NET': ['clr', 'mscoree', 'mscorlib', 'system.'],
            'Unity': ['unityplayer', 'unity', 'mono'],
            'Unreal': ['ue4', 'ue5', 'unreal'],
            'WPF': ['wpf', 'presentationcore', 'presentationframework'],
            'WinUI': ['winui', 'microsoft.ui'],
            'Tauri': ['tauri', 'webview2'],
            'Flutter': ['flutter', 'dart'],
            'Java': ['java', 'jvm', 'rt.jar'],
            'Python': ['python', 'pythoncom', '_tkinter'],
            'Node.js': ['node.exe', 'v8', 'libuv']
        }
        
        for framework, patterns in framework_patterns.items():
            matches = sum(1 for pattern in patterns if pattern in file_content)
            if matches > 0:
                confidence = min(100, (matches / len(patterns)) * 100)
                frameworks['detected'].append(framework)
                frameworks['confidence'][framework] = round(confidence, 1)
        
        self.analysis_results['frameworks'] = frameworks
        print(f"  ✅ Frameworks detected: {', '.join(frameworks['detected'])}")
    
    def architecture_analysis(self, app_path):
        """Analyze application architecture"""
        print("🏗️ Phase 7: Architecture Analysis...")
        time.sleep(0.6)  # Simulate processing
        
        architecture = {
            'type': 'Unknown',
            'complexity': 'Unknown',
            'deployment': 'Unknown',
            'ui_framework': 'Unknown'
        }
        
        app_dir = Path(app_path).parent
        file_count = len(list(app_dir.rglob('*')))
        dll_count = len(list(app_dir.rglob('*.dll')))
        
        # Determine architecture type
        if file_count < 10:
            architecture['type'] = 'Simple Standalone'
            architecture['complexity'] = 'Low'
        elif file_count < 100:
            architecture['type'] = 'Modular Application'
            architecture['complexity'] = 'Medium'
        else:
            architecture['type'] = 'Complex Enterprise'
            architecture['complexity'] = 'High'
        
        # Deployment analysis
        if dll_count > file_count * 0.3:
            architecture['deployment'] = 'Framework Dependent'
        else:
            architecture['deployment'] = 'Self Contained'
        
        self.analysis_results['architecture'] = architecture
        print(f"  ✅ Type: {architecture['type']}")
        print(f"  ✅ Complexity: {architecture['complexity']}")
    
    def replication_assessment(self):
        """Assess how difficult replication would be"""
        print("🎯 Phase 8: Replication Assessment...")
        time.sleep(0.4)  # Simulate processing
        
        difficulty_score = 0
        factors = []
        
        # Size factor
        size_mb = self.analysis_results['basic_info']['size_mb']
        if size_mb > 100:
            difficulty_score += 3
            factors.append("Large file size")
        elif size_mb > 10:
            difficulty_score += 1
        
        # Entropy factor (packing/obfuscation)
        if self.analysis_results['entropy']['value'] > 7.5:
            difficulty_score += 2
            factors.append("High entropy (likely packed)")
        
        # Framework complexity
        framework_count = len(self.analysis_results['frameworks']['detected'])
        if framework_count > 2:
            difficulty_score += 2
            factors.append("Multiple frameworks")
        elif framework_count == 0:
            difficulty_score += 1
            factors.append("Unknown framework")
        
        # Dependencies
        dll_count = len(self.analysis_results['dependencies']['local_dlls'])
        if dll_count > 20:
            difficulty_score += 2
            factors.append("Many dependencies")
        
        # Assessment
        if difficulty_score <= 2:
            difficulty = "Easy"
            time_estimate = "1-2 weeks"
        elif difficulty_score <= 5:
            difficulty = "Moderate"
            time_estimate = "1-3 months"
        elif difficulty_score <= 8:
            difficulty = "Hard"
            time_estimate = "6-12 months"
        else:
            difficulty = "Extremely Hard"
            time_estimate = "1+ years"
        
        replication = {
            'difficulty': difficulty,
            'score': difficulty_score,
            'time_estimate': time_estimate,
            'factors': factors,
            'recommended_approach': self.get_replication_approach(difficulty_score)
        }
        
        self.analysis_results['replication'] = replication
        
        total_time = round(time.time() - self.start_time, 2)
        
        print(f"  ✅ Difficulty: {difficulty} (Score: {difficulty_score})")
        print(f"  ✅ Time estimate: {time_estimate}")
        print(f"\n🎉 Analysis complete in {total_time} seconds!")
    
    def get_replication_approach(self, score):
        """Get recommended replication approach"""
        if score <= 2:
            return "Direct reverse engineering, simple recreation"
        elif score <= 5:
            return "Framework identification, component-by-component recreation"
        elif score <= 8:
            return "Advanced reverse engineering, dynamic analysis required"
        else:
            return "Professional reverse engineering tools, team effort required"
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()[:16]  # First 16 chars
    
    def calculate_entropy(self, filepath):
        """Calculate file entropy (indicates packing/encryption)"""
        import math
        with open(filepath, 'rb') as f:
            data = f.read(1024 * 1024)  # First 1MB
        
        if not data:
            return 0
        
        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                frequency = count / data_len
                entropy -= frequency * math.log2(frequency)
        
        return entropy

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python advanced_app_analyzer.py <path_to_executable>")
        sys.exit(1)
    
    analyzer = AdvancedAppAnalyzer()
    results = analyzer.analyze_application(sys.argv[1])
    
    if results:
        print("\n" + "="*60)
        print("📊 ANALYSIS SUMMARY")
        print("="*60)
        print(json.dumps(results, indent=2))
