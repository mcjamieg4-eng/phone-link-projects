#!/usr/bin/env python3
"""
Real APK Reverse Engineering Toolkit
No fake output, no lies - only verified functionality
"""

import os
import subprocess
import zipfile
import re
import json
import hashlib
from pathlib import Path

class APKToolkit:
    def __init__(self, java_path, apktool_path):
        self.java_path = java_path
        self.apktool_path = apktool_path
        self.working_dir = Path(".")

    def verify_tools(self):
        """Verify Java and APKTool are accessible"""
        try:
            # Test Java
            result = subprocess.run([self.java_path, "-version"],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                return False, "Java not found or not working"

            # Test APKTool
            result = subprocess.run([self.java_path, "-jar", self.apktool_path],
                                  capture_output=True, text=True)
            if "Apktool" not in result.stderr:
                return False, "APKTool not found or not working"

            return True, "Tools verified"
        except Exception as e:
            return False, f"Tool verification failed: {str(e)}"

    def get_apk_info(self, apk_path):
        """Get basic APK information without decompiling"""
        try:
            if not os.path.exists(apk_path):
                return None, "APK file not found"

            # Get file size
            size = os.path.getsize(apk_path)

            # Get file hash
            with open(apk_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Check if it's a valid ZIP (APK is ZIP format)
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    files = zf.namelist()
                    has_manifest = 'AndroidManifest.xml' in files
                    has_classes = any(f.endswith('.dex') for f in files)
            except:
                return None, "Not a valid APK file"

            info = {
                'path': apk_path,
                'size_bytes': size,
                'size_mb': round(size / (1024*1024), 2),
                'sha256': file_hash,
                'has_manifest': has_manifest,
                'has_classes': has_classes,
                'file_count': len(files)
            }

            return info, "APK info extracted"
        except Exception as e:
            return None, f"Failed to get APK info: {str(e)}"

    def decompile_apk(self, apk_path, output_dir):
        """Decompile APK using APKTool"""
        try:
            if not os.path.exists(apk_path):
                return False, "APK file not found"

            # Remove output directory if it exists
            if os.path.exists(output_dir):
                import shutil
                shutil.rmtree(output_dir)

            # Run APKTool decompile
            cmd = [self.java_path, "-jar", self.apktool_path, "d", apk_path, "-o", output_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0 and os.path.exists(output_dir):
                return True, f"APK decompiled to {output_dir}"
            else:
                return False, f"Decompile failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Decompile timed out after 5 minutes"
        except Exception as e:
            return False, f"Decompile error: {str(e)}"

    def find_purchase_methods(self, decompiled_dir):
        """Find potential purchase validation methods in smali files"""
        try:
            purchase_methods = []
            smali_dirs = [d for d in os.listdir(decompiled_dir) if d.startswith('smali')]

            for smali_dir in smali_dirs:
                smali_path = os.path.join(decompiled_dir, smali_dir)
                for root, dirs, files in os.walk(smali_path):
                    for file in files:
                        if file.endswith('.smali'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    content = f.read()

                                # Look for purchase-related methods
                                patterns = [
                                    r'\.method.*verifyPurchase.*',
                                    r'\.method.*checkLicense.*',
                                    r'\.method.*validatePurchase.*',
                                    r'\.method.*isPremium.*',
                                    r'\.method.*checkPremium.*'
                                ]

                                for pattern in patterns:
                                    matches = re.findall(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        purchase_methods.append({
                                            'file': file_path,
                                            'method': match.strip(),
                                            'class': file.replace('.smali', '')
                                        })
                            except:
                                continue

            return purchase_methods, f"Found {len(purchase_methods)} potential purchase methods"
        except Exception as e:
            return [], f"Search failed: {str(e)}"

    def patch_method(self, smali_file, method_name, new_code):
        """Patch a specific method in a smali file"""
        try:
            if not os.path.exists(smali_file):
                return False, "Smali file not found"

            with open(smali_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Find method start and end
            method_pattern = rf'\.method.*{re.escape(method_name)}.*?\.end method'
            match = re.search(method_pattern, content, re.DOTALL | re.IGNORECASE)

            if not match:
                return False, f"Method {method_name} not found"

            # Replace method content
            new_content = content.replace(match.group(0), new_code)

            # Backup original
            backup_file = smali_file + '.backup'
            if not os.path.exists(backup_file):
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(content)

            # Write patched version
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.write(new_content)

            return True, f"Method {method_name} patched successfully"
        except Exception as e:
            return False, f"Patch failed: {str(e)}"

    def rebuild_apk(self, source_dir, output_apk):
        """Rebuild APK from decompiled source"""
        try:
            if not os.path.exists(source_dir):
                return False, "Source directory not found"

            # Remove output file if exists
            if os.path.exists(output_apk):
                os.remove(output_apk)

            # Run APKTool build
            cmd = [self.java_path, "-jar", self.apktool_path, "b", source_dir, "-o", output_apk]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0 and os.path.exists(output_apk):
                size = os.path.getsize(output_apk)
                return True, f"APK rebuilt: {output_apk} ({round(size/(1024*1024), 2)} MB)"
            else:
                return False, f"Rebuild failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Rebuild timed out after 5 minutes"
        except Exception as e:
            return False, f"Rebuild error: {str(e)}"

def main():
    # Configuration
    JAVA_PATH = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.8.9-hotspot\bin\java.exe"
    APKTOOL_PATH = r"C:\Users\jamie\CrossDevice\Pixel 7a\storage\Download\APK.Tool.GUI.v3.3.1.6\Resources\apktool.jar"

    toolkit = APKToolkit(JAVA_PATH, APKTOOL_PATH)

    print("APK Reverse Engineering Toolkit")
    print("=" * 40)

    # Verify tools
    verified, msg = toolkit.verify_tools()
    print(f"Tool verification: {msg}")
    if not verified:
        return

    # Test with Family Guy APK
    apk_path = "Family-Guy.apk"
    if os.path.exists(apk_path):
        print(f"\nAnalyzing {apk_path}...")

        # Get APK info
        info, msg = toolkit.get_apk_info(apk_path)
        if info:
            print(f"APK Size: {info['size_mb']} MB")
            print(f"File Count: {info['file_count']}")
            print(f"SHA256: {info['sha256'][:16]}...")

        # Decompile
        output_dir = "family_guy_decompiled"
        success, msg = toolkit.decompile_apk(apk_path, output_dir)
        print(f"Decompile: {msg}")

        if success:
            # Find purchase methods
            methods, msg = toolkit.find_purchase_methods(output_dir)
            print(f"Purchase methods: {msg}")

            for method in methods[:5]:  # Show first 5
                print(f"  - {method['class']}: {method['method']}")
    else:
        print(f"APK file {apk_path} not found")

if __name__ == "__main__":
    main()
def get_apk_permissions(apk_path):
      """Extract permissions from APK manifest"""
      try:
          # TODO: Implement permission extraction
          return []
      except Exception as e:
          return None