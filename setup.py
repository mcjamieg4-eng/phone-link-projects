#!/usr/bin/env python3
"""
Setup script for APK Reverse Engineering Toolkit
"""

from setuptools import setup, find_packages

setup(
    name="apk-reverse-toolkit",
    version="1.0.0",
    description="Professional APK reverse engineering and bypass toolkit",
    author="APK Toolkit",
    packages=find_packages(),
    install_requires=[
        "Flask>=2.3.3",
        "pathlib2>=2.3.7",
        "Werkzeug>=2.3.7"
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'apk-toolkit=main:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
