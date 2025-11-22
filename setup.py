#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARTIS - Autonomous Red Teaming Integrated System
Setup script for installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="artis",
    version="0.1.0",
    description="Autonomous Red Teaming Integrated System - A Kali Linux command-line tool for automated penetration testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ARTIS Development Team",
    author_email="",
    url="https://github.com/yourusername/artis",
    license="MIT",
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    
    # Dependencies
    install_requires=requirements,
    python_requires=">=3.8",
    
    # Entry points for CLI
    entry_points={
        'console_scripts': [
            'artis=artis.cli.parser:main',
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    
    # Additional metadata
    keywords="penetration-testing red-team security kali-linux automation vulnerability-scanning exploitation",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/artis/issues",
        "Source": "https://github.com/yourusername/artis",
    },
)
