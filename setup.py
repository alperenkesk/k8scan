from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="k8scan",
    version="1.0.0",
    description="Kubernetes security scanner for detecting misconfigurations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "kubernetes>=29.0.0",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "click>=8.1.7",
        "requests>=2.31.0",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "k8scan=src.cli:cli",
        ],
    },
)
