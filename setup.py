from setuptools import setup, find_packages

setup(
    name="cfdiag",
    version="3.12.5",
    description="A professional-grade diagnostic tool for Cloudflare and connectivity issues.",
    author="Batur Kacamak",
    author_email="batur@example.com",
    url="https://github.com/baturkacamak/cfdiag",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "cfdiag=cfdiag.core:main",
        ],
    },
    install_requires=[
        "certifi",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.6",
)