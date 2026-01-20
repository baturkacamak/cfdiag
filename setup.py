from setuptools import setup

setup(
    name="cfdiag",
    version="2.7.0",
    description="A professional-grade diagnostic tool for Cloudflare and connectivity issues.",
    author="Batur Kacamak",
    author_email="batur@example.com",
    url="https://github.com/baturkacamak/cfdiag",
    py_modules=["cfdiag"],
    entry_points={
        "console_scripts": [
            "cfdiag=cfdiag:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.6",
)
