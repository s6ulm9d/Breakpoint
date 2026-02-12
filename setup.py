from setuptools import setup, find_packages

setup(
    name="breakpoint",
    version="3.0.0-ELITE",
    description="BREAKPOINT: Weaponized Resilience Engine",
    author="soulmad",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
        "colorama>=0.4.6",
        "playwright>=1.48.0",
        "docker>=7.0.0",
        "temporalio>=1.6.0",
        "sarif-om>=1.0.4",
        "openai>=1.40.0",
        "anthropic>=0.30.0",
        "tree-sitter>=0.21.3",
    ],
    entry_points={
        "console_scripts": [
            "breakpoint=breakpoint.cli:main", 
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        "breakpoint": ["*.yaml"],
    },
)
