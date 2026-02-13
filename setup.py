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
        "questionary>=2.0.1",
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
