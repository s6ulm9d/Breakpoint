from setuptools import setup, find_packages

setup(
    name="breakpoint",
    version="2.7.1",
    description="BREAKPOINT: Weaponized Resilience Engine",
    author="soulmad",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pyyaml",
        "colorama",
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
