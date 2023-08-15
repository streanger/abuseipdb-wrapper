import setuptools
from pathlib import Path

# requirements: pip install requests rich pandas openpyxl Jinja2 keyring pwinput
long_description = Path("README.rst").read_text()
requirements = Path('requirements.txt').read_text().splitlines()
version_path = Path(__file__).parent / "abuseipdb_wrapper/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setuptools.setup(
    name='abuseipdb-wrapper',
    version=version_info['__version__'],
    keywords="abuseipdb abuse ip",
    author="streanger",
    author_email="divisionexe@gmail.com",
    description="python wrapper for abuseipdb API",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/streanger/abuseipdb-wrapper",
    packages=['abuseipdb_wrapper', ],
    python_requires=">=3.7",
    license='MIT',
    install_requires=requirements,
    include_package_data=False,
    package_data={
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "abuse=abuseipdb_wrapper:main",
        ]
    },
)
