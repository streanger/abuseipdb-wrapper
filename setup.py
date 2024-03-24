import setuptools
from pathlib import Path

long_description = Path("README.rst").read_text()
version_path = Path(__file__).parent / "abuseipdb_wrapper/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

# pip-compile --annotation-style=line requirements.in
# import pprint
# requirements = [
#     item.split()[0].replace('==', '>=')
#     for item in open('requirements.txt').read().splitlines()
#     if 'via -r requirements.in' in item
# ]
# pprint.pprint(requirements)

requirements = [
    'keyring>=24.3.1',
    'openpyxl>=3.1.2',
    'pwinput>=1.0.3',
    'requests>=2.31.0',
    'rich>=13.7.1',
    'tabulate>=0.9.0'
]

setuptools.setup(
    name="abuseipdb-wrapper",
    version=version_info["__version__"],
    keywords="abuseipdb abuse",
    author="streanger",
    author_email="divisionexe@gmail.com",
    description="python wrapper for abuseipdb API",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/streanger/abuseipdb-wrapper",
    packages=["abuseipdb_wrapper",],
    python_requires=">=3.8",
    license="MIT",
    install_requires=requirements,
    include_package_data=False,
    package_data={},
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
