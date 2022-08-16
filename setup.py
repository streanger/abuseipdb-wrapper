import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()
    
setuptools.setup(
    name='abuseipdb-wrapper',
    version='0.1.3',
    keywords="abuseipdb abuse ip",
    author="streanger",
    author_email="divisionexe@gmail.com",
    description="python wrapper for abuseipdb API",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/streanger/abuseipdb-wrapper",
    packages=['abuseipdb-wrapper', ],
    python_requires=">=3.5",
    license='MIT',
    install_requires=['requests', 'rich', 'pandas', 'openpyxl', 'Jinja2'],
    include_package_data=False,
    package_data={
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
    },
)
