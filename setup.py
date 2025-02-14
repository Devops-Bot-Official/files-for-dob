from setuptools import setup, find_packages, Extension
from Cython.Build import cythonize
import os

# Define extensions only if the .py file exists
extensions = []
if os.path.exists("dob/cli.py"):  
    extensions.append(Extension("dob.cli", ["dob/cli.py"]))

setup(
    name="dob-cli",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests==2.28.2",
        "cryptography==39.0.0"
    ],
    ext_modules=cythonize(extensions, compiler_directives={"language_level": "3"}) if extensions else [],
    entry_points={
        "console_scripts": [
            "dob=dob.cli:main"
        ]
    },
    author="Dee empire Gmbh",
    description="DOB CLI for remote command execution with persona-based authentication.",
    python_requires=">=3.6",
)
