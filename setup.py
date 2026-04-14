from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="akha-scanner",
    version="1.0.0",
    author="AKHA Security",
    author_email="caneraktas12@gmail.com",
    description="AKHA-XSS Detection Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/akha-security/akha-xss",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "browser": [
            "playwright>=1.40.0",
            "selenium>=4.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "akha-xss=akha.__main__:_entry",
        ],
    },
    include_package_data=True,
    package_data={
        "akha": [
            "reports/templates/*.html",
            "reports/templates/assets/*.css",
            "reports/templates/assets/*.js",
            "data/wordlists/*.txt",
            "data/learning/*.json",
        ],
    },
)
