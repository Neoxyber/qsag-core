from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="qsag-core",
    version="0.1.6",
    description="Open source AI agent security toolkit — MCP poisoning scanner, ghost detection, prompt injection patterns",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="AIXYBER TECH LTD (trading as Neoxyber)",
    author_email="contact@neoxyber.com",
    url="https://github.com/Neoxyber/qsag-core",
    packages=find_packages(),
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    keywords="ai-agents mcp security owasp prompt-injection tool-poisoning ghost-agent quantum governance",
)
