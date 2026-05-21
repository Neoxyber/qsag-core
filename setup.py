from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="qsag-core",
    version="0.2.2",
    description="Pattern-based runtime detection for AI-agent attacks: MCP tool poisoning, prompt injection, ghost agents, and related OWASP Agentic risks.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="AIXYBER TECH LTD (trading as Neoxyber)",
    author_email="zaidnaeem@aixybertech.com",
    url="https://github.com/Neoxyber/qsag-core",
    packages=find_packages(),
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="ai-agents mcp security owasp prompt-injection tool-poisoning ghost-agent agentic-security",
    project_urls={
        "Source": "https://github.com/Neoxyber/qsag-core",
        "Issues": "https://github.com/Neoxyber/qsag-core/issues",
    },
)
