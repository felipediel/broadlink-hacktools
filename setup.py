from setuptools import find_packages, setup


with open("README.md", 'r') as f:
    long_description = f.read()

setup(
    name='broadlinkhacktools',
    version='0.0.1',
    description='Tools for hacking the Broadlink protocol.',
    license="MIT",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Felipe Martins Diel',
    author_email='felipemartinsdiel@gmail.com',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=['beautifultable>=0.8', 'cryptography>=2.8']
)
