from setuptools import setup


with open("README.md", 'r') as f:
    long_description = f.read()

setup(
   name='broadlinkhacktools',
   version='0.1',
   description='Tools for hacking the Broadlink protocol.',
   license="MIT",
   long_description=long_description,
   author='Felipe Martins Diel',
   author_email='felipemartinsdiel@gmail.com',
   packages=['broadlinkhacktools'],
   install_requires=['beautifultable', 'cryptography']
)
