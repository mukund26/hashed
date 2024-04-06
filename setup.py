from setuptools import setup, find_packages

setup(
    name='hashed',
    version='2.1.0',
    packages=find_packages(),
    install_requires=[],
    python_requires='>=3.6',
    author='Mukund Agarwal',
    author_email='m.agarwalhp@gmail.com',
    description='Provides secured hashes for given data',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/mukund26/hashed',
    license='MIT',
    keywords=['python', 'hashing', 'sha256', 'sha512'],
    classifiers= [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
