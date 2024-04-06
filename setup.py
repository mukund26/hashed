from setuptools import setup, find_packages

setup(
    name='hashed',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'your-cli-command=your_project.cli:main',
        ],
    },
    install_requires=[
        # List your dependencies here
    ],
    python_requires='>=3.6',
    author='Mukund Agarwal',
    author_email='m.agarwalhp@gmail.com',
    description='Provides secured hashes for given data',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/your_username/your_project',
    license='MIT',
)
