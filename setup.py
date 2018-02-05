import ast
import re
from os.path import join

from setuptools import find_packages, setup


CLASSIFIERS = [
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: Implementation :: CPython',
    'Programming Language :: Python',
    'Topic :: Software Development',
    'Topic :: Utilities',
]
INSTALL_REQUIRES = [
    'click',
]
TESTS_REQUIRE = [
    'pytest',
]


def get_description():
    with open('README.rst') as fileobj:
        return fileobj.read()


def get_meta():
    meta_re = re.compile(r'^__(?P<name>\w+?)__\s*=\s*(?P<value>.+)$')
    meta_filepath = join('src', 'okita', '__init__.py')
    meta = {}
    with open(meta_filepath) as meta_fileobj:
        for line in meta_fileobj:
            match = meta_re.match(line)
            if not match:
                continue
            meta_name = match.group('name')
            meta_value = ast.literal_eval(match.group('value'))
            meta[meta_name] = meta_value
    return meta


LONG_DESCRIPTION = get_description()
META = get_meta()


setup(
    name=META['name'],
    version=META['version'],
    description=META['description'],
    long_description=LONG_DESCRIPTION,
    author=META['author'],
    author_email=META['email'],
    url=META['uri'],
    package_dir={'': 'src'},
    packages=find_packages('src'),
    entry_points={
        'console_scripts': [
            'okita=okita.__main__:main',
        ],
    },
    install_requires=INSTALL_REQUIRES,
    tests_require=TESTS_REQUIRE,
)