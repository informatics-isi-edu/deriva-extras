#
# Copyright 2020 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from setuptools import setup, find_packages, find_namespace_packages

url = "https://github.com/informatics-isi-edu/deriva-extras"
author = 'USC Information Sciences Institute, Informatics Systems Research Division'
author_email = 'isrd-support@isi.edu'

setup(
    name='deriva-extras',
    description='DERIVA extra modules',
    version='0.1',
    url=url,
    author=author,
    author_email=author_email,
    maintainer=author,
    maintainer_email=author_email,
    #package_dir={"": "deriva"},
    # this exclude list not supported by ubuntu (python 3.8): list(setuptools.discovery.FlatLayoutPackageFinder.DEFAULT_EXCLUDE)    
    packages=find_namespace_packages(
        include=[
            "deriva.utils.extras",
            "deriva.utils.extras.*",                        
        ],
        exclude= ["build", "*.tests.*", "*.tmp.*", "__pycache__", "deriva.utils.extras.tmp"]
    ),
    package_data={},
    python_requires='>=3.8, <4',    
#    entry_points={
#        'console_scripts': [
#            'atlas_d2k-imaging-server = atlas_d2k.pipelines.image_processing.server:main',
#        ]
#    },
    # move all image processing to requires if downloading lots of dependencies is a concern. 
    install_requires=[
        'deriva>1.5.0',
    ],
    license='Apache 2.0',
    classifiers=[
        'Intended Audience :: Science/Research',        
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12'
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
