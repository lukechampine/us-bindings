import os
import platform
from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

if platform.system() == "Darwin":
    os.environ['LDFLAGS'] = '-framework Security'

us_extension = Extension(
    name="pyus",
    sources=["pyus.pyx"],
    libraries=["us"],
    library_dirs=["."],
    include_dirs=["."]
)
setup(
    name="pyus",
    ext_modules=cythonize([us_extension])
)
