# This is called to patch the zipfile source code.
# Once stdlib has support for dependency injection, this should no longer
# be needed.
import shutil
import site
import os

site.getsitepackages()[0]

# Create the site package dir.
os.makedirs(os.path.join(site.getsitepackages()[0], "zipfile_patched"), exist_ok=True)

# Copy the manually patched version.
destination = os.path.join(site.getsitepackages()[0], "zipfile_patched", "__init__.py")
shutil.copyfile("src/zipfile_stdlib_patched.py", destination)
