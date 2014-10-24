check_archives recursively and using available CPU cores verifies the integrity of various archive, image, and document formats.

To run check_archives, one runs check_archives.py. If one desires .7z support, py7zlib.py should be placed in the same directory or otherwise in Python's import path.

check_archives depends on https://pypi.python.org/pypi/Pillow to verify images.