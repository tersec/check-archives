#!/usr/bin/env python3

def read_until_end(fh):
	# handles fileobj-like objects
	# Designed to pass through most file reading errors
	# so caller can catch them.
	try:
		while len(fh.read(1024**2*16)) > 0: pass
	except EOFError:
		pass
	return

def external_handler(*args):
	from subprocess import Popen, PIPE
	ext = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False)

	# Without this, some external programs hang on .wait()
	ext.stdin.close()
	read_until_end(ext.stdout)
	read_until_end(ext.stderr)

	return ext.wait() == 0

class BuiltinHandler:
	def present(self):
		return True

	def __call__(self, filename):
		return self.handler_fn(filename)

	def __init__(self, handler_fn):
		self.handler_fn = handler_fn

class ExternalHandler:
	def present(self):
		# Assume when called without arguments, the external programs don't do
		# anything harmful.
		if self.cached_presence:
			return self.cached_presence

		# Otherwise try,.
		try:
			external_handler(self.program_name)
			self.cached_presence = True
		except OSError:
			print(self.program_name)
			assert False
			self.cached_presence = False
		return self.cached_presence

	def __call__(self, filename):
		return self.handler_fn(filename)

	def __init__(self, program_name, *parameters):
		# Assumes that the filename can be last argument
		self.handler_fn = lambda filename:external_handler(*([program_name] + list(parameters) + [filename]))
		self.cached_presence = None
		self.program_name = program_name

def zip_handler(filename):
	# Encrypted .zip handling purportedly exists. For now, fail.
	# http://mail.python.org/pipermail/python-checkins/2007-February/058579.html
	# http://mail.python.org/pipermail/patches/2007-February/021638.html
	from zipfile import ZipFile
	try:
		return ZipFile(filename).testzip() == None
	except:
		return False

def bzip2_handler(filename):
	from bz2 import BZ2File
	try:
		read_until_end(BZ2File(filename, 'rb'))
	except:
		return False
	return True

def gzip_handler(filename):
	from gzip import GzipFile
	try:
		read_until_end(GzipFile(filename, 'rb'))
	except:
		return False
	return True

def xz_handler(filename):
	from lzma import LZMAFile
	try:
		read_until_end(LZMAFile(filename, 'rb'))
	except:
		return False
	return True

def _7z_handler(filename):
	from py7zlib import Archive7z
	try:
		return Archive7z(filename).test7z()
	except:
		return False

def pil_handler(filename):
	from PIL import Image
	try:
		Image.open(filename).load()
	except:
		return False
	return True

def reverse_index(handler_map):
	handlers = {}
	for handler, extensions in handler_map:
		for extension in extensions:
			handlers[extension] = handler
	return handlers

def get_file_handlers():
	return reverse_index({
		BuiltinHandler(zip_handler):
			['.zip', '.odt', '.ods', '.odp', '.odg', '.docx', '.xlsx', '.pptx', '.jar', '.apk', '.cbz', '.epub', '.xpi'],
		BuiltinHandler(gzip_handler): ['.gz', '.tgz'],
		BuiltinHandler(bzip2_handler): ['.bz2', '.tbz'],
		BuiltinHandler(xz_handler): ['.xz', '.txz'],
		BuiltinHandler(_7z_handler): ['.7z'],
		ExternalHandler("unrar", "t", "-inul"): ['.rar'],
		# "Can't identify TIF with mode=CMYK": https://github.com/python-imaging/Pillow/issues/257
		BuiltinHandler(pil_handler): ['.png', '.jpg', '.gif']
	}.items())

# Only one copy should exist, so that the presence caching
# actually functions.
file_handlers = get_file_handlers()

def get_file_handler(filename):
	from os.path import splitext
	return file_handlers.get(splitext(filename)[1].lower(), None)

def check_file_integrity(lock_filename_pair):
	from os import access, R_OK
	_, filename = lock_filename_pair
	handler = get_file_handler(filename)
	# Handler-not-found ==> succeed.
	correct = \
	    not access(filename, R_OK) or \
	    not handler or \
	    not handler.present() or \
	    handler(filename)
	return filename, correct


### No console output occurs above here.
def get_available_columns():
	from shutil import get_terminal_size
	return get_terminal_size(fallback=(72, 24)).columns-len(': fail ')

def elide_path(path):
	# Preserve useful beginning and end of path
	delim, max_len = '~', get_available_columns()
	half_len = (max_len - len(delim))//2
	if len(path) > max_len:
		return '%s%s%s'%(path[:half_len], delim, path[-half_len:])
	else:
		return path

def display_file_integrity(lock_filename_pair):
	from sys import stdout
	lock, filename = lock_filename_pair
	filename, correct = check_file_integrity(lock_filename_pair)
	padding = ' '*(get_available_columns() - len(filename))
	lock.acquire()
	if correct:
		stdout.write('\r%s: ok  %s'%(elide_path(filename), padding))
	else:
		# Need to pad to wipe out rest of previous 'ok' lines
		stdout.write('\r%s: fail%s\n'%(filename, padding))
	lock.release()

	# multiprocessing pools only function with top-level functions because those can be pickled
	return filename, correct

def filter_names_with_sizes(dir_, names):
	# Derive file sizes from stat(...), but filter out file entirely
	# if stat(...) throws an OSError, such as in the case of a broken
	# symlink.
	from os import stat
	from os.path import join
	names_with_sizes = []
	for filename in names:
		path = join(dir_, filename)
		try:
			names_with_sizes.append((path, stat(path)[6]))
		except OSError:
			# Move on to next filename, but don't include this one.
			pass
	return dict(names_with_sizes)

def search_dir(root, check_fn):
	from multiprocessing import Pool, cpu_count
	from multiprocessing import Manager
	from os import walk
	total, checked, succeeded, t_bytes, c_bytes, s_bytes = 0, 0, 0, 0, 0, 0

	with Manager() as m:
		workers = Pool(processes = cpu_count())

		for dir_, dirs, files in walk(root):
			annotated_names = filter_names_with_sizes(dir_, files)
			get_byte_sum = lambda _:sum(map(lambda __:annotated_names[__], _))

			handled_names = [_ for _ in annotated_names.keys()
					 if (lambda __:__ and __.present())(get_file_handler(_))]
			succeeded_names = [_[0]
						 for _ in map(check_fn, zip([m.Lock()]*len(handled_names),
										    handled_names))
						 if _[1]]

			succeeded += len(succeeded_names)
			s_bytes += get_byte_sum(succeeded_names)
			total += len(annotated_names)
			t_bytes += get_byte_sum(annotated_names)
			checked += len(handled_names)
			c_bytes += get_byte_sum(handled_names)

	return total, checked, succeeded, t_bytes, c_bytes, s_bytes

def cmdline_parser():
	from optparse import OptionParser
	parser = OptionParser(usage='usage %prog [options] [scan_directory]', version="%prog 0.4")
	# parser.add_option('-v', action='store_true', dest='verbose', help='display progress')
	parser.add_option('-q', action='store_false', dest='verbose', help='produce no output', default=True)

	(options, args) = parser.parse_args()
	return options.verbose, args

def main():
	from sys import stdout
	verbose, args = cmdline_parser()
	t, c, s, t_bytes, c_bytes, s_bytes = search_dir(args[0] if args != [] else '.',
							display_file_integrity if verbose else check_file_integrity)
	if verbose:
		# TODO: this message lies (can get here even w/ failures)
		# avoid division by zero.
		stdout.write('\r%s\n'%('all ok; tested %2.2f%% (%d of %d) of available files and %2.2f%% of available data'
				       %(s*100.0/(t+1), s, t, s_bytes*100.0/(t_bytes+1)) if s==c else
				       'failed%s'%(' '*(get_available_columns()-6))))
	return not (s==c)

if __name__ == '__main__':
	from sys import exit

	# For multiprocessing on Win32
	from multiprocessing import freeze_support
	freeze_support()

	exit(main())
