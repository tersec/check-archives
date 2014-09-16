#!/usr/bin/env python3


def get_file_handlers():
    from itertools import chain, repeat
    from lzma import LZMAFile
    from PIL import Image
    from zipfile import ZipFile

    return dict(chain(*(zip(exts, repeat(fn)) for exts, fn in [
        (['.zip', '.odt', '.ods', '.odp', '.odg', '.docx', '.xlsx', '.pptx',
         '.jar', '.apk', '.cbz', '.epub', '.xpi'],
         lambda filename:(ZipFile(filename).testzip() is None)),
        (['.xz', '.txz'],
         lambda filename:(lambda fh:next(filter(lambda _:fh.read(2**24) == b'',
                                                repeat(True))))
                         (LZMAFile(filename, 'rb'))),
        (['.png', '.jpg', '.gif', '.tiff', '.tif'],
         lambda filename:bool(Image.open(filename).load()))
    ])))

file_handlers = get_file_handlers()


def get_file_handler(filename):
    from os.path import splitext
    return file_handlers.get(splitext(filename)[1].lower(), None)

# Until otherwise noted, functions run in multiprocessing
# subprocesses.
FILES_GOOD, FILES_BROKEN, DATA_LEFT, DATA_GOOD, DATA_BROKEN = range(5)


def check_file_intact(lock_filename_pair):
    from os import stat
    _, filename = lock_filename_pair
    handler = get_file_handler(filename)

    try:
        size = stat(filename).st_size

        if not handler:
            return [0, 0, size, 0, 0]
        if handler(filename):
            return [1, 0, 0, size, 0]
        else:
            return [0, 1, 0, 0, size]

    except FileNotFoundError:
        return [0, 0, 0, 0, 0]
    except PermissionError:
        # stat() shouldn't raise this, but still slightly risky
        return [0, 0, size, 0, 0]
    except:
        # Otherwise, assume data error (see else branch above)
        return [0, 1, 0, 0, size]


# No display output above here.
def get_available_columns():
    from shutil import get_terminal_size
    return get_terminal_size(fallback=(72, 24)).columns-len(': fail ')


def elide_path(path):
    # Preserve useful beginning and end of path
    delim, max_len = '~', get_available_columns()
    half_len = (max_len - len(delim))//2
    if len(path) > max_len:
        return '%s%s%s' % (path[:half_len], delim, path[-half_len:])
    else:
        return path


def display_file_intact(lock_filename_pair):
    from sys import stdout
    lock, filename = lock_filename_pair
    padding = ' '*(get_available_columns() - len(filename))

    stats = check_file_intact(lock_filename_pair)
    assert sorted(map(lambda _: stats[_],
                      [DATA_LEFT, DATA_GOOD, DATA_BROKEN]))[:2] == [0, 0]

    lock.acquire()
    if stats[FILES_GOOD] == 1:
        stdout.write('\r%s: ok  %s' % (elide_path(filename), padding))
    elif stats[FILES_BROKEN] == 1:
        # Need to pad to wipe out rest of previous 'ok' lines
        stdout.write('\r%s: fail%s\n' % (filename, padding))
    lock.release()

    # multiprocessing pools only functions with top-level functions
    # because those can be pickled
    return stats


# Remaining functions run in parent multiprocessing process.
def search_dir(root):
    from itertools import chain
    from os import walk
    from os.path import join
    return chain(*[list(map(lambda filename:join(dir_, filename), files))
                   for dir_, _, files in walk(root)])


def check_files(root, check_fn):
    from functools import reduce
    from itertools import repeat
    from multiprocessing import Manager, Pool, cpu_count

    with Manager() as m:
        stats = Pool(cpu_count()).map(check_fn,
                                      zip(repeat(m.Lock()), search_dir(root)))

    return reduce(lambda a, b: [x+y for x, y in zip(a, b)],
                  stats, [0, 0, 0, 0, 0, 0])


def cmdline_parser():
    from optparse import OptionParser
    parser = OptionParser(usage='usage %prog [options] [scan_directory]',
                          version="%prog 0.5")
    parser.add_option('-q', action='store_false', dest='verbose',
                      help='produce no output', default=True)

    (options, args) = parser.parse_args()
    return options.verbose, args


def main():
    from sys import stdout
    verbose, args = cmdline_parser()
    info = check_files(args[0] if args != [] else '.',
                       display_file_intact if verbose else check_file_intact)

    if verbose:
        stdout.write(
            '\r%s\n' % ('all ok; tested %2.2f%% of available data'
                        % (info[DATA_GOOD]*100 /
                           (info[DATA_LEFT]+info[DATA_GOOD]+1))
                        if info[FILES_BROKEN] == 0
                        else 'failed%s' % (' '*(get_available_columns()-6))))
    return info[FILES_BROKEN] != 0

if __name__ == '__main__':
    # For multiprocessing on Win32
    from multiprocessing import freeze_support
    freeze_support()

    from sys import exit
    exit(main())
