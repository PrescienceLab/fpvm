"""Manage shelves of pickled objects.

A "shelf" is a persistent, dictionary-like object.  The difference
with dbm databases is that the values (not the keys!) in a shelf can
be essentially arbitrary Python objects -- anything that the "pickle"
module can handle.  This includes most class instances, recursive data
types, and objects containing lots of shared sub-objects.  The keys
are ordinary strings.

To summarize the interface (key is a string, data is an arbitrary
object):

        import shelve
        d = shelve.open(filename) # open, with (g)dbm filename -- no suffix

        d[key] = data   # store data at key (overwrites old data if
                        # using an existing key)
        data = d[key]   # retrieve a COPY of the data at key (raise
                        # KeyError if no such key) -- NOTE that this
                        # access returns a *copy* of the entry!
        del d[key]      # delete data stored at key (raises KeyError
                        # if no such key)
        flag = key in d # true if the key exists
        list = d.keys() # a list of all existing keys (slow!)

        d.close()       # close it

Dependent on the implementation, closing a persistent dictionary may
or may not be necessary to flush changes to disk.

Normally, d[key] returns a COPY of the entry.  This needs care when
mutable entries are mutated: for example, if d[key] is a list,
        d[key].append(anitem)
does NOT modify the entry d[key] itself, as stored in the persistent
mapping -- it only modifies the copy, which is then immediately
discarded, so that the append has NO effect whatsoever.  To append an
item to d[key] in a way that will affect the persistent mapping, use:
        data = d[key]
        data.append(anitem)
        d[key] = data

To avoid the problem with mutable entries, you may pass the keyword
argument writeback=True in the call to shelve.open.  When you use:
        d = shelve.open(filename, writeback=True)
then d keeps a cache of all entries you access, and writes them all back
to the persistent mapping when you call d.close().  This ensures that
such usage as d[key].append(anitem) works as intended.

However, using keyword argument writeback=True may consume vast amount
of memory for the cache, and it may make d.close() very slow, if you
access many of d's entries after opening it in this way: d has no way to
check which of the entries you access are mutable and/or which ones you
actually mutate, so it must cache, and write back at close, all of the
entries that you access.  You can call d.sync() to write back all the
entries in the cache, and empty the cache (d.sync() also synchronizes
the persistent dictionary on disk, if feasible).
"""

from pickle import Pickler, Unpickler
from io import BytesIO
import collections.abc
import os

__all__ = ["Shelf", "BsdDbShelf", "DbfilenameShelf", "open"]


class _ClosedDict(collections.abc.MutableMapping):
    "Marker for a closed dict.  Access attempts raise a ValueError."

    def closed(self, *args):
        raise ValueError("invalid operation on closed shelf")

    __iter__ = __len__ = __getitem__ = __setitem__ = __delitem__ = keys = closed

    def __repr__(self):
        return "<Closed Dictionary>"


import threading

LOCK = threading.Lock()


def pickle_and_write(items, dict, protocol, keyencoding, debug):
    _pickled = {}
    if len(items) == 0 or items is None:
        return

    for key, entry in items:
        f = BytesIO()
        p = Pickler(f, protocol)
        p.dump(entry)
        ready = f.getvalue()
        _pickled[key] = ready

    LOCK.acquire(True)  # blocking acquire
    # got lock
    for key, entry in _pickled.items():
        dict[key] = entry
        if debug:
            print("size in bytes", len(entry))

    LOCK.release()
    return


class Shelf(collections.abc.MutableMapping):
    """Base class for shelf implementations.

    This is initialized with a dictionary-like object.
    See the module's __doc__ string for an overview of the interface.
    """

    def __init__(
        self,
        dict,
        protocol=None,
        writeback=False,
        loadback=False,
        debug=False,
        buffer=0,
        mode="c",
        keyencoding="utf-8",
    ):

        self.dict = dict
        self.keys = set()
        if protocol is None:
            protocol = 3
        self._protocol = protocol
        self.writeback = writeback
        self.loadback = loadback
        self.debug = debug
        self.cache = {}
        self.keyencoding = keyencoding
        self.buffer = buffer
        self.mode = mode

    def __iter__(self):
        for k in self.keys:
            yield k

    def __len__(self):
        return len(self.keys)

    def __contains__(self, key):
        return key in self.keys
        # return key in self.cache

    def get(self, key, default=None):
        if key in self.keys:
            return self[key]
        return default

    def __getitem__(self, key):
        try:
            value = self.cache[key]
        except KeyError:
            f = BytesIO(self.dict[key])
            value = Unpickler(f).load()
            if self.loadback:
                if self.buffer > 0 and len(self.cache) > self.buffer:
                    if self.mode != "r":
                        self.sync()  # I assume read only
                    self.cache = {}
                self.cache[key] = value

        return value

    def __setitem__(self, key, value):
        # if self.writeback:
        self.cache[key] = value

        self.keys.add(key)

        # f = BytesIO()
        # p = Pickler(f, self._protocol)
        # p.dump(value)
        # self.dict[key] = f.getvalue()

    def __delitem__(self, key):
        # del self.dict[key]
        try:
            self.keys.remove(key)
        except KeyError as e:
            # print("keys error", e)
            pass
        try:
            del self.cache[key]
        except KeyError as e:
            # print("Cache key error", e)
            pass

        try:
            del self.dict[key]
        except KeyError as e:
            print("Dict Key error", e)
            exit()
            # self.dict.pop(key)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.dict is None:
            return
        try:
            if self.mode != "r":
                self.sync()
            try:
                self.dict.sync()
                self.dict.close()
            except AttributeError:
                pass

        finally:
            # Catch errors that may happen when close is called from __del__
            # because CPython is in interpreter shutdown.
            try:
                self.dict = _ClosedDict()
            except:
                self.dict = None

    def __del__(self):
        if not hasattr(self, "writeback"):
            # __init__ didn't succeed, so don't bother closing
            # see http://bugs.python.org/issue1339007 for details
            return
        self.close()

    def sync(self):
        if self.writeback and self.cache:

            # parallelize this one

            # N = 16 #os.cpu_count()
            # all = list(self.cache.items())
            # chunk = int(len(all)/N)+1
            # size = len(all)
            # # print(f"parallel save each with {chunk}")
            # threads = [ threading.Thread(target=pickle_and_write, args=( list(all[i*chunk: min(size, (i+1)*chunk)]), self.dict, self._protocol, self.keyencoding, self.debug))  for i in range(N) if i*chunk < size]

            # for thread in threads:
            #     thread.start()

            # for thread in threads:
            #     thread.join()

            # print(f"parallel save done")

            for c, (key, entry) in enumerate(self.cache.items()):
                f = BytesIO()
                p = Pickler(f, self._protocol)
                p.dump(entry)
                self.dict[key] = f.getvalue()
                if self.debug:
                    print(c, len(f.getvalue()))
                # self.dict[key] = entry
                # self[key] = entry
            self.cache = {}

        # if hasattr(self.dict, 'sync'):
        #     self.dict.sync()


class DbfilenameShelf(Shelf):
    """Shelf implementation using the "dbm" generic dbm interface.

    This is initialized with the filename for the dbm database.
    See the module's __doc__ string for an overview of the interface.
    """

    def __init__(
        self,
        filename,
        flag="c",
        protocol=None,
        writeback=False,
        loadback=False,
        debug=False,
        preset_keys=None,
        buffer=0,
    ):
        # print("use berkeleydb")
        # print("use dump db; install libdb-dev to use berkeleydb")
        import dbm

        # import berkeleydb as dbm
        # Shelf.__init__(self, dbm.btopen(filename, flag, cachesize=1*1024*1024*1024), protocol, writeback, loadback, debug, buffer, flag)
        Shelf.__init__(
            self,
            dbm.open(filename, flag),
            protocol,
            writeback,
            loadback,
            debug,
            buffer,
            flag,
        )
        try:
            if preset_keys:
                self.keys = set(preset_keys)
            else:
                self.keys = set(self.dict.keys())
        except:
            pass

        # Shelf.__init__(self, file_archive(filename,serialized=True).archive, protocol, writeback, loadback)


def open(
    filename,
    flag="c",
    protocol=None,
    writeback=False,
    loadback=False,
    debug=False,
    preset_keys=None,
    buffer=0,
):
    """Open a persistent dictionary for reading and writing.

    The filename parameter is the base filename for the underlying
    database.  As a side-effect, an extension may be added to the
    filename and more than one file may be created.  The optional flag
    parameter has the same interpretation as the flag parameter of
    dbm.open(). The optional protocol parameter specifies the
    version of the pickle protocol.

    See the module's __doc__ string for an overview of the interface.
    """

    return DbfilenameShelf(
        filename, flag, protocol, writeback, loadback, debug, preset_keys, buffer
    )
