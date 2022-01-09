#!/usr/bin/env python

"""This is a hash function that is applied to the remainder of
a file or standard input after removing the desired number
of bytes from the beginning.
    For example, if there is some kind of header data attached to
the binary data, you may want to remove it and get the hash
value of the content.
"""


import hashlib


class skiphash(object):

    def __init__(self, func, head, num):
        self.head = head
        self.num = num
        self.bulkread_size = 1 * 1024 * 1024
        # self.bulkread_size = 100 * 1024 * 1024
        self.outputlength = None
        if func is None:
            self.hashobj = hashlib.sha1()
        else:
            self.hashobj = eval("hashlib.{}()".format(func))
        if func == "shake_128" or func == "shake_256":
            self.outputlength = 16

    def _calc(self):
        if self.outputlength is None:
            dig = self.hashobj.digest()
        else:
            dig = self.hashobj.digest(self.outputlength)
        return dig

    def _process_byte(self, data):
        head = self.head
        if self.num < 0:
            self.num = len(data) - head
        last = head + self.num
        # print("head:", head, "last:", last)
        self.hashobj.update(data[head:last])
        return self._calc()

    def _process_file(self, data):
        with open(data, "rb") as f:
            filesize = f.seek(0, 2)
            if filesize < self.bulkread_size:
                f.seek(0)
                rawdata = f.read()
                # print("go onmemory")
                return self._process_byte(rawdata)
            if self.head > filesize:
                raise Exception("head size is too large for the file size.")
            if self.num < 0:
                self.num = filesize - self.head  # rest of all file.
            if self.head + self.num > filesize:
                raise Exception("head + num exceededs the file size.")
            f.seek(self.head)
            chunksize = 1024 if self.num > 1024 else self.num
            readsize = 0
            # print("chunksize: ", chunksize)
            while readsize < self.num:
                source = f.read(chunksize)
                srclen = len(source)
                # print("srclen: ", srclen)
                self.hashobj.update(source)
                readsize += srclen
                if self.num - readsize < chunksize:
                    chunksize = self.num - readsize
                if self.num - readsize == 0:
                    break
            return self._calc()
        return b""

    def digest(self, data):
        """
        calc digest of data.
        whree data is bytes or 'filename'.
        """
        if type(data) == bytes:
            return self._process_byte(data)
        if type(data) == str:
            return self._process_file(data)
        else:
            raise Exception("unknown type")
        return 0


def printhex(data):
    for x in data:
        print("{:02x}".format(x), end="")
    print("\n")


def converthex(data):
    str_ = ""
    for x in data:
        str_ += "{:02x}".format(x)
    return str_


if __name__ == "__main__":
    import sys
    import getopt
    import pathlib

    _usage = """Usage: {} [-f hashfunc] [-h head_skipsize] [-n calc_num] file ...
    -f hashfunc     : hash function name. default is sha1
            md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s,
            sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.
        are available. the default is sha1. output length is only 16 for
        shake_128 and shake_256.
    -h head_skipsize: data head address(bytes).
    -n calc_num     : byte num for calculating the hash.
                      if num < 0, use all data.

        ex)
          skiphash.py -f sha1 -h 10 -n 1000 some.data.file"""

    option = {"f": "sha1", "h": 0, "n": -1}

    if len(sys.argv) < 2:
        print(_usage.format(pathlib.os.path.basename(sys.argv[0])))
        sys.exit(1)

    try:
        opt, argv = getopt.getopt(sys.argv[1:], "f:h:n:")
        for o, v in opt:
            if o == "-f":
                option[o[1:]] = v
            elif o == "-h" or o == "-n":
                option[o[1:]] = int(v)
    except Exception as e:
        print("Error:", e)
        print(_usage.format(pathlib.os.path.basename(sys.argv[0])))
        sys.exit(1)

    files = argv
    # print(option)
    # print(files)

    use_file = True
    if use_file:
        m = skiphash(option["f"], option["h"], option["n"])
        for file in files:
            digest = m.digest(file)
            print(converthex(digest) + "  " + file)

    # for test
    use_byte = False
    if use_byte:
        m = skiphash(option["f"], option["h"], option["n"])
        for file in files:
            with open(file, "rb") as f:
                rawdata = f.read()
                digest = m.digest(rawdata)
                printhex(digest)
