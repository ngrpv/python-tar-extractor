#!/usr/bin/env python3

import argparse
import os.path
import sys
from struct import unpack
from typing import NamedTuple, Optional
from datetime import datetime
from math import ceil


class FileHeader(NamedTuple):
    file_name: str
    access_mod: str
    user_id: int
    group_id: int
    size: int
    last_mod_time: datetime
    check_sum: str
    file_type: str
    link_name: str
    magic: Optional[str] = None
    version: Optional[str] = None
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    dev_major: Optional[str] = None
    dev_minor: Optional[str] = None
    prefix: Optional[str] = None
    other: Optional[str] = None


def read(file, block_num):
    with open(file, 'rb') as f:
        f.seek(512 * block_num)
        return f.read(512)


class TarParser:
    _HEADER_FMT1 = '100s8s8s8s12s12s8sc100s255s'
    _HEADER_FMT2 = '6s2s32s32s8s8s155s12s'
    _HEADER_FMT3 = '6s2s32s32s8s8s12s12s112s31x'
    _READ_BLOCK = 16 * 2 ** 20
    _BLOCK_SIZE = 512
    _NULL_BLOCK = bytes(512)

    _FILE_TYPES = {
        b'0': 'Regular file',
        b'1': 'Hard link',
        b'2': 'Symbolic link',
        b'3': 'Character device node',
        b'4': 'Block device node',
        b'5': 'Directory',
        b'6': 'FIFO node',
        b'7': 'Reserved',
        b'D': 'Directory entry',
        b'K': 'Long linkname',
        b'L': 'Long pathname',
        b'M': 'Continue of last file',
        b'N': 'Rename/symlink command',
        b'S': "`sparse' regular file",
        b'V': "`name' is tape/volume header name"
    }

    def __init__(self, filename):
        """
        Открывает tar-архив `filename' и производит его предобработку
        (если требуется)
        """
        self._filename = filename
        self._file_to_position = {}

    def get_names(self):
        was_first_zero_block = False
        with open(self._filename, 'rb') as f:
            long_link_name = None
            for i in range(1000):
                block = f.read(self._BLOCK_SIZE)
                if block == self._NULL_BLOCK or block == b'':
                    if was_first_zero_block or block == b'':
                        return
                    else:
                        was_first_zero_block = True
                        continue
                else:
                    was_first_zero_block = False
                if block[156:157] == b'L':
                    long_link_name = f.read(self._BLOCK_SIZE).strip(
                        b'\x00').decode()
                    continue
                if long_link_name:
                    self._file_to_position[
                        long_link_name] = f.tell() - self._BLOCK_SIZE
                    yield long_link_name
                    long_link_name = None
                else:
                    filename = block[0:100].strip(b'\x00').decode()
                    self._file_to_position[
                        filename] = f.tell() - self._BLOCK_SIZE
                    yield filename
                size = int(block[124:136].strip(b'\x00').decode(), 8)
                f.seek(f.tell() + ceil(
                    size / self._BLOCK_SIZE) * self._BLOCK_SIZE)

    def unpack_second_part(self, header):
        if header[-1].startswith(b'ustar '):
            second_part = unpack(self._HEADER_FMT2, header[-1])
        else:
            second_part = unpack(self._HEADER_FMT3, header[-1])
        return header[:-1] + second_part

    def get_file_data(self, start_byte, filename):
        with(open(self._filename, 'rb')) as f:
            f.seek(start_byte)
            block = f.read(self._BLOCK_SIZE)
            header = self.unpack_second_part(unpack(self._HEADER_FMT1, block))
            decoded_header = [i.strip(b'\x00').decode() for i in header]
            decoded_header = self.decode_to_int_from_octal(header,
                                                           decoded_header,
                                                           1, 2, 3, 4, 5)
            decoded_header[5] = datetime.fromtimestamp(decoded_header[5])
            decoded_header[7] = self._FILE_TYPES[header[7]]
            decoded_header[0] = filename
            return FileHeader(*decoded_header)

    def get_file_bytes(self, file_data: FileHeader):
        start = self._file_to_position[file_data.file_name] + self._BLOCK_SIZE
        with open(self._filename, 'rb') as f:
            f.seek(start)
            return f.read(file_data.size)

    @staticmethod
    def decode_to_int_from_octal(header, decoded_header, *indexes):
        for i in indexes:
            if i > len(header):
                return
            decoded_header[i] = int(header[i].strip(b'\x00'), 8)
        return decoded_header

    def extract(self, dest=os.getcwd()):
        """
        Распаковывает данный tar-архив в каталог `dest'
        """
        for file in self.files():
            start = self._file_to_position[file]
            data = self.get_file_data(start, file)
            if data.file_type == 'Directory':
                if not os.path.exists(dest + '/' + data.file_name):
                    os.mkdir(dest + '/' + data.file_name)
            elif data.file_type == 'Regular file':
                if not os.path.exists(dest + '/' + data.file_name):
                    with open(dest + '/' + data.file_name, 'xb') as f:
                        f.write(self.get_file_bytes(data))
                else:
                    with open(dest + '/' + data.file_name, 'wb') as f:
                        f.write(self.get_file_bytes(data))

    def files(self):
        """
        Возвращает итератор имён файлов (с путями) в архиве
        """
        yield from self.get_names()
        return

    def file_stat(self, filename):
        """
        Возвращает информацию о файле `filename' в архиве.

        Пример (некоторые поля могут отсутствовать, подробности см. в описании
        формата tar):
        [
            ('Filename', '/NSimulator'),
            ('Type', 'Directory'),
            ('Mode', '0000755'),
            ('UID', '1000'),
            ('GID', '1000'),
            ('Size', '0'),
            ('Modification time', '29 Mar 2014 03:52:45'),
            ('Checksum', '5492'),
            ('User name', 'victor'),
            ('Group name', 'victor')
        ]
        """
        data = self.get_file_data(self._file_to_position[filename], filename)
        info = [('Filename', data.file_name, self._file_to_position),
                ('Type', data.file_type),
                ('Mode', data.access_mod),
                ('UID', data.user_id),
                ('GID', data.group_id),
                ('Size', data.size),
                ('Modification time', data.last_mod_time),
                ('Checksum', data.check_sum),
                ('User name', data.user_name),
                ('Group name', data.group_name)]

        return info


def print_file_info(stat, f=sys.stdout):
    max_width = max(map(lambda s: len(s[0]), stat))
    for field in stat:
        print("{{:>{}}} : {{}}".format(max_width).format(*field), file=f)


def main():
    parser = argparse.ArgumentParser(
        usage='{} [OPTIONS] FILE'.format(os.path.basename(sys.argv[0])),
        description='Tar extractor')
    parser.add_argument('-l', '--list', action='store_true', dest='ls',
                        help='list the contents of an archive')
    parser.add_argument('-x', '--extract', action='store_true', dest='extract',
                        help='extract files from an archive')
    parser.add_argument('-i', '--info', action='store_true', dest='info',
                        help='get information about files in an archive')
    parser.add_argument('fn', metavar='FILE',
                        help='name of an archive')

    args = parser.parse_args()
    if not (args.ls or args.extract or args.info):
        sys.exit("Error: action must be specified")

    try:
        tar = TarParser(args.fn)

        if args.info:
            for fn in sorted(tar.files()):
                print_file_info(tar.file_stat(fn))
                print()
        elif args.ls:
            for fn in sorted(tar.files()):
                print(fn)

        if args.extract:
            tar.extract()
    except Exception as e:
        sys.exit(e)


if __name__ == '__main__':
    main()

    