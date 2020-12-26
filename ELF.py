class ELF():

    def __init__(self, ELF_file):
        self.ELF_file = ELF_file
        self.validate()
        self.header = self.parse_magick()  # ELF_HEADER
        self.e = self.header.endiannes
        self.addition_info = self.get_addition_info()
        print(self.addition_info)

    def validate(self):
        if self.ELF_file.read(4) != b'\x7fELF':
            raise Exception('File is not ELF!')

    def parse_magick(self):
        magick_number = self.ELF_file.read(16)

        _class = "ELF64" if magick_number[0] == 2 else "ELF32"  # real offset here is +4
        endianness = "little" if magick_number[1] == 1 else "big"
        version = magick_number[2]
        os_list = {
            0: "System V",
            1: "HP-UX",
            2: "NetBSD",
            3: "Linux",
            4: "GNU Hurd",
            5: "¯\\_(ツ)_/¯",
            6: "Solaris",
            7: "AIX",
            8: "IRIX",
            9: "FreeBSD",
            10: "Tru64",
            11: "Novell Modesto",
            12: "OpenBSD",
            13: "OpenVMS",
            14: "NonStop Kernel",
            15: "AROS",
            16: "Fenix OS",
            17: "CloudABI",
            18: "Stratus Technologies OpenVOS"
        }
        OS = os_list.get(magick_number[3], 0)
        ABI_version = magick_number[4]
        # unused = magick_number[5:11]
        obj_filetype_list = {
            b'\x00': "ET_NONE",
            b'\x01': "ET_REL",
            b'\x02': "ET_EXEC",
            b'\x03': "ET_DYN",
            b'\x04': "ET_CORE",
            b'\xFE00': "ET_LOOS",
            b'\xFEFF': "ET_HIOS",
            b'\xFF00': "ET_LOPROC",
            b'\xFFFF': "ET_HIPROC",
        }
        obj_filetype = obj_filetype_list.get(magick_number[12:13])
        machine_list = {
            b'\x00': "¯\\_(ツ)_/¯",
            b'\x03': "x86",
            b'\x3E': "amd64"
            # and much more
        }
        machine = machine_list.get(magick_number[14:15])
        return ELF_HEADER(_class, endianness, version, OS, ABI_version, obj_filetype, machine)

    def get_addition_info(self):
        # real offset here is +20
        additional_info = {"e_version": self.ELF_file.read(4),
                           "e_entry": int.from_bytes(self.ELF_file.read(8), self.e),
                           "e_phoff": int.from_bytes(self.ELF_file.read(8), self.e),
                           "e_shoff": int.from_bytes(self.ELF_file.read(8), self.e),
                           "e_flags": int.from_bytes(self.ELF_file.read(4), self.e),
                           "e_ehsize": int.from_bytes(self.ELF_file.read(2), self.e),
                           "e_phentsize": int.from_bytes(self.ELF_file.read(2), self.e),
                           "e_phnum": int.from_bytes(self.ELF_file.read(2), self.e),
                           "e_shentsize": int.from_bytes(self.ELF_file.read(2), self.e),
                           "e_shnum": int.from_bytes(self.ELF_file.read(2), self.e),
                           "e_shstrndx": int.from_bytes(self.ELF_file.read(2), self.e),
                           }
        return additional_info

    def get_sections_info(self):
        sections = []
        self.ELF_file.seek(self.addition_info["e_shoff"], 0)
        sections_offset = self.ELF_file.read()
        sections_table_name_offset_index = self.addition_info["e_shstrndx"] * self.addition_info["e_shentsize"] + \
                                           self.addition_info["e_shoff"]
        self.ELF_file.seek(sections_table_name_offset_index + 24, 0)
        sections_table_name_offset = int.from_bytes(self.ELF_file.read(8), self.e)
        sections_table_name_size = int.from_bytes(self.ELF_file.read(8), self.e)
        self.ELF_file.seek(sections_table_name_offset, 0)
        section_names = str(self.ELF_file.read(sections_table_name_size)).split("\\x00")[1:-1]

        for i in section_names:
            sections.append(Section(sections_offset, i))

        print(sections)

        # print(sections_table_name_offset)
        # print(sections_offset)
        # b_sections = self.addition_info["e_shnum"] * self.addition_info["e_ehsize"]
        # print(self.ELF_file.read(self.addition_info["e_shentsize"]))
        # sections = self.ELF_file.read(self.addition_info["e_shentsize"])
        # print(sections)


class ELF_HEADER:
    def __init__(self, _class, _endiannes, _version, _os, _abi, _obj_filetype, _machine):
        self._class = _class  # ELF64 or ELF32
        self.endiannes = _endiannes
        self.version = _version
        self.os = _os
        self.abi = _abi
        self.obj_filetype = _obj_filetype
        self.machine = _machine

    def __str__(self):
        fields = ["Class", "Data", "Version", "OS/ABI", "ABI version", "Type", "Machine"]
        values = [self._class, self.endiannes, self.version, self.os, self.abi, self.obj_filetype, self.machine]
        string = ""
        for i in range(len(fields)):
            string += fields[i] + ": " + str(values[i]) + '\n'
        return string


class Section:
    sh_type = {0: "SHT_NULL",
               1: "SHT_PROGBITS",
               2: "SHT_SYMTAB",
               3: "SHT_STRTAB",
               4: "SHT_RELA",
               5: "SHT_HASH",
               6: "SHT_DYNAMIC",
               7: "SHT_NOTE",
               8: "SHT_NOBITS",
               9: "SHT_REL",
               10: "SHT_SHLIB",
               11: "SHT_DYNSYM",
               14: "SHT_INIT_ARRAY",
               15: "SHT_FINI_ARRAY",
               16: "SHT_PREINIT_ARRAY",
               17: "SHT_GROUP",
               18: "SHT_SYMTAB_SHNDX"}

    sh_flags = {b'0x1': "SHF_WRITE",
                b'0x2': "SHF_ALLOC",
                b'0x4': "SHF_EXECINSTR",
                b'0x10': "SHF_MERGE",
                b'0x20': "SHF_STRINGS",
                b'0x40': "SHF_INFO_LINK",
                b'0x80': "SHF_LINK_ORDER",
                b'0x100': "SHF_OS_NONCONFORMING",
                b'0x200': "SHF_GROUP",
                b'0x400': "SHF_TLS",
                b'0x800': "SHF_COMPRESSED",
                b'0x0ff00000': "SHF_MASKOS",
                b'0xf0000000': "SHF_MASKPROC",
                }

    def __init__(self, bytes_array, sh_name):
        self.sh_name = sh_name
        self.sh_type = bytes_array(4)
        self.sh_flags = bytes_array(8)
        self.sh_addr = bytes_array(8)
        self.sh_offset = bytes_array(8)
        self.sh_size = bytes_array(8)
        self.sh_link = bytes_array(4)
        self.sh_info = bytes_array(4)
        self.sh_addralign = bytes_array(8)
        self.sh_entsize = bytes_array(8)
