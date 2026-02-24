"""
TFTTool by Max Zuidberg

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""

import sys
import struct
import json
import string
import argparse
import re
from pathlib import Path
from NextionChecksum import Checksum
from NextionInstructionSets import all_instruction_sets

# Disable traceback for Nuitka compiling
if not __debug__:
    sys.tracebacklimit = 0

class pdict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __str__(self):
        return json.dumps(self, indent=4)

def hexStr(raw:bytes):
    return " ".join("{:02X}".format(c) for c in raw)

class Usercode:
    class CodeBlock:
        _operandTypesEncode = {
            "local:":  0x01,
            "global:": 0x05,
            "system:": 0x04,
            "":        0x03, #actual value
        }
        _operandTypesDecode = {v: k for k, v in _operandTypesEncode.items()}

        def __init__(self, instruction_set:dict, rawBlock:bytes, hexVals=True, globalVars=dict(), localVars=dict()):
            self.instruction_set = instruction_set
            self.raw = rawBlock
            self._asHex = hexVals
            self._globalVars = globalVars
            self._localVars  = localVars
            self.decoded = ""
            self._decode(hexVals)

        def _decode(self, hexVals=True):
            if not self.raw:
                self.decoded = "EMPTY_BLOCK"
                return
            else:
                self.decoded = ""
            operation = False
            strActive = False
            escActive = False
            skip = 0
            replaced = False
            # Check if its a (hash) value list
            # Format n * (4-byte-hash + 2-byte-index)
            isList = False
            if len(self.raw) % 6 == 0:
                entries = dict()
                for i in range(0, len(self.raw), 6):
                    value = self.raw[i + 0:i + 4]
                    key   = self.raw[i + 4:i + 6]
                    value = struct.unpack("<I", value)[0]
                    key   = struct.unpack("<H", key)[0]
                    value = self._hexOrNot(value)
                    entries[key] = value
                if (max(entries.keys()) + 1) * 6 == len(self.raw):
                    isList = True
                    for i in range(len(self.raw) // 6):
                        if i not in entries:
                            isList = False
            if isList:
                self.decoded = entries
            else:
                # Search for strings
                stringRegions = set()
                for i, b in enumerate(self.raw):
                    if strActive:
                        stringRegions.add(i)
                        if not escActive:
                            if b == ord("\\"):
                                escActive = True
                            elif b == ord("\""):
                                strActive = not strActive
                        else:
                            escActive = False
                nostrings = b"".join([chr(c).encode() for i, c in enumerate(self.raw) if i not in stringRegions])
                # Search for commands
                for op in self.instruction_set["other_operators"]["unary"]:
                    if op.encode("ascii") in nostrings:
                        operation = True
                        break
                if not operation:
                    for op in self.instruction_set["other_operators"]["binary"]:
                        if op.encode("ascii") in nostrings:
                            operation = True
                            break
                if not operation:
                    jmp = struct.pack("<H", self.instruction_set["other_operators"]["jmp"])
                    if nostrings.startswith(jmp):
                        operation = True
                        skip += len(jmp)
                        self.decoded += "jmp"

                if not operation:
                    if self.raw.startswith(b"\x09"):
                        l = 1
                        if len(self.raw) == 3:
                            operation = True
                        else:
                            l += 2
                        if l < len(self.raw):
                            c = self.raw[l]
                            if c in self._operandTypesDecode.keys() or chr(c) in string.printable:
                                operation = True

                if operation:
                    decoded = False
                    for i, b in enumerate(self.raw):
                        if skip:
                            skip -= 1
                            continue
                        if i not in stringRegions:
                            replaced = True
                            if b == 0x09:
                                localI = i
                                dataStruct = "BB"
                                localI += 1
                                skip = struct.calcsize(dataStruct)
                                op_num, op_size = struct.unpack_from(dataStruct, self.raw, localI)
                                if op_size in self.instruction_set["numerated_operators"]:
                                    op_list = self.instruction_set["numerated_operators"][op_size]
                                    if op_num < len(op_list):
                                        self.decoded += op_list[op_num]
                                        decoded = True
                                if not decoded:
                                    self.decoded += f"op:{op_size}:{self._hexOrNot(op_num)}"
                                if i < len(self.raw) - 1:
                                    self.decoded += " "
                            elif b in self._operandTypesDecode:
                                dataStruct = "<I"
                                skip = struct.calcsize(dataStruct)
                                try:
                                    val = struct.unpack_from(dataStruct, self.raw, i+1)[0]
                                    varLookup = dict()
                                    if b == 1: #local variable
                                        varLookup = self._localVars
                                    elif b == 5: #global variable
                                        varLookup = self._globalVars
                                    elif b == 4: #system variable
                                        # System vars are not 4 byte pointers like local or global vars.
                                        # The lowest byte actually encodes the "class" of the variable.
                                        # Similar to the operator decoding.
                                        sysvar_size = val & 0xff
                                        val >>= 8
                                        if sysvar_size in self.instruction_set["numerated_system_variables"]:
                                            sysvars = self.instruction_set["numerated_system_variables"][sysvar_size]
                                            # TODO not the cleanest solution
                                            if val < len(sysvars):
                                                varLookup = {val: sysvars[val]}
                                    if val not in varLookup:
                                        self.decoded += self._operandTypesDecode[b] + self._hexOrNot(val)
                                    else:
                                        self.decoded += varLookup[val]
                                except:
                                    replaced = False
                            else:
                                replaced = False
                        if not replaced:
                            self.decoded += chr(b)
                else:
                    printable = True
                    for c in self.raw:
                        if chr(c) not in string.printable:
                            printable = False
                            break
                    if printable:
                        self.decoded = self.raw.decode()
                    else:
                        self.decoded = "RAW_DATA: " + hexStr(self.raw)

        def setHex(self, asHex):
            self._asHex = asHex
            self._decode()

        def _hexOrNot(self, val, asHex=-1):
            if asHex == -1:
                asHex = self._asHex
            if asHex:
                return hex(val)
            else:
                return str(val)

        def rawHex(self, raw:bytes):
            return " ".join(["{:02X}".format(c) for c in raw])

        def __repr__(self):
            if len(self.raw) == 0:
                return "EMPTY_BLOCK"
            elif self.decoded:
                return self.decoded
            else:
                return hexStr(self.raw)

    def __init__(self, instruction_set:int, rawUsercode:bytes, hexVals=True):
        self.instruction_set = instruction_set
        self.raw = rawUsercode
        nextBlock = 0
        #self.rawGlobalMem, nextBlock = self._getRawBlock(nextBlock)
        #self.rawPageList, nextBlock  = self._getRawBlock(nextBlock)
        self.blocks = dict()
        while nextBlock <= len(self.raw) - 4:
            currentBlock = nextBlock
            blockSize = struct.unpack_from("<I", self.raw, currentBlock)[0]
            if currentBlock + 4 + blockSize > len(self.raw):
                break  # block size overflows available data
            raw, nextBlock = self._getRawBlock(currentBlock)
            self.blocks[currentBlock] = self.CodeBlock(self.instruction_set, raw)
        #self.pages = dict()
        #for i in range(0, len(self.rawPageList), 6):
        #    value = self.rawPageList[i+0:i+4]
        #    key   = self.rawPageList[i+4:i+6]
        #    value = struct.unpack("<I", value)[0]
        #    key   = struct.unpack("<H", key)[0]
        #    self.pages[key] = value

    def _getRawBlock(self, offset):
        blockSize = struct.unpack_from("<I", self.raw, offset)[0]
        offset += 4
        newOffset = offset + blockSize
        return self.raw[offset:newOffset], newOffset

class HeaderData:
    def __init__(self, raw:bytes, properties:dict, decode_hint:int=0):
        self.size    = properties["size"]
        self.start   = properties["start"]
        self.hasCRC  = properties["hasCRC"]
        self.content = pdict(properties["content"])

        # Read content.
        self._contentStruct = "<" + "".join(v["struct"] for v in self.content.values())
        self._contentSize = struct.calcsize(self._contentStruct)
        self._emptyRegion = self.size - self._contentSize
        if self.hasCRC:
            self._emptyRegion -= 4
        if self._emptyRegion < 0:
            raise Exception("Header size mismatch")
        if len(raw) < self.size:
            raise Exception("raw size smaller than header")

        fullStruct = self._contentStruct + str(self._emptyRegion) + "x"
        if self.hasCRC:
            fullStruct += "I"

        # Now that the structure has been parsed from the content dict, convert it to a flat, "normal" k:v dict and
        # initialize it with the given default values.
        for k, v in self.content.items():
            self.content[k] = v["val"]

        data = raw[self.start: (self.start + self.size)]

        # XOR decoding. By default the key does nothing.
        self.key = bytes(len(raw))
        self.encrypted = False
        if type(decode_hint) is int:
            self.set_key(decode_hint)
            # only decode the part that actually contains encoded data. Copy the rest as-is.
            data = bytes([b ^ self.key[i] for i, b in enumerate(data[:self._contentSize])]) + data[self._contentSize:]
            data = struct.unpack(fullStruct, data)
            for i, k in enumerate(self.content.keys()):
                self.content[k] = data[i]
            if self.hasCRC:
                self.crc = data[-1]
        # (partially) decoded header. In this case we ignore the data from raw.
        elif type(decode_hint) is str:
            # String can be hex data ("01 3a 44 [...]"), a json with values, or a file path to either one.
            # Check if it's a file path. If so, replace the hint with the file content.
            try:
                with open(decode_hint) as f:
                    decode_hint = f.read()
            except OSError:
                pass
            data = None
            # Check if it's a hex string...
            try:
                data = bytes.fromhex(decode_hint)
            except ValueError:
                pass
            if data:
                data = struct.unpack_from(self._contentStruct, data, 0)
                for i, k in enumerate(self.content.keys()):
                    self.content[k] = data[i]
            # ... else check if it's a json string...
            else:
                try:
                    # Double quotes get removed from the CLI if not escaped. Single quotes work, but the json parser
                    # doesn't like them.
                    data = json.loads(decode_hint.replace("\'", "\""))
                except json.decoder.JSONDecodeError:
                    pass
                if data:
                    # Skip all unknown keys.
                    for k, v in data.items():
                        if k in self.content:
                            if type(v) is int:
                                self.content[k] = v
                            else:
                                try:
                                    self.content[k] = int(v, 16)
                                except:
                                    try:
                                        self.content[k] = int(v, 2)
                                    except:
                                        self.content[k] = int(v)

            # Update CRC. This requires serializing the data. Both things are done by getRaw
            # even though we don't use or need the actual raw version of the header.
            self.getRaw()

    def set_key(self, key):
        if type(key) is int:
            if key:
                self.encrypted = True
            else:
                self.encrypted = False
            self.key = struct.pack("<I", key)
            self.key = self.key * (self.size // len(self.key) + 1)
        elif type(key) in (bytes, bytearray):
            self.encrypted = False
            for b in key:
                if b:
                    self.encrypted = True
                    break
            self.key = key
        else:
            raise Exception(f"Key has unknown type: {key} (type: {type(key)})")

    def getRaw(self):
        raw = struct.pack(self._contentStruct, *self.content.values())
        if self.encrypted:
            raw = bytes([b ^ self.key[i] for i, b in enumerate(raw)])
        raw += b"\xff" * self._emptyRegion
        if self.hasCRC:
            self.crc = Checksum().CRC(data=raw)
            raw += struct.pack("<I", self.crc)
        return raw


class TFTFile:

    _nextion_type_names = {
        0x79: "page",           # page
        0x74: "text",           # t
        0x37: "scrolling_text", # g
        0x36: "number",         # n
        0x3B: "xfloat",         # x
        0x62: "button",         # b
        0x35: "dual_state",     # bt
        0x01: "slider",         # h
        0x6A: "progress_bar",   # j
        0x71: "crop",           # q
        0x70: "picture",        # p
        0x00: "waveform",       # s
        0x7A: "gauge",          # z
        0x33: "timer",          # tm
        0x34: "variable",       # va
        0x38: "checkbox",       # c
        0x39: "radio",          # r
        0x6D: "hotspot",        # m
        0x3A: "qrcode",         # qr
        0x05: "touchcap",       # tc
    }

    _modelXORs = {
         "NX3224T024_011": 0x6d713e32,
         "NX3224T028_011": 0x965cdd00,
         "NX4024T032_011": 0x3b91869c,
         "NX4832T035_011": 0xebab2932,
         "NX4827T043_011": 0x1eb276b6,
         "NX8048T050_011": 0x3b66b524,
         "NX8048T070_011": 0xc079789d,

         "NX3224F024_011": 0,
         "NX3224F028_011": 0,
         "NX4832F035_011": 0,

         "NX3224K024_011": 0x1324a9d7,
         "NX3224K028_011": 0xe8094ae5,
         "NX4024K032_011": 0x45c41179,
         "NX4832K035_011": 0x95febed7,
         "NX4827K043_011": 0x60e7e153,
         "NX8048K050_011": 0x453322c1,
         "NX8048K070_011": 0xbe2cef78,

         "NX4827P043_011": 0xcdc7c258,
         "NX8048P050_011": 0xe81301ca,
         "NX8048P070_011": 0x130ccc73,
         "NX1060P070_011": 0x18a58690,
         "NX1060P101_011": 0xdcb511f5,

        "TJC3224T022_011": 0x189a66fb,
        "TJC3224T024_011": 0x54cd4ea3,
        "TJC3224T028_011": 0xafe0ad91,
        "TJC4024T032_011": 0x022df60d,
        "TJC4832T035_011": 0xd21759a3,
        "TJC4827T043_011": 0x270e0627,
        "TJC8048T050_011": 0x02dac5b5,
        "TJC8048T070_011": 0xf9c5080c,

        "TJC1612T118_011": 0,
        "TJC3224T122_011": 0,
        "TJC3224T124_011": 0,
        "TJC3224T128_011": 0,
        "TJC4024T132_011": 0,
        "TJC4832T135_011": 0,

        "TJC3224K022_011": 0x66cff11e,
        "TJC3224K024_011": 0x2a98d946,
        "TJC3224K028_011": 0xd1b53a74,
        "TJC4024K032_011": 0x7c7861e8,
        "TJC4827K043_011": 0x595b91c2,
        "TJC4832K035_011": 0xac42ce46,
        "TJC8048K050_011": 0x7c8f5250,
        "TJC8048K070_011": 0x87909fe9,

        "TJC4848X340_011": 0x9ea280d2,
        "TJC4827X343_011": 0x767c3bae,
        "TJC8048X343_011": 0x5eb5f196,
        "TJC8048X350_011": 0x53a8f83c,
        "TJC8048X370_011": 0xa8b73585,
        "TJC1060X370_011": 0xa31e7f66,
        "TJC8060X380_011": 0xd9b92b5c,
        "TJC1060X3A1_011": 0x2c3a9902,

        "TJC4848X540_011": 0x8e472af9,
        "TJC4827X543_011": 0x66999185,
        "TJC8048X543_011": 0x4e505bbd,
        "TJC8048X550_011": 0x434d5217,
        "TJC8048X570_011": 0xb8529fae,
        "TJC1060X570_011": 0xb3fbd54d,
        "TJC8060X580_011": 0xc95c8177,
        "TJC1060X5A1_011": 0x3cdf3329,
    }
    _models = list(_modelXORs.keys())
    _modelCRCs = [Checksum().CRC(data=m.encode("ascii")) for m in _models]

    _fileHeader1 = {
        "size":    0xc8,
        "start":   0x00,
        "hasCRC":  True,
        "content": {
            "old_lcd_orientation":                  {"struct": "B", "val": 0}, # editor fixes this to 0
            "editor_version_main":                  {"struct": "B", "val": 0},
            "editor_version_sub":                   {"struct": "B", "val": 0},
            "editor_vendor":                        {"struct": "B", "val": 0},
            "unknown_old_firmware_address":         {"struct": "I", "val": 0},
            "unknwon_old_firmware_size":            {"struct": "I", "val": 0},
            "old_lcd_resolution_width":             {"struct": "H", "val": 0}, # always largest resolution
            "old_lcd_resolution_height":            {"struct": "H", "val": 0}, # always smallest resolution
            "lcd_resolution_x":                     {"struct": "H", "val": 0}, # x-resolution in current orientation (cf ui_orientation)
            "lcd_resolution_y":                     {"struct": "H", "val": 0}, # y-resolution in current orientation (cf ui_orientation)
            "ui_orientation":                       {"struct": "B", "val": 0},
            "model_series":                         {"struct": "B", "val": 0}, # 0=T0, 1=K0, 2=X3, 3=X5, 100=T1
            "unknown_otp":                          {"struct": "B", "val": 0},
            "editor_version_bugfix":                {"struct": "B", "val": 3},
            "unknown_stm32_lcddriver_address":      {"struct": "I", "val": 0},
            "unknown_res1":                         {"struct": "H", "val": 0},
            "unknown_old_stm32_lcddriver_address":  {"struct": "I", "val": 0},
            "unknown_stm32_lcddriver_size":         {"struct": "I", "val": 0},
            "unknown_stm32_binary_address":         {"struct": "I", "val": 0},
            "unknown_stm32_binary_size":            {"struct": "I", "val": 0},
            "model_crc":                            {"struct": "I", "val": 0},
            "file_version":                         {"struct": "B", "val": 0},
            "unknown_encode_start":                 {"struct": "B", "val": 0},
            "ressources_files_address":             {"struct": "I", "val": 0},
            "ressources_files_count":               {"struct": "I", "val": 0},
            "file_size":                            {"struct": "I", "val": 0},
            "ressource_files_size":                 {"struct": "I", "val": 0},
            "ressource_files_crc":                  {"struct": "I", "val": 0},
            "unknown_memory_fs_size":               {"struct": "I", "val": 0},
            "unknown_next_file_address":            {"struct": "I", "val": 0},
            "unknown_file_id":                      {"struct": "I", "val": 0},
            "unknown_metadata_size":                {"struct": "I", "val": 0},
        },
    }
    _fileHeader2 = {
        "size":    0xc8,
        "start":   0xc8,
        "hasCRC":  True,
        "content": {
            "static_usercode_address":      {"struct": "I", "val": 0},
            "app_attributes_data_address":  {"struct": "I", "val": 0},
            "ressources_files_address":     {"struct": "I", "val": 0},
            "usercode_address":             {"struct": "I", "val": 0},
            "unknown_pages_address":        {"struct": "I", "val": 0},
            "unknown_objects_address":      {"struct": "I", "val": 0},
            "pictures_address":             {"struct": "I", "val": 0},
            "gmovs_address":               {"struct": "I", "val": 0},
            "videos_address":              {"struct": "I", "val": 0},
            "audios_address":              {"struct": "I", "val": 0},
            "fonts_address":               {"struct": "I", "val": 0},
            "unknown_maincode_binary":      {"struct": "I", "val": 0},
            "pages_count":                  {"struct": "H", "val": 0},
            "unknown_objects_count":        {"struct": "H", "val": 0},
            "pictures_count":               {"struct": "H", "val": 0},
            "gmovs_count":                  {"struct": "H", "val": 0},
            "videos_count":                 {"struct": "H", "val": 0},
            "audios_count":                 {"struct": "H", "val": 0},
            "fonts_count":                  {"struct": "H", "val": 0},
            "unknown_res1":                 {"struct": "H", "val": 0},
            "unknown_encode":               {"struct": "B", "val": 0},
            "unknown_res2":                 {"struct": "B", "val": 0},
            "unknown_res3":                 {"struct": "H", "val": 0},
        },
    }
    _fileHeader2_ext = {
        "size":    0xc8,
        "start":   0xc8,
        "hasCRC":  True,
        "content": {
            "static_usercode_address":      {"struct": "I", "val": 0},
            "app_vas_address":              {"struct": "I", "val": 0},
            "app_vas_count":                {"struct": "I", "val": 0},
            "app_attributes_data_address":  {"struct": "I", "val": 0},
            "ressources_files_address":     {"struct": "I", "val": 0},
            "usercode_address":             {"struct": "I", "val": 0},
            "unknown_pages_address":        {"struct": "I", "val": 0},
            "unknown_objects_address":      {"struct": "I", "val": 0},
            "pictures_address":             {"struct": "I", "val": 0},
            "gmovs_address":               {"struct": "I", "val": 0},
            "videos_address":              {"struct": "I", "val": 0},
            "audios_address":              {"struct": "I", "val": 0},
            "fonts_address":               {"struct": "I", "val": 0},
            "unknown_maincode_binary":      {"struct": "I", "val": 0},
            "pages_count":                  {"struct": "H", "val": 0},
            "unknown_objects_count":        {"struct": "H", "val": 0},
            "pictures_count":               {"struct": "H", "val": 0},
            "gmovs_count":                  {"struct": "H", "val": 0},
            "videos_count":                 {"struct": "H", "val": 0},
            "audios_count":                 {"struct": "H", "val": 0},
            "fonts_count":                  {"struct": "H", "val": 0},
            "unknown_res1":                 {"struct": "H", "val": 0},
            "unknown_encode":               {"struct": "B", "val": 0},
            "unknown_res2":                 {"struct": "B", "val": 0},
            "unknown_res3":                 {"struct": "H", "val": 0},
        },
    }

    def __init__(self, raw:bytes, hexVals=True, header2_hint:str="", decode_usercode=True):
        self.raw = raw
        self.hexVals = hexVals
        self.header1 = HeaderData(self.raw, self._fileHeader1)
        try:
            self.model = self._models[self._modelCRCs.index(self._getVal("model_crc"))]
        except:
            self.model = "Unknown display model"
        decode_hint = 0
        if self.model in self._modelXORs:
            decode_hint = self._modelXORs[self.model]
        if header2_hint:
            decode_hint = header2_hint

        # Select header2 layout based on editor version
        h2_layout = self._fileHeader2
        v_main = self.header1.content.get("editor_version_main", 0)
        v_sub = self.header1.content.get("editor_version_sub", 0)
        if v_main > 1 or (v_main == 1 and v_sub >= 67):
            h2_layout = self._fileHeader2_ext
        self.header2 = HeaderData(self.raw, h2_layout, decode_hint)

        # Determine correct instruction set based on editor and model series
        version_str = self.getEditorVersionStr()
        self.instructions = None
        for e in all_instruction_sets:
            if version_str in e["versions"]:
                self.instructions = e["models"][self._getVal("model_series")]
                break
        if not self.instructions:
            print(f"Warning: No instruction set found that matches editor version {version_str}. "
                  f"You won't be able to decode any usercode. ")

        # Decode Usercode if requested
        self.usercode = None
        if decode_usercode:
            self.decode_usercode(hexVals=hexVals)

    def getEditorVersionStr(self):
        vendor = {ord("T"): "tjc", ord("N"): "nxt"}[self._getVal("editor_vendor")]
        main   = self._getVal("editor_version_main")
        sub    = self._getVal("editor_version_sub")
        bug    = self._getVal("editor_version_bugfix")
        editor_str = f"{vendor}-{main}.{sub}"
        if main: # 0.xx versions didn't have bugfix numbers
            editor_str = editor_str + f".{bug}"
        return editor_str

    def decode_usercode(self, hexVals=True):
        if not self.instructions:
            raise Exception("A valid instruction set is required to decode the usercode. ")
        self.usercode = Usercode(self.instructions, self.getRawUsercode(), hexVals)

    def getRawBootloader(self):
        start = self._getVal("ressources_files_address")
        end = start + self._getVal("ressources_files_size")
        return self.raw[start:end]

    def getRawPictures(self):
        start = self._getVal("pictures_address")
        end = start + self._getVal("gmovs_address")
        return self.raw[start:end]

    def getRawFonts(self):
        # Hacky.
        end = -1
        for i in reversed(range(self._getVal("fonts_address"), self._getVal("usercode_address"))):
            if(self.raw[i] != 0x00):
                end = i + 1
                break
        if end > 0:
            return self.raw[self._getVal("fonts_address") : end]
        else:
            return b""

    def getRawUsercode(self):
        start = self._getVal("usercode_address")
        # static_usercode_address is the size of actual block data (tighter bound)
        static_size = self._getVal("static_usercode_address")
        pages_addr = self._getVal("unknown_pages_address")
        if static_size and static_size < pages_addr - start:
            return self.raw[start : start + static_size]
        return self.raw[start : pages_addr]

    def exportRawBootloader(self, path = "/Raw/Bootloader.bin"):
        with open(path, "w") as f:
            f.write(self.getRawBootloader())

    def exportRawPictures(self, path = "/Raw/Pictures.bin"):
        with open(path, "w") as f:
            f.write(self.getRawPictures())

    def exportRawFonts(self, path = "/Raw/Fonts.bin"):
        with open(path, "w") as f:
            f.write(self.getRawFonts())

    def exportRawUsercode(self, path = "/Raw/Usercode.bin"):
        with open(path, "w") as f:
            f.write(self.getRawUsercode())

    def getReadable(self, includeUnknowns=False):
        d = pdict()

        # Info section — rich metadata from both headers
        uc_addr = self._getVal("usercode_address")
        pages_addr = self._getVal("unknown_pages_address")
        static_size = self._getVal("static_usercode_address")
        uc_size = static_size if static_size and static_size < pages_addr - uc_addr else pages_addr - uc_addr
        info = {
            "model": self.model,
            "editor": self.getEditorVersionStr(),
            "resolution": [self._getVal("lcd_resolution_x"), self._getVal("lcd_resolution_y")],
            "orientation": self._getVal("ui_orientation"),
            "pages_count": self._getVal("pages_count"),
            "objects_count": self._getVal("unknown_objects_count"),
            "pictures_count": self._getVal("pictures_count"),
            "fonts_count": self._getVal("fonts_count"),
            "usercode_address": f"0x{uc_addr:x}",
            "usercode_size": uc_size,
        }
        if not self.header2.encrypted:
            info["header2_key_unknown"] = True
        d["info"] = info

        # Raw headers — all integer values for parseability
        d["header1"] = dict([(k, v) for k, v in self.header1.content.items()
                             if includeUnknowns or not k.startswith("unknown")])
        d["header2"] = dict([(k, v) for k, v in self.header2.content.items()
                             if includeUnknowns or not k.startswith("unknown")])

        # Definitions (block 0) — extract meaningful strings
        blocks = list(self.usercode.blocks.items())
        if blocks:
            _, block0 = blocks[0]
            strings = self._extract_ascii_strings(block0.raw)
            d["definitions"] = {
                "size": len(block0.raw),
                "strings": [{"offset": f"0x{off:03x}", "value": s} for off, s in strings],
            }
        else:
            d["definitions"] = {"size": 0, "strings": []}

        # Parse component metadata from page/object records
        page_objects = self._parse_objects()

        # Build block lookup: usercode offset → block object
        block_map = {addr: blk for addr, blk in blocks}

        # Find dict block indices for page boundaries
        dict_indices = [i for i, (_, blk) in enumerate(blocks)
                        if isinstance(blk.decoded, dict)]
        pages_count = self._getVal("pages_count")

        pages = []
        if page_objects and dict_indices and len(dict_indices) == pages_count:
            prev_start = 1  # after block 0
            for page_num, dict_idx in enumerate(dict_indices):
                # Collect all block offsets for this page (between prev page end and dict block)
                page_block_offsets = [blocks[i][0] for i in range(prev_start, dict_idx)]

                # Build event pointer → (obj_index, slot, event_name) mapping
                # and sorted list of event boundaries
                obj_list = page_objects[page_num]
                event_starts = {}  # offset → (obj_index, event_name)
                for obj_i, obj in enumerate(obj_list):
                    ptrs = obj.get("_event_ptrs", ())
                    for slot, ptr in enumerate(ptrs):
                        if ptr != 0xFFFFFFFF:
                            ename = self._event_name(obj["type"], slot)
                            event_starts[ptr] = (obj_i, ename)

                sorted_events = sorted(event_starts.keys())

                # Assign each block to an event based on offset ranges
                # Blocks between event_starts[i] and event_starts[i+1] belong to event i
                # Blocks before the first event are "preinitialize"
                obj_events = {}  # obj_index → {event_name: [blocks]}
                preinit_blocks = []

                for blk_off in page_block_offsets:
                    blk = block_map.get(blk_off)
                    if not blk:
                        continue
                    text = self._block_text(blk)
                    if not text:
                        continue
                    block_entry = {
                        "offset": f"0x{blk_off:x}",
                        "size": len(blk.raw),
                        "content": text,
                    }

                    # Find which event this block belongs to
                    # (last event start <= blk_off)
                    owner = None
                    for i in range(len(sorted_events) - 1, -1, -1):
                        if blk_off >= sorted_events[i]:
                            owner = event_starts[sorted_events[i]]
                            break

                    if owner is None:
                        preinit_blocks.append(block_entry)
                    else:
                        obj_i, ename = owner
                        if obj_i not in obj_events:
                            obj_events[obj_i] = {}
                        if ename not in obj_events[obj_i]:
                            obj_events[obj_i][ename] = []
                        obj_events[obj_i][ename].append(block_entry)

                # Build clean object list (strip internal _event_ptrs, add events)
                clean_objects = []
                for obj_i, obj in enumerate(obj_list):
                    clean_obj = {
                        "id": obj["id"], "type": obj["type"],
                        "x": obj["x"], "y": obj["y"],
                        "w": obj["w"], "h": obj["h"],
                    }
                    if obj_i in obj_events:
                        clean_obj["events"] = obj_events[obj_i]
                    clean_objects.append(clean_obj)

                _, dict_blk = blocks[dict_idx]
                variables = dict_blk.decoded if isinstance(dict_blk.decoded, dict) else {}
                variables = {str(k): v for k, v in variables.items()}

                page_entry = {"page": page_num}
                if preinit_blocks:
                    page_entry["preinitialize"] = preinit_blocks
                page_entry["objects"] = clean_objects
                page_entry["variables"] = variables
                pages.append(page_entry)
                prev_start = dict_idx + 1
        else:
            # Fallback: no object metadata, flat block list
            for i, (addr, blk) in enumerate(blocks[1:], 1):
                text = self._block_text(blk)
                if not text:
                    continue
                entry = {
                    "page": None,
                    "blocks": [{
                        "offset": f"0x{addr:x}",
                        "size": len(blk.raw),
                        "content": text,
                    }],
                }
                if isinstance(blk.decoded, dict):
                    entry["variables"] = {str(k): v for k, v in blk.decoded.items()}
                pages.append(entry)

        d["pages"] = pages
        return str(d)

    @staticmethod
    def _block_text(blk):
        """Get block content as a string, handling dict decoded values."""
        if not blk.raw:
            return ""
        if not blk.decoded:
            return ""
        if blk.decoded == "EMPTY_BLOCK":
            return ""
        if isinstance(blk.decoded, dict):
            return json.dumps(blk.decoded, indent=2)
        return str(blk.decoded) if isinstance(blk.decoded, str) else repr(blk.decoded)

    @staticmethod
    def _extract_ascii_strings(data, min_len=4):
        """Extract printable ASCII strings from binary data."""
        results = []
        current = []
        start = -1
        for i, b in enumerate(data):
            if 0x20 <= b < 0x7f:
                if not current:
                    start = i
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    results.append((start, "".join(current)))
                current = []
        if len(current) >= min_len:
            results.append((start, "".join(current)))
        return results

    # Event slot names per component type.
    # Slots not listed here use "event_N" as fallback.
    _event_names = {
        "page":  {0: "postinitialize"},
        "timer": {4: "timer"},
    }
    _default_event_names = {
        0: "event_0", 1: "event_1",
        2: "touch_press", 3: "touch_release",
        4: "event_4", 5: "event_5",
    }

    def _parse_objects(self):
        """Parse page and object metadata records from the TFT binary.
        Returns list of pages, each containing its object list with event
        pointers, or None on failure."""
        pages_addr = self._getVal("unknown_pages_address")
        obj_addr = self._getVal("unknown_objects_address")
        pages_count = self._getVal("pages_count")
        obj_count = self._getVal("unknown_objects_count")

        if pages_addr == 0 or obj_addr == 0 or pages_count == 0:
            return None
        page_sec_size = obj_addr - pages_addr
        if page_sec_size != pages_count * 16:
            return None
        obj_sec_size = len(self.raw) - 4 - obj_addr  # -4 for file checksum
        if obj_sec_size < obj_count * 232:
            return None

        result = []
        obj_idx = 0
        for pg in range(pages_count):
            prec = self.raw[pages_addr + pg * 16 : pages_addr + (pg + 1) * 16]
            _first_id, obj_cnt = struct.unpack_from("<HH", prec, 0)

            objects = []
            for j in range(obj_cnt):
                off = obj_addr + obj_idx * 232
                type_code = self.raw[off]
                obj_id = self.raw[off + 1] | (self.raw[off + 2] << 8)
                event_ptrs = struct.unpack_from("<6I", self.raw, off + 4)
                x, y, w, h = struct.unpack_from("<HHHH", self.raw, off + 40)
                type_name = self._nextion_type_names.get(type_code, f"unknown_0x{type_code:02x}")
                objects.append({
                    "id": obj_id, "type": type_name,
                    "x": x, "y": y, "w": w, "h": h,
                    "_event_ptrs": event_ptrs,
                })
                obj_idx += 1

            result.append(objects)
        return result

    def _event_name(self, type_name, slot):
        """Get human-readable event name for a component type and slot index."""
        names = self._event_names.get(type_name, self._default_event_names)
        return names.get(slot, f"event_{slot}")

    def _getVal(self, key:str):
        if key in self.header1.content:
            return self.header1.content[key]
        elif key in self.header2.content:
            return self.header2.content[key]
        else:
            raise Exception("Value \"" + key + "\" not found in headers.")

    def setModel(self, model:str, force=False):
        if model not in self._models:
            raise Exception("Unknown model " + model)
        if model not in self._modelXORs:
            raise Exception("Unable to convert to specified model because the corresponding XOR key"
                            " is missing in the database.")
        # Vendor aside, the first 6 letters of the model name contain resolution and series
        # (NX8048T070 = 80, 48, T0 f.ex.)
        # These values must match, otherwise a simple conversion is not possible.
        current = self.model.lstrip("NX").lstrip("TJC")[:6]
        new     = model.lstrip("NX").lstrip("TJC")[:6]
        if not force and new != current:
            raise Exception("Cannot convert to a model with different resolution or from a different series.")
            pass

        # Set vendor, model CRC and XOR key to the new model
        self.model = model
        self.header1.content["editor_vendor"] = ord(model[0])
        self.header1.content["model_crc"] = self._modelCRCs[self._models.index(model)]
        self.header2.set_key(self._modelXORs[model])
        self.update_raw()

    def update_raw(self):
        # Convert modified headers back to raw, which also updates the header checksums
        raw  = self.header1.getRaw()
        raw += self.header2.getRaw()

        # Copy updated raw header content into the file raw
        self.raw = raw + self.raw[len(raw):]

        # Update file checksum with the correct checksum algorithm
        series = self._getVal("model_series")
        if series not in (0, 1, 2, 3, 100):
            raise Exception(f"Unknown model series ({series}).")
        # Remove old checksum
        self.raw = self.raw[:-4]
        if series in (2, 3):
            # word based
            words = len(self.raw) // 4
            missingBytes = len(self.raw) - words * 4
            words = list(struct.unpack("<{}I".format(words), self.raw + b"\x00" * missingBytes))
            checksum = Checksum().CRC(data=words)
        else:
            # byte based
            checksum = Checksum().CRC(data=self.raw)
        # Checksum LSB is XORed with some bytes from the header
        checksum ^= self.raw[0x03] ^ self.raw[0x2e] ^ self.raw[0x3c]
        self.raw += struct.pack("<I", checksum)


### Here begins the argparsing
if __name__ == '__main__':
    desc = "TFTTool v1.0.0 - Analyze and convert TFT files. " \
           "Note that the analyze part is very work-in-progress-ish. " \
           "Developped by Max Zuidberg, non-commercial usage only."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-i", "--input", metavar="TFT_FILE", type=str, required=True,
                        help="Path to the TFT source file")
    parser.add_argument("-o", "--output", metavar="OUTPUT_FILE", type=str, required=False, default="",
                        help="Optional path to the resulting text or TFT file. If only a folder is specified, the file "
                             "name is automatically determined based on the input file.")
    parser.add_argument("-t", "--target", default="TXT",
                        help="Optional parameter to specify a new model. No text file will be created but rather "
                             "a new TFT file according to the specified model. If no output file/folder is specified, "
                             "a new file will be created in the same directory with the new model as suffix to the "
                             "original file name. Use -t LIST to list all available models. Use -t NXT or -t TJC "
                             "to keep the original model but change the vendor. Note that this does not work for the "
                             "X3, X5 and P series.")
    parser.add_argument("-e", "--editor-version", default="",
                        help="Optional parameter to specify a new editor version. This is useful if you want to run "
                             "an existing file in a different editor version or migrate between Nextion and TJC where "
                             "the same editor can have a different version number (f.ex. TJC 1.63.1 equals NXT 1.63.3) "
                             "CAREFUL! There is no guarantee that the file still works properly in the new editor "
                             "version. Format: '1.23.4' (three integers separated by a dot).")
    parser.add_argument("--header2", default="",
                        help="Optional parameter to provide the decoded header 2 for T1/Discovery series files. Can "
                             "either be a string with a json (see TFTTool source for the parameters and their names "
                             "that header 2 includes), or a string with the raw hex values (\"00 01 AC D3 ...\") "
                             "or a path to a file with either a json or a hex string. In the case of the hex string "
                             "the full header is required (minus the empty part at the end). In the case of the json "
                             "the order and the number of parameters given does not matter. However, when the argument "
                             "is a json string you must enclose it with double quotes and use single quotes within the "
                             "json string like this: \"{'hello':42,'world':26}\". For the json file this is possible, "
                             "too, but not required. Alternatively, you must escape the double quotes in the json "
                             "string (\"{\\\"hello\\\":42,\\\"world\\\":26}\". This does not work for the json file.")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Add this flag to skip the model check during conversion. Not recommended and probably "
                             "doesn't give you the results you want. Use at your own risk. ")
    parser.add_argument("-v", action="store_true",
                        help="Add this flag to write the decoded text to the console. Useless with -t")

    args = parser.parse_args()
    tftPath = Path(args.input)
    if not tftPath.exists():
        parser.error("Invalid source file!")
    outputPath = args.output
    if outputPath:
        outputPath = Path(outputPath)

    with open(tftPath, "rb") as f:
        tft = TFTFile(f.read(), header2_hint=args.header2)

    args.target = args.target.upper()
    if args.target == "TXT":
        result = tft.getReadable(includeUnknowns=True)
        if args.v:
            print(result)
        if not outputPath:
            outputPath = tftPath.with_suffix(".json")
        if outputPath.is_dir():
            outputPath /= tftPath.with_suffix(".json").name
        outputPath.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(outputPath, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"Output written to: {outputPath}")
        except Exception as e:
            parser.error(f"Can't open output file: {e}")
    elif args.target == "LIST":
        def s(model):
            # Returns an ascending number to sort models by series, resolution, then size
            val = ["T", "K", "P", "X"].index(model[-8:-7])
            val <<= 4
            val += int(model[-7:-6])
            val <<= 8
            val += ord(model[0])
            val <<= 16
            val += int(model[-12:-10].replace("10", "100")) * int(model[-10:-8])
            val <<= 16
            val += int(model[-6:-4], 16)
            return val
        print("List of all supported models:")
        models = sorted(tft._modelXORs.keys(), key=s)
        for m in models:
            print("  " + m.replace("NX", " NX"))
    else:
        if args.target in ("NXT", "TJC"):
            args.target = args.target.rstrip("T") + tft.model[-12:]
        elif not args.target.endswith("_011"):
            args.target += "_011"

        tft.setModel(args.target, args.force)

        if args.editor_version:
            try:
                v_main, v_sub, v_bug = [int(v) for v in args.editor_version.split(".")]
            except ValueError:
                parser.error(f"Invald version string: {args.editor_version}")
            tft.header1.content["editor_version_main"] = v_main
            tft.header1.content["editor_version_sub"] = v_sub
            tft.header1.content["editor_version_bugfix"] = v_bug
            tft.update_raw()

        if not outputPath or outputPath == tftPath:
            outputPath = tftPath.with_stem(tftPath.stem + "_" + args.target)
        elif outputPath.is_dir():
            outputPath /= tftPath.with_stem(tftPath.stem + "_" + args.target).name
        else:
            outputPath = outputPath.with_suffix(".tft")
        with open(outputPath, "wb") as f:
            f.write(tft.raw)
