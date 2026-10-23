#!/usr/bin/env python3
"""Verify direct transfers to the SRSC bounded-read helper in US retail code.

This is a static relative-call inventory; indirect dispatch is out of scope.
"""

import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


EXPECTED_SHA256 = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"
READ_HELPER = 0x0045F2D0
EXPECTED_INSTRUCTIONS = {
    0x0045F2F3: "mov edi,DWORD PTR [esp+0x10]",
    0x0045F2FC: "mov eax,DWORD PTR [edi]",
    0x0045F2FE: "cmp eax,ecx",
    0x0045F311: "call DWORD PTR ds:0x4750c8",
    0x0045F317: "mov DWORD PTR [esi+0x18],0x0",
    0x0045F337: "call DWORD PTR ds:0x4750c8",
    0x0045F34B: "mov eax,DWORD PTR [esi+0x18]",
    0x0045F351: "mov DWORD PTR [esi+0x18],eax",
    0x0045F35A: "mov DWORD PTR [edi],eax",
    0x0045F362: "mov DWORD PTR [esi+0x18],ecx",
    0x0045F3FA: "cmp edi,eax",
    0x0045F40B: "push 0x1",
    0x0045F40D: "push 0x0",
    0x0045F40F: "push edi",
    0x0045F410: "push eax",
    0x0045F411: "call DWORD PTR ds:0x4750c4",
    0x0045F41D: "mov DWORD PTR [esi+0x18],eax",
    0x0045F37B: "mov DWORD PTR [esp+0x8],0x4",
    0x0045F3AB: "mov DWORD PTR [esp+0x8],0x2",
    0x0045F444: "mov DWORD PTR [esp+0x14],0x2",
    0x0045F45D: "and eax,0xffff",
    0x0045F462: "cmp eax,esi",
    0x0045F47E: "call 0x45f2d0",
    0x0045F4B3: "call 0x45f3d0",
}
EXPECTED_CALLER_INSTRUCTIONS = {
    0x00424949: "lea ecx,[esp+0x10]",
    0x0042494D: "lea edx,[esp+0x58]",
    0x00424951: "push ecx",
    0x00424952: "push edx",
    0x00424953: "mov ecx,ebx",
    0x00424955: "mov DWORD PTR [esp+0x18],0x6",
    0x0042495D: "call 0x45f2d0",
    0x00424962: "mov ecx,DWORD PTR [edi+0x18]",
    0x00424965: "mov eax,DWORD PTR [esp+0x20]",
    0x00424973: "mov esi,DWORD PTR [esp+0x5a]",
    0x0042497F: "and esi,0xffff",
    0x0042498A: "lea ecx,[esp+0x10]",
    0x0042498E: "lea eax,[esi+esi*4]",
    0x00424991: "lea edx,[esp+0x58]",
    0x00424995: "shl eax,1",
    0x00424997: "push ecx",
    0x00424998: "push edx",
    0x00424999: "mov ecx,ebx",
    0x0042499B: "mov DWORD PTR [esp+0x18],eax",
    0x0042499F: "call 0x45f2d0",
    0x004249A4: "test esi,esi",
    0x004249C2: "mov si,WORD PTR [eax]",
    0x004249C5: "add eax,0x2",
    0x004249D0: "mov esi,DWORD PTR [eax]",
    0x004249D2: "add eax,0x8",
    0x004249F8: "dec edx",
    0x004249FD: "jne 0x4249bb",
    0x004254A0: "lea edx,[esp+0x10]",
    0x004254A4: "lea eax,[esp+0x14]",
    0x004254A8: "mov edi,0x2",
    0x004254AD: "push edx",
    0x004254AE: "push eax",
    0x004254AF: "mov ecx,ebx",
    0x004254B1: "mov DWORD PTR [esp+0x18],edi",
    0x004254B5: "call 0x45f2d0",
    0x004255F0: "lea ecx,[esp+0x10]",
    0x004255F4: "lea edx,[ebp+0x4]",
    0x004255F7: "mov esi,0x4",
    0x004255FC: "push ecx",
    0x004255FD: "push edx",
    0x004255FE: "mov ecx,ebx",
    0x00425600: "mov DWORD PTR [esp+0x18],esi",
    0x00425604: "call 0x45f2d0",
    0x00425BD2: "mov eax,DWORD PTR [esp+0x3c]",
    0x00425BD6: "mov edx,DWORD PTR [ebp+0xa8]",
    0x00425BDC: "mov edi,0x30",
    0x00425BE1: "lea ecx,[eax*8+0x0]",
    0x00425BE8: "sub ecx,eax",
    0x00425BF5: "push ecx",
    0x00425BF6: "push esi",
    0x00425BF7: "mov ecx,ebx",
    0x00425BF9: "mov DWORD PTR [esp+0x18],edi",
    0x00425BFD: "call 0x45f2d0",
    0x00425D4D: "lea eax,[esp+0x10]",
    0x00425D51: "mov edi,0x4",
    0x00425D56: "push eax",
    0x00425D57: "mov esi,DWORD PTR [edx]",
    0x00425D59: "mov edx,DWORD PTR [esp+0x28]",
    0x00425D5D: "add esi,edx",
    0x00425D5F: "mov ecx,ebx",
    0x00425D61: "push esi",
    0x00425D62: "mov DWORD PTR [esp+0x18],edi",
    0x00425D66: "call 0x45f2d0",
    0x0042B7CA: "lea edx,[esp+0x14]",
    0x0042B7CE: "lea eax,[esp+0x38]",
    0x0042B7D2: "mov ebp,0x4",
    0x0042B7D7: "push edx",
    0x0042B7D8: "push eax",
    0x0042B7DD: "mov DWORD PTR [esp+0x1c],ebp",
    0x0042B7E1: "call 0x45f2d0",
    0x0043140F: "lea ecx,[esp+0x78]",
    0x00431413: "lea edx,[esp+0x5c]",
    0x00431417: "mov ebx,0xc",
    0x0043141C: "push ecx",
    0x0043141D: "push edx",
    0x0043141E: "mov ecx,esi",
    0x00431420: "mov DWORD PTR [esp+0x80],ebx",
    0x00431427: "call 0x45f2d0",
    0x00436FFD: "lea eax,[esp+0x14]",
    0x00437001: "lea ecx,[esp+0x1c]",
    0x00437005: "push eax",
    0x00437006: "mov esi,0x4",
    0x0043700B: "push ecx",
    0x0043700C: "mov ecx,ebp",
    0x0043700E: "mov DWORD PTR [esp+0x1c],esi",
    0x00437012: "call 0x45f2d0",
    0x00437669: "lea ecx,[esp+0x14]",
    0x0043766D: "lea edx,[esp+0x10]",
    0x00437671: "mov ebp,0x4",
    0x00437676: "push ecx",
    0x00437677: "push edx",
    0x00437678: "mov ecx,edi",
    0x0043767A: "mov DWORD PTR [esp+0x1c],ebp",
    0x0043767E: "call 0x45f2d0",
    0x004156B8: "lea ecx,[esp+0x10]",
    0x004156BC: "lea edx,[edi+0x14]",
    0x004156BF: "mov ebx,0x4",
    0x004156C4: "push ecx",
    0x004156C5: "push edx",
    0x004156C6: "mov ecx,esi",
    0x004156C8: "mov DWORD PTR [esp+0x18],ebx",
    0x004156CC: "call 0x45f2d0",
}
EXPECTED_CALLERS = frozenset({
    0x0040BE48, 0x0040C50A, 0x0040CCCA, 0x0040CD09, 0x0040CD5F, 0x0040CDAA,
    0x0040CEBA, 0x0040CEE3, 0x0040D056, 0x0040D0C9, 0x0040D0E2, 0x0040D211,
    0x0040D375, 0x0040D47A, 0x0040D495, 0x0040D5F4, 0x0040D7F7, 0x00411F25,
    0x00411F9A, 0x004156CC, 0x004156F3, 0x004157B6, 0x0041580B, 0x00421FDF,
    0x004222E7, 0x004223BA, 0x004248BF, 0x0042495D, 0x0042499F, 0x00424A99,
    0x00424ADF, 0x00424B86, 0x00424BB7, 0x00424C06, 0x00424C51, 0x00424D2C,
    0x00424DFF, 0x00424EBC, 0x00424F68, 0x00425000, 0x00425019, 0x004250A8,
    0x00425213, 0x00425259, 0x00425300, 0x004254B5, 0x004254E1, 0x00425604,
    0x00425618, 0x0042562C, 0x004256EF, 0x004257CF, 0x00425983, 0x00425BCD,
    0x00425BFD, 0x00425C35, 0x00425D66, 0x00425D7A, 0x00425D8E, 0x00425DA2,
    0x00425DB6, 0x00425E95, 0x0042603C, 0x00429DA6, 0x0042B293, 0x0042B388,
    0x0042B7E1, 0x0042B7FA, 0x0042B813, 0x0042B830, 0x0042BB48, 0x0042BBA1,
    0x0042BC30, 0x0042BCB7, 0x0042BDEC, 0x0042CC25, 0x0042CCAB, 0x0042EEEF,
    0x00431323, 0x00431427, 0x0043143F, 0x00433279, 0x00433297, 0x004332C2,
    0x00435737, 0x00435BE8, 0x00435C13, 0x00435CBA, 0x00435D1C, 0x00437012,
    0x00437035, 0x004372EA, 0x0043767E, 0x004376A9, 0x004376D4, 0x00437782,
    0x0043779D, 0x00442043, 0x0044205B, 0x0045F383, 0x0045F3B3, 0x0045F44C,
    0x0045F47E,
})
EXPECTED_REQUEST_SIZES = {
    0x004254B5: 0x02, 0x00425604: 0x04, 0x00425BFD: 0x30,
    0x00425D66: 0x04, 0x0042B7E1: 0x04, 0x00431427: 0x0C,
    0x00437012: 0x04, 0x0043767E: 0x04,
    0x004156CC: 0x04,
    0x0040D0E2: 0x0C, 0x0040D375: 0x6C, 0x00411F25: 0x08,
    0x00411F9A: 0x04, 0x0042495D: 0x06, 0x00424A99: 0x10,
    0x00424BB7: 0x02, 0x00424D2C: 0x30,
    0x00424DFF: 0x02, 0x00424EBC: 0x02,
    0x00424F68: 0x02, 0x00425000: 0x06,
    0x00425019: 0x06, 0x004250A8: 0x02, 0x00425213: 0x10,
    0x004256EF: 0x02,
    0x004257CF: 0x08,
    0x00425983: 0x18, 0x00425BCD: 0x04, 0x00425E95: 0x08,
    0x0042B830: 0x02, 0x0042BB48: 0x04, 0x0042BC30: 0x04,
    0x00431323: 0x10, 0x00433297: 0x04, 0x00435BE8: 0x04,
    0x00435CBA: 0x04, 0x004372EA: 0x02, 0x00442043: 0x0C,
    0x0044205B: 0x0C, 0x0045F383: 0x04, 0x0045F3B3: 0x02,
    0x0045F44C: 0x02,
}
EXPECTED_DERIVED_REQUEST_SIZES = {0x0042499F: "masked_count * 10"}

# Address-specific arithmetic observed in the hash-pinned retail disassembly.
# These entries describe the requested byte count only; they do not assign
# semantic names or meanings to the source fields. Every supporting instruction
# is also an exact anchor in EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS.
EXPECTED_VARIABLE_REQUEST_FORMULAS = {
    0x0040D056: {
        "formula": "108 * DWORD [esp+0x34]",
        "anchors": (0x0040D023, 0x0040D02A, 0x0040D039, 0x0040D03D,
                    0x0040D040, 0x0040D046, 0x0040D049, 0x0040D04D,
                    0x0040D053, 0x0040D054, 0x0040D056),
    },
    0x0040D0C9: {
        "formula": "12 * DWORD [esp+0x30]",
        "anchors": (0x0040D0AA, 0x0040D0B1, 0x0040D0B4, 0x0040D0B8,
                    0x0040D0BB, 0x0040D0BF, 0x0040D0C5, 0x0040D0C6,
                    0x0040D0C7, 0x0040D0C9),
    },
    0x0040D211: {
        "formula": "152 * DWORD [esp+0x30]",
        "anchors": (0x0040D1EF, 0x0040D1F3, 0x0040D1F6, 0x0040D1FC,
                    0x0040D1FF, 0x0040D203, 0x0040D209, 0x0040D20D,
                    0x0040D20F, 0x0040D210, 0x0040D211),
    },
    0x0040D47A: {
        "formula": "4 * DWORD [esp+0x20]",
        "anchors": (0x0040D458, 0x0040D45C, 0x0040D460, 0x0040D469,
                    0x0040D470, 0x0040D474, 0x0040D477, 0x0040D478,
                    0x0040D47A),
    },
    0x0040D495: {
        "formula": "2 * DWORD [esp+0x48]",
        "anchors": (0x0040D47F, 0x0040D483, 0x0040D487, 0x0040D488,
                    0x0040D48B, 0x0040D48F, 0x0040D492, 0x0040D493,
                    0x0040D495),
    },
    0x0040D5F4: {
        "formula": "2 * DWORD [esp+0x1c]",
        "anchors": (0x0040D5D5, 0x0040D5DF, 0x0040D5E3, 0x0040D5E4,
                    0x0040D5E7, 0x0040D5ED, 0x0040D5EE, 0x0040D5F0,
                    0x0040D5F4),
    },
    0x0040D7F7: {
        "formula": "4 * DWORD [esp+0x1c]",
        "anchors": (0x0040D718, 0x0040D71C, 0x0040D728, 0x0040D7B1,
                    0x0040D7B5, 0x0040D7BC, 0x0040D7C0, 0x0040D7C4,
                    0x0040D7C9, 0x0040D7CB, 0x0040D7CD, 0x0040D7CF,
                    0x0040D7D4, 0x0040D7D6, 0x0040D7E5, 0x0040D7EF,
                    0x0040D7F0, 0x0040D7F3, 0x0040D7F7),
    },
    0x0040C50A: {
        "formula": "2 * DWORD [esp+0x10]",
        "anchors": (0x0040C4E7, 0x0040C4F7, 0x0040C4F3, 0x0040C500,
                    0x0040C501, 0x0040C502, 0x0040C506, 0x0040C50A),
    },
    0x0040CCCA: {
        "formula": "12 * DWORD [esp+0x3c]",
        "anchors": (0x0040CCB1, 0x0040CCB8, 0x0040CCBB, 0x0040CCBF,
                    0x0040CCC0, 0x0040CCC1, 0x0040CCC6, 0x0040CCCA),
    },
    0x0040CD09: {
        "formula": "44 * DWORD [esp+0x3c]",
        "anchors": (0x0040CCED, 0x0040CCF1, 0x0040CCF5, 0x0040CCF8,
                    0x0040CCFB, 0x0040CD01, 0x0040CD04, 0x0040CD05,
                    0x0040CD09),
    },
    0x0040CD5F: {
        "formula": "4 * sign_extend_i16([esi+0x8e])",
        "anchors": (0x0040CD43, 0x0040CD50, 0x0040CD54, 0x0040CD55,
                    0x0040CD56, 0x0040CD5B, 0x0040CD5F),
    },
    0x0040CDAA: {
        "formula": "if WORD [esi+0x8c] == bx: 16 * sign_extend_i16([esi+0x8e]); "
                   "else: 60 * sign_extend_i16([esi+0x8e])",
        "anchors": (0x0040CD64, 0x0040CD6B, 0x0040CD6D, 0x0040CD7A,
                    0x0040CD7E, 0x0040CD81, 0x0040CD85, 0x0040CD86,
                    0x0040CD88,
                    0x0040CD95, 0x0040CD98, 0x0040CD9B, 0x0040CD9F,
                    0x0040CDA2, 0x0040CDA6, 0x0040CDA7, 0x0040CDAA),
    },
    0x0040CEBA: {
        "formula": "6 * DWORD [[esi+0x78]+0x94]",
        "anchors": (0x0040CE9A, 0x0040CE9D, 0x0040CEA3, 0x0040CEA6,
                    0x0040CEAA, 0x0040CEAC, 0x0040CEB6, 0x0040CEB7,
                    0x0040CEBA),
    },
    0x0040CEE3: {
        "formula": "104 * DWORD [[esi+0x78]+0xa0]",
        "anchors": (0x0040CEBF, 0x0040CEC2, 0x0040CEC8, 0x0040CECB,
                    0x0040CECE, 0x0040CED2, 0x0040CED5, 0x0040CEDF,
                    0x0040CEE0, 0x0040CEE3),
    },
}
EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS = {
    0x0040D023: "lea edx,[esp+0x2c]",
    0x0040D02A: "push edx",
    0x0040D039: "mov eax,DWORD PTR [esp+0x34]",
    0x0040D03D: "lea eax,[eax+eax*2]",
    0x0040D040: "lea ecx,[eax+eax*8]",
    0x0040D046: "shl ecx,0x2",
    0x0040D049: "mov DWORD PTR [esp+0x30],ecx",
    0x0040D04D: "mov ecx,DWORD PTR [eax+0xb0]",
    0x0040D053: "push ecx",
    0x0040D054: "mov ecx,ebp",
    0x0040D056: "call 0x45f2d0",
    0x0040D0AA: "mov eax,DWORD PTR [esp+0x30]",
    0x0040D0B1: "lea edx,[eax+eax*2]",
    0x0040D0B4: "lea eax,[esp+0x2c]",
    0x0040D0B8: "shl edx,0x2",
    0x0040D0BB: "mov DWORD PTR [esp+0x2c],edx",
    0x0040D0BF: "mov edx,DWORD PTR [ecx+0xa4]",
    0x0040D0C5: "push eax",
    0x0040D0C6: "push edx",
    0x0040D0C7: "mov ecx,ebp",
    0x0040D0C9: "call 0x45f2d0",
    0x0040D1EF: "mov eax,DWORD PTR [esp+0x30]",
    0x0040D1F3: "lea ecx,[eax+eax*8]",
    0x0040D1F6: "lea edx,[eax+ecx*2]",
    0x0040D1FC: "shl edx,0x3",
    0x0040D1FF: "mov DWORD PTR [esp+0x2c],edx",
    0x0040D203: "mov edx,DWORD PTR [ecx+0xbc]",
    0x0040D209: "lea eax,[esp+0x2c]",
    0x0040D20D: "mov ecx,ebp",
    0x0040D20F: "push eax",
    0x0040D210: "push edx",
    0x0040D211: "call 0x45f2d0",
    0x0040D458: "mov eax,DWORD PTR [esp+0x20]",
    0x0040D45C: "lea edx,[esp+0x14]",
    0x0040D460: "push edx",
    0x0040D469: "lea ecx,[eax*4+0x0]",
    0x0040D470: "mov DWORD PTR [esp+0x18],ecx",
    0x0040D474: "mov eax,DWORD PTR [edi+0x8]",
    0x0040D477: "push eax",
    0x0040D478: "mov ecx,ebx",
    0x0040D47A: "call 0x45f2d0",
    0x0040D47F: "mov ecx,DWORD PTR [esp+0x48]",
    0x0040D483: "lea eax,[esp+0x14]",
    0x0040D487: "push eax",
    0x0040D488: "lea edx,[ecx+ecx*1]",
    0x0040D48B: "mov DWORD PTR [esp+0x18],edx",
    0x0040D48F: "mov ecx,DWORD PTR [edi+0x14]",
    0x0040D492: "push ecx",
    0x0040D493: "mov ecx,ebx",
    0x0040D495: "call 0x45f2d0",
    0x0040D5D5: "lea eax,[esp+0x14]",
    0x0040D5DF: "mov ecx,DWORD PTR [esp+0x1c]",
    0x0040D5E3: "push eax",
    0x0040D5E4: "lea edx,[ecx+ecx*1]",
    0x0040D5E7: "mov ecx,DWORD PTR [esi+0xbc]",
    0x0040D5ED: "push ecx",
    0x0040D5EE: "mov ecx,ebx",
    0x0040D5F0: "mov DWORD PTR [esp+0x1c],edx",
    0x0040D5F4: "call 0x45f2d0",
    0x0040D718: "mov eax,DWORD PTR [esp+0x1c]",
    0x0040D71C: "lea edi,[eax*4+0x0]",
    0x0040D728: "mov DWORD PTR [esp+0x48],edi",
    0x0040D7B1: "mov edi,DWORD PTR [esp+0x48]",
    0x0040D7B5: "jmp 0x40d7c4",
    0x0040D7BC: "mov edi,DWORD PTR [esp+0x48]",
    0x0040D7C0: "jmp 0x40d7c4",
    0x0040D7C4: "mov ecx,DWORD PTR [esp+0x1c]",
    0x0040D7C9: "cmp ecx,eax",
    0x0040D7CB: "je 0x40d7d6",
    0x0040D7CD: "mov ecx,ebx",
    0x0040D7CF: "call 0x45f3d0",
    0x0040D7D4: "jmp 0x40d808",
    0x0040D7D6: "push 0x0",
    0x0040D7E5: "lea ecx,[esp+0x14]",
    0x0040D7EF: "push ecx",
    0x0040D7F0: "push eax",
    0x0040D7F3: "mov DWORD PTR [esp+0x1c],edi",
    0x0040D7F7: "call 0x45f2d0",
    0x0040C4E7: "mov ecx,DWORD PTR [esp+0x10]",
    0x0040C4F3: "lea eax,[esp+0x24]",
    0x0040C4F7: "lea edx,[ecx+ecx*1]",
    0x0040C500: "push eax",
    0x0040C501: "push ecx",
    0x0040C502: "lea ecx,[esp+0x34]",
    0x0040C506: "mov DWORD PTR [esp+0x2c],edx",
    0x0040C50A: "call 0x45f2d0",
    0x0040CCB1: "mov eax,DWORD PTR [esp+0x3c]",
    0x0040CCB8: "lea edx,[eax+eax*2]",
    0x0040CCBB: "lea eax,[esp+0x10]",
    0x0040CCBF: "push eax",
    0x0040CCC0: "push ecx",
    0x0040CCC1: "shl edx,0x2",
    0x0040CCC6: "mov DWORD PTR [esp+0x18],edx",
    0x0040CCCA: "call 0x45f2d0",
    0x0040CCED: "mov eax,DWORD PTR [esp+0x3c]",
    0x0040CCF1: "lea ecx,[esp+0x10]",
    0x0040CCF5: "push ecx",
    0x0040CCF8: "lea edx,[eax+eax*4]",
    0x0040CCFB: "lea eax,[eax+edx*2]",
    0x0040CD01: "shl eax,0x2",
    0x0040CD04: "push edx",
    0x0040CD05: "mov DWORD PTR [esp+0x18],eax",
    0x0040CD09: "call 0x45f2d0",
    0x0040CD43: "movsx edx,WORD PTR [esi+0x8e]",
    0x0040CD50: "lea eax,[esp+0x30]",
    0x0040CD54: "push eax",
    0x0040CD55: "push ecx",
    0x0040CD56: "shl edx,0x2",
    0x0040CD5B: "mov DWORD PTR [esp+0x38],edx",
    0x0040CD5F: "call 0x45f2d0",
    0x0040CD64: "cmp WORD PTR [esi+0x8c],bx",
    0x0040CD6B: "jne 0x40cd88",
    0x0040CD6D: "movsx edx,WORD PTR [esi+0x8e]",
    0x0040CD7A: "lea eax,[esp+0x34]",
    0x0040CD7E: "shl edx,0x4",
    0x0040CD81: "mov DWORD PTR [esp+0x34],edx",
    0x0040CD85: "push eax",
    0x0040CD86: "jmp 0x40cda7",
    0x0040CD88: "movsx eax,WORD PTR [esi+0x8e]",
    0x0040CD95: "lea eax,[eax+eax*2]",
    0x0040CD98: "lea edx,[eax+eax*4]",
    0x0040CD9B: "lea eax,[esp+0x34]",
    0x0040CD9F: "shl edx,0x2",
    0x0040CDA2: "mov DWORD PTR [esp+0x34],edx",
    0x0040CDA6: "push eax",
    0x0040CDA7: "push ecx",
    0x0040CDAA: "call 0x45f2d0",
    0x0040CE9D: "mov ecx,DWORD PTR [eax+0x94]",
    0x0040CE9A: "mov eax,DWORD PTR [esi+0x78]",
    0x0040CEA3: "lea edx,[ecx+ecx*2]",
    0x0040CEA6: "lea ecx,[esp+0x2c]",
    0x0040CEAA: "shl edx,1",
    0x0040CEAC: "mov DWORD PTR [esp+0x2c],edx",
    0x0040CEB6: "push ecx",
    0x0040CEB7: "push edx",
    0x0040CEBA: "call 0x45f2d0",
    0x0040CEBF: "mov ecx,DWORD PTR [esi+0x78]",
    0x0040CEC2: "mov eax,DWORD PTR [ecx+0xa0]",
    0x0040CEC8: "lea edx,[eax+eax*2]",
    0x0040CECB: "lea eax,[eax+edx*4]",
    0x0040CECE: "lea edx,[esp+0x2c]",
    0x0040CED2: "shl eax,0x3",
    0x0040CED5: "mov DWORD PTR [esp+0x2c],eax",
    0x0040CEDF: "push edx",
    0x0040CEE0: "push eax",
    0x0040CEE3: "call 0x45f2d0",
}

_CALL = re.compile(r"^\s*([0-9a-fA-F]+):.*\bcall\s+0x([0-9a-fA-F]+)\b")
_JMP = re.compile(r"^\s*([0-9a-fA-F]+):.*\bjmp\s+0x([0-9a-fA-F]+)\b")
_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(\S.*)$")
_INSTRUCTION_WIDE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(\S.*)$")
_REGISTER = re.compile(r"^(?:eax|ebx|ecx|edx|esi|edi|ebp)$")
_LEA_ESP = re.compile(
    r"^lea\s+(eax|ebx|ecx|edx|esi|edi|ebp),\[esp(?:\+0x([0-9a-f]+))?\]$")
_STACK_STORE = re.compile(
    r"^mov\s+DWORD PTR \[esp(?:\+0x([0-9a-f]+))?\],(.+)$")
_ESP_ADJUST = re.compile(r"^(sub|add)\s+esp,0x([0-9a-f]+)$")
_BLOCK_END = re.compile(r"^(?:call\b|j[a-z]+\b|loop(?:e|ne|z|nz)?\b|jecxz\b|jcxz\b|ret\b)")
_REGISTER_ALIASES = {
    "eax": {"eax", "ax", "al", "ah"},
    "ebx": {"ebx", "bx", "bl", "bh"},
    "ecx": {"ecx", "cx", "cl", "ch"},
    "edx": {"edx", "dx", "dl", "dh"},
    "esi": {"esi", "si"},
    "edi": {"edi", "di"},
    "ebp": {"ebp", "bp"},
    "esp": {"esp", "sp"},
}
_BRANCH_TARGET = re.compile(
    r"^(?:j[a-z]+|loop(?:e|ne|z|nz)?|jecxz|jcxz)\s+0x([0-9a-f]+)\b")


def instructions(disassembly):
    """Return normalized instructions keyed by virtual address."""
    result = {}
    for line in disassembly.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            result[int(match.group(1), 16)] = " ".join(match.group(2).split())
    return result


def instruction_rows(disassembly):
    """Return decoded address, bytes and instruction rows for local checks."""
    result = []
    for line in disassembly.splitlines():
        match = _INSTRUCTION_WIDE.match(line)
        if match:
            raw_bytes = match.group(2).split()
            result.append((int(match.group(1), 16),
                           " ".join(match.group(3).split()), raw_bytes))
    return sorted(result)


def _reverse_esp_delta(instruction, raw_bytes, delta):
    prefixes = {"66", "67", "f0", "f2", "f3", "2e", "36", "3e", "26", "64", "65"}
    operand_size_16 = False
    for byte in raw_bytes:
        if byte == "66":
            operand_size_16 = True
        elif byte not in prefixes:
            break
    width = 2 if operand_size_16 else 4
    if instruction.startswith(("push ", "pushf")):
        return delta + width
    if instruction.startswith(("pop ", "popf")):
        return delta - width
    match = _ESP_ADJUST.match(instruction)
    if match:
        amount = int(match.group(2), 16)
        return delta + amount if match.group(1) == "sub" else delta - amount
    return delta


def _writes_register(instruction, register):
    """Conservatively detect an instruction that changes a GPR or its alias."""
    mnemonic, _, operands = instruction.partition(" ")
    if mnemonic in {"rep", "repe", "repz", "repne", "repnz"}:
        # Prefixed string operations have implicit count and pointer updates.
        # Refuse tracked provenance rather than attempting partial decoding.
        return True
    if mnemonic in {"cmp", "test", "push", "call", "ret", "nop", "jmp"} or mnemonic.startswith("j"):
        return False
    aliases = _REGISTER_ALIASES[register]
    operands = [part.strip() for part in operands.split(",")]
    if mnemonic == "xchg":
        return any(re.fullmatch(r"[a-z]+", operand) and operand in aliases
                   for operand in operands)
    if mnemonic == "xadd":
        return any(re.fullmatch(r"[a-z]+", operand) and operand in aliases
                   for operand in operands)
    if mnemonic == "cmpxchg" and register == "eax":
        return True
    if mnemonic in {"loop", "loope", "loopne", "loopz", "loopnz"}:
        return register == "ecx"
    if mnemonic in {"cpuid", "cmpxchg8b"}:
        return register in {"eax", "ebx", "ecx", "edx"}
    if mnemonic == "imul":
        if len(operands) == 1:
            return register in {"eax", "edx"}
        return bool(operands and re.fullmatch(r"[a-z]+", operands[0])
                    and operands[0] in aliases)
    if mnemonic in {"mul", "div", "idiv", "rdtsc"}:
        return register in {"eax", "edx"}
    if mnemonic in {"cdq", "cwd"}:
        return register == "edx"
    if mnemonic in {"cbw", "cwde"}:
        return register == "eax"
    if mnemonic in {"movs", "movsb", "movsw", "movsd", "cmps", "cmpsb", "cmpsw", "cmpsd",
                    "stos", "stosb", "stosw", "stosd", "lods", "lodsb", "lodsw", "lodsd",
                    "scas", "scasb", "scasw", "scasd"}:
        implicit = {"esi", "edi"}
        if mnemonic.startswith(("lod", "stos", "scas")):
            implicit.add("eax")
        return register in implicit
    if mnemonic == "xlat":
        return register == "eax"
    if not operands:
        return False
    # Most integer instructions with an explicit register destination write
    # their first operand. Include partial-width names (e.g. CL) so an 8-bit
    # write cannot leave a stale full-width pointer provenance behind.
    destination = operands[0]
    if re.fullmatch(r"[a-z]+", destination) and destination in aliases:
        return True
    return False


def _has_unmodeled_esp_write(block):
    for _, instruction, _ in block:
        if instruction.startswith(("leave", "enter", "pusha", "pushad", "popa", "popad")):
            return True
        if _ESP_ADJUST.match(instruction):
            continue
        if _writes_register(instruction, "esp"):
            return True
        if instruction.startswith(("pushf", "popf")):
            return True
        if re.match(r"^(?:add|sub)\s+esp,(?!0x[0-9a-f]+$)", instruction):
            return True
    return False


def _argument_stack_changed_after_pushes(block, argument_pushes):
    """Reject stack operations that can remove or shift final call arguments."""
    argument_push_addresses = {entry[0] for entry in argument_pushes}
    first_argument_push = min(argument_push_addresses)
    for address, instruction, _ in block:
        if address < first_argument_push or address in argument_push_addresses:
            continue
        if (instruction.startswith(("push ", "pushf", "pop ", "popf", "ret",
                                   "leave", "enter", "pusha", "pushad",
                                   "popa", "popad"))
                or _ESP_ADJUST.match(instruction)):
            return True
    return False


def _argument_memory_changed_before_size_store(block, argument_pushes,
                                                size_store_address, deltas,
                                                branch_targets):
    """Reject writes that may overwrite final helper argument slots."""
    argument_push_addresses = {entry[0] for entry in argument_pushes}
    first_argument_push = min(argument_push_addresses)
    widths = {"BYTE": 1, "WORD": 2, "DWORD": 4, "FWORD": 6,
              "QWORD": 8, "TBYTE": 10, "XMMWORD": 16}
    stack_aliases = {}
    for address, instruction, _ in block:
        if address == size_store_address and not _STACK_STORE.match(instruction):
            return True
        if address >= first_argument_push and address not in argument_push_addresses:
            if _may_write_memory(instruction):
                _, _, operands_text = instruction.partition(" ")
                operands = [part.strip() for part in operands_text.split(",")]
                writable_operands = operands if instruction.startswith("xchg ") else operands[:1]
                for operand in writable_operands:
                    match = re.fullmatch(
                        r"(?:(BYTE|WORD|DWORD|FWORD|QWORD|TBYTE|XMMWORD) PTR )?\[(.+)\]",
                        operand)
                    if not match:
                        return True
                    expression = match.group(2)
                    offset = None
                    address_match = re.fullmatch(
                        r"esp(?:([+-])0x([0-9a-f]+))?", expression)
                    if address_match:
                        offset = (int(address_match.group(2), 16)
                                  if address_match.group(2) else 0)
                        if address_match.group(1) == "-":
                            offset = -offset
                        offset += deltas[address]
                    else:
                        reg_match = re.fullmatch(
                            r"(eax|ebx|ecx|edx|esi|edi|ebp)(?:([+-])0x([0-9a-f]+))?",
                            expression)
                        if not reg_match or reg_match.group(1) not in stack_aliases:
                            return True
                        register = reg_match.group(1)
                        offset, definition_address = stack_aliases[register]
                        if any(definition_address < target <= address
                               for target in branch_targets):
                            return True
                        adjustment = (int(reg_match.group(3), 16)
                                      if reg_match.group(3) else 0)
                        offset += adjustment if reg_match.group(2) != "-" else -adjustment
                    if offset is not None:
                        width = widths.get(match.group(1) or "DWORD", 4)
                        if offset < 8 and offset + width > 0:
                            return True
        lea = _LEA_ESP.match(instruction)
        if lea:
            register = lea.group(1)
            stack_aliases[register] = (
                int(lea.group(2) or "0", 16) + deltas[address], address)
        else:
            for register in tuple(stack_aliases):
                if _writes_register(instruction, register):
                    del stack_aliases[register]
    return False


def _may_write_memory(instruction):
    """Return true for explicit or implicit memory writes in a local block."""
    mnemonic, _, operands = instruction.partition(" ")
    if mnemonic in {"rep", "repe", "repz", "repne", "repnz"}:
        return True
    if mnemonic in {"cmp", "test", "push", "pushf", "call", "ret", "nop", "lea"} or mnemonic.startswith("j"):
        return False
    if mnemonic in {"movs", "movsb", "movsw", "movsd", "stos", "stosb", "stosw", "stosd",
                    "ins", "insb", "insw", "insd"}:
        return True
    operands = [part.strip() for part in operands.split(",")]
    destinations = operands if mnemonic == "xchg" else operands[:1]
    return any("[" in destination for destination in destinations)


def classify_request_sizes(disassembly, call_addresses=None):
    """Classify only local stack-size constants passed through the size pointer.

    The helper's second stack argument is a pointer to a DWORD request length.
    This routine follows that register only to a local ESP-relative LEA and a
    matching DWORD stack store in the same straight-line block. Other dataflow
    is reported unknown; this is not a general x86 dataflow analysis.
    """
    rows = instruction_rows(disassembly)
    calls = (set(call_addresses) if call_addresses is not None else
             callers(disassembly))
    classified = {}
    unknown = set()
    branch_targets = {
        int(match.group(1), 16)
        for _, instruction, _ in rows
        if (match := _BRANCH_TARGET.match(instruction))
    }
    for index, (call_address, call_instruction, _) in enumerate(rows):
        if call_address not in calls:
            continue
        start = max(0, index - 40)
        for candidate in range(index - 1, start - 1, -1):
            if _BLOCK_END.match(rows[candidate][1]):
                start = candidate + 1
                break
        block = rows[start:index]
        if (not block or block[-1][0] + len(block[-1][2]) != call_address
                or any(left[0] + len(left[2]) != right[0]
                       for left, right in zip(block, block[1:]))):
            unknown.add(call_address)
            continue
        if _has_unmodeled_esp_write(block):
            unknown.add(call_address)
            continue
        deltas = {}
        delta = 0
        for address, instruction, raw_bytes in reversed(block):
            deltas[address] = delta
            delta = _reverse_esp_delta(instruction, raw_bytes, delta)

        pushes = [(address, match.group(1),
                   _reverse_esp_delta(instruction, raw_bytes, 0))
                  for address, instruction, raw_bytes in reversed(block)
                  if (match := re.match(r"^push\s+(.+)$", instruction))][:2]
        if (len(pushes) != 2
                or any(width != 4 for _, _, width in pushes)
                or not _REGISTER.fullmatch(pushes[1][1])):
            unknown.add(call_address)
            continue
        if _argument_stack_changed_after_pushes(block, pushes):
            unknown.add(call_address)
            continue

        size_register = pushes[1][1]
        size_pointer = None
        size_pointer_address = None
        for address, instruction, _ in reversed(block):
            if address >= pushes[1][0]:
                continue
            lea = _LEA_ESP.match(instruction)
            if lea and lea.group(1) == size_register:
                size_pointer = int(lea.group(2) or "0", 16) + deltas[address]
                size_pointer_address = address
                break
            if _writes_register(instruction, size_register):
                break
        if size_pointer is None:
            unknown.add(call_address)
            continue
        if any(size_pointer_address < target <= call_address for target in branch_targets):
            unknown.add(call_address)
            continue

        stores = []
        for address, instruction, _ in block:
            store = _STACK_STORE.match(instruction)
            if (store and address < call_address
                    and int(store.group(1) or "0", 16) + deltas[address] == size_pointer):
                stores.append((address, store.group(2)))
        if not stores:
            unknown.add(call_address)
            continue
        last_store_address, value = stores[-1]
        if _argument_memory_changed_before_size_store(
                block, pushes, last_store_address, deltas, branch_targets):
            unknown.add(call_address)
            continue
        if any(address > last_store_address and _may_write_memory(instruction)
               for address, instruction, _ in block):
            unknown.add(call_address)
            continue
        if any(last_store_address < target <= call_address
               for target in branch_targets):
            unknown.add(call_address)
            continue
        if re.fullmatch(r"0x[0-9a-f]+", value):
            classified[call_address] = int(value, 16)
            continue
        if not _REGISTER.fullmatch(value):
            unknown.add(call_address)
            continue

        # Resolve only a register's latest same-block full-width immediate
        # assignment. A later alias write or any other GPR clobber remains
        # unknown; this intentionally does not model general value flow.
        immediate = None
        size_value_definition = None
        for address, instruction, _ in reversed(block):
            if address >= last_store_address:
                continue
            match = re.fullmatch(
                rf"mov\s+{value},(0x[0-9a-f]+)", instruction)
            if match:
                size_value_definition = address
                immediate = int(match.group(1), 16)
                break
            if _writes_register(instruction, value):
                break
        if immediate is None:
            unknown.add(call_address)
            continue
        if any(size_value_definition < target <= call_address
               for target in branch_targets):
            unknown.add(call_address)
            continue
        classified[call_address] = immediate
    return classified, unknown


def direct_references(disassembly, pattern, target=READ_HELPER):
    """Return instruction addresses for direct calls or jumps to target."""
    result = set()
    for line in disassembly.splitlines():
        match = pattern.match(line)
        if match and int(match.group(2), 16) == target:
            result.add(int(match.group(1), 16))
    return result


def callers(disassembly, target=READ_HELPER):
    return direct_references(disassembly, _CALL, target)


def jumps(disassembly, target=READ_HELPER):
    return direct_references(disassembly, _JMP, target)


def raw_pointer_offsets(data, target=READ_HELPER):
    """Find exact little-endian absolute-address literals in raw file bytes."""
    needle = target.to_bytes(4, "little")
    result = []
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            return result
        result.append(offset)
        offset += 1


def disassemble_snapshot(data, objdump="objdump"):
    """Disassemble an immutable verified byte snapshot via a temporary PE."""
    with tempfile.TemporaryDirectory(prefix="dragonrider-srsc-read-helper-") as temp:
        snapshot = Path(temp) / "Drakan.exe"
        snapshot.write_bytes(data)
        return subprocess.run(
            [objdump, "-d", "-Mintel", "-w", str(snapshot)],
            check=True, capture_output=True, text=True).stdout


def verify_instruction_anchors(disassembly):
    observed_instructions = instructions(disassembly)
    expected_instructions = EXPECTED_INSTRUCTIONS | EXPECTED_CALLER_INSTRUCTIONS
    formula_callers = set(EXPECTED_VARIABLE_REQUEST_FORMULAS)
    if not formula_callers <= EXPECTED_CALLERS:
        raise ValueError("variable request formulas include an unverified caller")
    for call_address, entry in EXPECTED_VARIABLE_REQUEST_FORMULAS.items():
        if (call_address not in entry["anchors"]
                or not set(entry["anchors"]) <= set(EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS)):
            raise ValueError(
                f"variable request formula at 0x{call_address:08x} lacks instruction anchors")
    expected_instructions = (expected_instructions |
                             EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS)
    mismatches = {
        hex(address): {"expected": expected, "actual": observed_instructions.get(address)}
        for address, expected in expected_instructions.items()
        if observed_instructions.get(address) != expected
    }
    if mismatches:
        raise ValueError(f"SRSC read-helper anchors differ: {mismatches}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if not args.executable.is_file() or args.executable.is_symlink():
        raise ValueError("executable must be a regular non-symlink file")
    data = args.executable.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError("unexpected executable SHA-256")
    disassembly = disassemble_snapshot(data, args.objdump)
    verify_instruction_anchors(disassembly)
    observed = callers(disassembly)
    observed_jumps = jumps(disassembly)
    if observed != EXPECTED_CALLERS:
        missing = sorted(EXPECTED_CALLERS - observed)
        unexpected = sorted(observed - EXPECTED_CALLERS)
        raise ValueError(
            "direct SRSC read-helper caller inventory differs "
            f"(missing={[hex(value) for value in missing]}, "
            f"unexpected={[hex(value) for value in unexpected]})")
    if observed_jumps:
        raise ValueError(
            "unexpected direct jumps to SRSC read helper "
            f"({[hex(value) for value in sorted(observed_jumps)]})")
    pointer_literals = raw_pointer_offsets(data)
    if pointer_literals:
        raise ValueError(
            "unexpected raw absolute-address literals for SRSC read helper "
            f"({[hex(value) for value in pointer_literals]})")
    request_sizes, unknown_sizes = classify_request_sizes(disassembly, observed)
    if set(request_sizes) & unknown_sizes or set(request_sizes) | unknown_sizes != observed:
        raise ValueError("request-size classification did not cover every direct helper call")
    if request_sizes != EXPECTED_REQUEST_SIZES:
        raise ValueError("locally traced request-size constants differ from pinned anchors")
    if not set(EXPECTED_DERIVED_REQUEST_SIZES) <= unknown_sizes:
        raise ValueError("derived-size anchor was unexpectedly classified as a local constant")
    remaining_unknown = unknown_sizes - set(EXPECTED_DERIVED_REQUEST_SIZES)
    histogram = dict(sorted(Counter(request_sizes.values()).items()))
    print(f"Verified direct transfers to 0x{READ_HELPER:08x}: "
          f"{len(observed)} calls, {len(observed_jumps)} unconditional jumps, "
          f"{len(pointer_literals)} raw address literals; "
          f"verified {len(EXPECTED_INSTRUCTIONS)} helper, "
          f"{len(EXPECTED_CALLER_INSTRUCTIONS)} existing caller, and "
          f"{len(EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS)} variable-size caller instruction anchors")
    derived = ", ".join(
        f"0x{address:08x}={expression}"
        for address, expression in sorted(EXPECTED_DERIVED_REQUEST_SIZES.items()))
    print(f"Locally traced constant request sizes: {len(request_sizes)}; "
          f"anchored derived-size calls: {derived}; unknown: {len(remaining_unknown)}; "
          f"constant histogram: {histogram}")
    sites = ", ".join(
        f"0x{address:08x}={size}"
        for address, size in sorted(request_sizes.items()))
    print(f"Constant callsite measurements (address=bytes): {sites}")
    formulas = ", ".join(
        f"0x{address:08x}={entry['formula']}"
        for address, entry in sorted(EXPECTED_VARIABLE_REQUEST_FORMULAS.items()))
    print(f"Anchored variable request byte formulas (source semantics unknown): {formulas}")


if __name__ == "__main__":
    main()
