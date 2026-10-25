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
EXPECTED_SELECTOR_CALLERS = {
    0x00415360: {0x00415345, 0x0041682E, 0x00416BA8, 0x00417450,
                 0x0041801F, 0x00418B24},
    0x004155D0: {0x0041538D},
    0x0045FA10: {0x00415668, 0x0042476E, 0x00433030, 0x0045F24D},
}
EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS = {
    0x00415340: "mov eax,DWORD PTR [esp+0x4]",
    0x00415344: "push eax",
    0x00415345: "call 0x415360",
    0x0041681D: "mov eax,DWORD PTR [edi+0x4]",
    0x00416828: "push eax",
    0x0041682E: "call 0x415360",
    0x00416B97: "mov eax,DWORD PTR [esi+0x4]",
    0x00416BA2: "push eax",
    0x00416BA8: "call 0x415360",
    0x004173E3: "mov eax,DWORD PTR [esp+0x34]",
    0x004173EA: "push eax",
    0x00417450: "call 0x415360",
    0x0041800E: "mov eax,DWORD PTR [edi+0x4]",
    0x00418019: "push eax",
    0x0041801F: "call 0x415360",
    0x00418B16: "mov eax,DWORD PTR [ecx+eax*8+0x4]",
    0x00418B1E: "push eax",
    0x00418B24: "call 0x415360",
}

# Full bounded function-body anchors used when a request value is carried in a
# register across a helper whose body does not write that register.
READ_HELPER_BODY_ANCHORS = (
    0x0045F2D0, 0x0045F2D1, 0x0045F2D3, 0x0045F2D4, 0x0045F2D7,
    0x0045F2D9, 0x0045F2DA, 0x0045F2DF, 0x0045F2E0, 0x0045F2E3,
    0x0045F2E7, 0x0045F2E9, 0x0045F2EA, 0x0045F2EF, 0x0045F2F0,
    0x0045F2F3, 0x0045F2F7, 0x0045F2FA, 0x0045F2FC, 0x0045F2FE,
    0x0045F300, 0x0045F302, 0x0045F305, 0x0045F309, 0x0045F30A,
    0x0045F30B, 0x0045F30F, 0x0045F310, 0x0045F311, 0x0045F317,
    0x0045F31E, 0x0045F31F, 0x0045F324, 0x0045F325, 0x0045F328,
    0x0045F32C, 0x0045F330, 0x0045F331, 0x0045F332, 0x0045F335,
    0x0045F336, 0x0045F337, 0x0045F33D, 0x0045F33F, 0x0045F343,
    0x0045F345, 0x0045F347, 0x0045F349, 0x0045F34B, 0x0045F34E,
    0x0045F34F, 0x0045F351, 0x0045F354, 0x0045F356, 0x0045F357,
    0x0045F35A, 0x0045F35C, 0x0045F35F, 0x0045F361, 0x0045F362,
    0x0045F365, 0x0045F36A, 0x0045F36B,
)
SKIP_HELPER_BODY_ANCHORS = (
    0x0045F3D0, 0x0045F3D1, 0x0045F3D3, 0x0045F3D4, 0x0045F3D7,
    0x0045F3D9, 0x0045F3DA, 0x0045F3DF, 0x0045F3E0, 0x0045F3E3,
    0x0045F3E7, 0x0045F3E9, 0x0045F3EA, 0x0045F3EF, 0x0045F3F0,
    0x0045F3F3, 0x0045F3F7, 0x0045F3FA, 0x0045F3FC, 0x0045F3FE,
    0x0045F3FF, 0x0045F404, 0x0045F405, 0x0045F408, 0x0045F40B,
    0x0045F40D, 0x0045F40F, 0x0045F410, 0x0045F411, 0x0045F417,
    0x0045F41A, 0x0045F41C, 0x0045F41D, 0x0045F420, 0x0045F422,
    0x0045F423,
)
WORD_READER_BODY_ANCHORS = (
    0x0045F370, 0x0045F371, 0x0045F375, 0x0045F379, 0x0045F37A,
    0x0045F37B, 0x0045F383, 0x0045F388, 0x0045F38A, 0x0045F38C,
    0x0045F390, 0x0045F393, 0x0045F395, 0x0045F397, 0x0045F399,
    0x0045F39A,
)
VECTOR_SCALE_BODY_ANCHORS = (
    0x00409DB0, 0x00409DB3, 0x00409DB8, 0x00409DBC, 0x00409DBF,
    0x00409DC2, 0x00409DC3, 0x00409DC6, 0x00409DCA, 0x00409DCD,
    0x00409DD0, 0x00409DD4, 0x00409DD7, 0x00409DDA, 0x00409DDC,
    0x00409DDF, 0x00409DE3, 0x00409DE6, 0x00409DE9, 0x00409DED,
    0x00409DF0, 0x00409DF3, 0x00409DF7, 0x00409DFA,
)
SELECTED_RECORD_HELPER_BODY_ANCHORS = (
    0x0045F270, 0x0045F271, 0x0045F272, 0x0045F274, 0x0045F275,
    0x0045F278, 0x0045F27A, 0x0045F27B, 0x0045F27C, 0x0045F281,
    0x0045F282, 0x0045F285, 0x0045F289, 0x0045F28C, 0x0045F28E,
    0x0045F290, 0x0045F297, 0x0045F299, 0x0045F29B, 0x0045F29D,
    0x0045F2A0, 0x0045F2A4, 0x0045F2A7, 0x0045F2A8, 0x0045F2A9,
    0x0045F2AF, 0x0045F2B2, 0x0045F2B4, 0x0045F2B5, 0x0045F2B6,
    0x0045F2BB, 0x0045F2BC, 0x0045F2BF, 0x0045F2C2, 0x0045F2C5,
    0x0045F2C8, 0x0045F2C9, 0x0045F2CA, 0x0045F2CC, 0x0045F2CD,
)

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
    0x004157B6: {
        "formula": "8 * DWORD [edi+0x20]",
        "anchors": (0x0041578E, 0x00415791, 0x004157A7, 0x004157AB,
                    0x004157AE, 0x004157B2, 0x004157B3, 0x004157B4,
                    0x004157B6),
    },
    0x0041580B: {
        "formula": "52 * DWORD [ebp]",
        "anchors": (0x004157DD, 0x004157E0, 0x004157E3, 0x004157E6,
                    0x004157E9, 0x004157EA, 0x004157EC, 0x004157F2, 0x004157F3,
                    0x004157F9, 0x004157FC, 0x00415800, 0x00415803,
                    0x00415807, 0x00415808, 0x00415809, 0x0041580B,
                    0x0041581F, 0x00415829, 0x00415847, 0x0041584A),
    },
    0x004248BF: {
        "formula": "12 * DWORD [edi+0xc]",
        "anchors": (0x004248A7, 0x004248AA, 0x004248AE, 0x004248AF,
                    0x004248B2, 0x004248B5, 0x004248B9, 0x004248BC,
                    0x004248BD, 0x004248BF),
    },
    0x00421FDF: {
        "formula": "4 * DWORD [esp+0x28]",
        "anchors": (0x00421FC4, 0x00421FC8, 0x00421FCC, 0x00421FCD,
                    0x00421FD4, 0x00421FD8, 0x00421FD9, 0x00421FDB,
                    0x00421FDF),
    },
    0x004222E7: {
        "formula": "DWORD [esp+0x48]",
        "anchors": (0x004222BC, 0x004222C0, 0x004222C2, 0x004222C6,
                    0x004222C7, 0x004222C8, 0x004222CA, 0x004222D1,
                    0x004222D8, 0x004222E3, 0x004222E7),
    },
    0x00425D7A: {
        "formula": "4 (EDI=4; helper preserves EDI)",
        "anchors": (0x00425D6B, 0x00425D6F, 0x00425D72, 0x00425D73,
                    0x00425D74, 0x00425D76, 0x00425D7A, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x00425D8E: {
        "formula": "4 (EDI=4; helper preserves EDI)",
        "anchors": (0x00425D7F, 0x00425D83, 0x00425D86, 0x00425D87,
                    0x00425D88, 0x00425D8A, 0x00425D8E, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x00425DA2: {
        "formula": "4 (EDI=4; helper preserves EDI)",
        "anchors": (0x00425D93, 0x00425D97, 0x00425D9A, 0x00425D9B,
                    0x00425D9C, 0x00425D9E, 0x00425DA2, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x00425DB6: {
        "formula": "4 (EDI=4; helper preserves EDI)",
        "anchors": (0x00425DA7, 0x00425DAB, 0x00425DAE, 0x00425DAF,
                    0x00425DB0, 0x00425DB2, 0x00425DB6, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x00429DA6: {
        "formula": "4 * DWORD [esp+0x10]",
        "anchors": (0x00429D8A, 0x00429D8E, 0x00429D92, 0x00429D93,
                    0x00429D9A, 0x00429D9E, 0x00429DA0, 0x00429DA3,
                    0x00429DA5, 0x00429DA6),
    },
    0x00424C06: {
        "formula": "4 * sign_extend_i16(WORD [ebp+0x8e])",
        "anchors": (0x00424BE4, 0x00424BEB, 0x00424BEE, 0x00424BF4,
                    0x00424BF8, 0x00424BFE, 0x00424C02, 0x00424C03,
                    0x00424C04, 0x00424C06),
    },
    0x00424C51: {
        "formula": "16 * sign_extend_i16(WORD [ebp+0x8e])",
        "anchors": (0x00424C35, 0x00424C39, 0x00424C40, 0x00424C43,
                    0x00424C47, 0x00424C4D, 0x00424C4E, 0x00424C4F,
                    0x00424C51),
    },
    0x00425259: {
        "formula": "48 (immediate size-slot store)",
        "anchors": (0x00425220, 0x00425224, 0x00425225, 0x00425227,
                    0x00425229, 0x0042522C, 0x00425232, 0x00425235,
                    0x00425238, 0x0042523E, 0x00425241, 0x00425244,
                    0x0042524A, 0x0042524D, 0x0042524E, 0x00425251,
                    0x00425259),
    },
    0x0042B388: {
        "formula": "DWORD [esi+0x6]",
        "anchors": (0x0042B372, 0x0042B375, 0x0042B379, 0x0042B37D,
                    0x0042B380, 0x0042B381, 0x0042B382, 0x0042B388),
    },
    0x0042B7FA: {
        "formula": "4 (EBP=4 retained across helper)",
        "anchors": (0x0042B7D2, 0x0042B7D7, 0x0042B7D8, 0x0042B7D9,
                    0x0042B7DD, 0x0042B7E1, 0x0042B7E6, 0x0042B7EA,
                    0x0042B7EE, 0x0042B7EF, 0x0042B7F5, 0x0042B7F6,
                    0x0042B7FA, 0x0045F2D3, 0x0045F2D9, 0x0045F2E0,
                    0x0045F2E9, 0x0045F2F0, 0x0045F31E, 0x0045F325,
                    0x0045F34E, 0x0045F357, 0x0045F361, 0x0045F36B),
    },
    0x0042B813: {
        "formula": "4 (EBP=4 retained across helper)",
        "anchors": (0x0042B7FF, 0x0042B803, 0x0042B807, 0x0042B808,
                    0x0042B809, 0x0042B80F, 0x0042B813, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x0042CCAB: {
        "formula": "12 * DWORD [esp+0x20]",
        "anchors": (0x0042CC8F, 0x0042CC96, 0x0042CC9A, 0x0042CC9B,
                    0x0042CC9E, 0x0042CCA1, 0x0042CCA5, 0x0042CCA8,
                    0x0042CCA9, 0x0042CCAB),
    },
    0x0042BDEC: {
        "formula": "DWORD [esp+0x20]",
        "anchors": (0x0042BDCC, 0x0042BDD0, 0x0042BDD4, 0x0042BDD8,
                    0x0042BDDB, 0x0042BDDE, 0x0042BDE2, 0x0042BDE3,
                    0x0042BDE5, 0x0042BDEB, 0x0042BDEC),
    },
    0x0042CC25: {
        "formula": "56 * EDI (value at 0x0042CC0B)",
        "anchors": (0x0042CC01, 0x0042CC07, 0x0042CC0B, 0x0042CC12,
                    0x0042CC14, 0x0042CC18, 0x0042CC1B, 0x0042CC1F,
                    0x0042CC22, 0x0042CC23, 0x0042CC25),
    },
    0x00425300: {
        "formula": "2 (immediate size-slot overwrite)",
        "anchors": (0x00425266, 0x0042526A, 0x0042526E, 0x0042526F,
                    0x00425270, 0x00425272, 0x00425274, 0x00425277,
                    0x0042527D, 0x00425280, 0x00425283, 0x00425289,
                    0x0042528C, 0x0042528F, 0x00425295, 0x00425298,
                    0x0042529B, 0x004252A1, 0x004252A4, 0x004252A7,
                    0x004252AD, 0x004252B0, 0x004252B3, 0x004252B9,
                    0x004252BC, 0x004252BF, 0x004252C5, 0x004252C8,
                    0x004252CB, 0x004252D1, 0x004252D4, 0x004252D7,
                    0x004252DD, 0x004252E0, 0x004252E3, 0x004252E9,
                    0x004252EC, 0x004252EF, 0x004252F5, 0x004252F8,
                    0x00425300),
    },
    0x00424ADF: {
        "formula": "48 (immediate size-slot store)",
        "anchors": (0x00424AD0, 0x00424AD3, 0x00424AD7, 0x00424ADF),
    },
    0x00424B86: {
        "formula": "2 (immediate size-slot store)",
        "anchors": (0x00424B5F, 0x00424B60, 0x00424B7E, 0x00424B86),
    },
    0x004254E1: {
        "formula": "2 (EDI=2 retained across read/skip helpers)",
        "anchors": (0x004254A8, 0x004254D9, 0x004254DA, 0x004254DD,
                    0x004254E1, 0x0045F2D3, 0x0045F2D9, 0x0045F2E0,
                    0x0045F2E9, 0x0045F2F0, 0x0045F31E, 0x0045F325,
                    0x0045F34E, 0x0045F357, 0x0045F361, 0x0045F36B),
    },
    0x00425618: {
        "formula": "4 (ESI=4 retained across helper)",
        "anchors": (0x004255F7, 0x00425610, 0x00425611, 0x00425614,
                    0x00425618, 0x0045F2D0, 0x0045F2D1, 0x0045F2D3,
                    0x0045F2D9, 0x0045F2E0, 0x0045F2E9, 0x0045F2F0,
                    0x0045F31E, 0x0045F325, 0x0045F34E, 0x0045F357,
                    0x0045F361, 0x0045F36B),
    },
    0x0042562C: {
        "formula": "4 (ESI=4 retained across helper)",
        "anchors": (0x00425621, 0x00425624, 0x00425625, 0x00425626,
                    0x00425628, 0x0042562C, 0x0045F2D0, 0x0045F2D1,
                    0x0045F2D3, 0x0045F2D9, 0x0045F2E0, 0x0045F2E9,
                    0x0045F2F0, 0x0045F31E, 0x0045F325, 0x0045F34E,
                    0x0045F357, 0x0045F361, 0x0045F36B),
    },
    0x00425C35: {
        "formula": "48 (EDI=0x30 retained across helper)",
        "anchors": (0x00425BDC, 0x00425C0F, 0x00425C12, 0x00425C13,
                    0x00425C31, 0x00425C35, 0x0045F2D3, 0x0045F2D9,
                    0x0045F2E0, 0x0045F2E9, 0x0045F2F0, 0x0045F31E,
                    0x0045F325, 0x0045F34E, 0x0045F357, 0x0045F361,
                    0x0045F36B),
    },
    0x00433279: {
        "formula": "DWORD [esi+0x22]",
        "anchors": (0x00433266, 0x00433269, 0x0043326D, 0x00433271,
                    0x00433275, 0x00433276, 0x00433277, 0x00433279),
    },
    0x004332C2: {
        "formula": "DWORD [esp+0x10]",
        "anchors": (0x004332B0, 0x004332B4, 0x004332B8, 0x004332BA,
                    0x004332BE, 0x004332BF, 0x004332C0, 0x004332C2),
    },
    0x00435737: {
        "formula": "4 * (DWORD [esp+0x18] & 0xffff)",
        "anchors": (0x0043570E, 0x00435712, 0x00435719, 0x0043571D,
                    0x00435723, 0x00435728, 0x0043572B, 0x0043572F,
                    0x00435733, 0x00435736, 0x00435737),
    },
    0x00435C13: {
        "formula": "DWORD [esp+0x1c]",
        "anchors": (0x00435C01, 0x00435C05, 0x00435C07, 0x00435C0B,
                    0x00435C0D, 0x00435C0E, 0x00435C0F, 0x00435C13),
    },
    0x00435D1C: {
        "formula": "DWORD [esp+0x30]",
        "anchors": (0x00435D00, 0x00435D04, 0x00435D08, 0x00435D0C,
                    0x00435D0F, 0x00435D12, 0x00435D13, 0x00435D17,
                    0x00435D19, 0x00435D1B, 0x00435D1C),
    },
    0x0042603C: {
        "formula": "16 * (DWORD [esi+0x8] + EBP)",
        "anchors": (0x00426023, 0x00426026, 0x0042602A, 0x0042602C,
                    0x0042602D, 0x00426030, 0x00426032, 0x00426035,
                    0x00426039, 0x0042603B, 0x0042603C),
    },
    0x0042BBA1: {
        "formula": "DWORD [esp+0x28]",
        "anchors": (0x0042BB8B, 0x0042BB91, 0x0042BB95, 0x0042BB96,
                    0x0042BB9C, 0x0042BB9D, 0x0042BBA1),
    },
    0x0042BCB7: {
        "formula": "DWORD [esp+0x28]",
        "anchors": (0x0042BCA3, 0x0042BCA7, 0x0042BCAD, 0x0042BCB1,
                    0x0042BCB5, 0x0042BCB6, 0x0042BCB7),
    },
    0x00437782: {
        "formula": "4 * DWORD [esp+0x20]",
        "anchors": (0x00437760, 0x00437764, 0x00437768, 0x00437769,
                    0x0043776B, 0x00437772, 0x0043777A, 0x0043777E,
                    0x00437781, 0x00437782),
    },
    0x0043779D: {
        "formula": "2 * DWORD [esp+0x18]",
        "anchors": (0x00437787, 0x0043778B, 0x0043778F, 0x00437790,
                    0x00437793, 0x00437797, 0x0043779A, 0x0043779B,
                    0x0043779D),
    },
    0x0045F47E: {
        "formula": "min(DWORD [esp+0x10] & 0xffff, DWORD [esp+0x1c])",
        "anchors": (0x0045F44C, 0x0045F451, 0x0045F453, 0x0045F455,
                    0x0045F459, 0x0045F45D, 0x0045F462, 0x0045F464,
                    0x0045F468, 0x0045F46A, 0x0045F46E, 0x0045F472,
                    0x0045F474, 0x0045F476, 0x0045F47A, 0x0045F47C,
                    0x0045F47D, 0x0045F47E),
    },
    0x004156F3: {
        "formula": "4 (EBX=4 retained across bounded-read, skip, and word-reader helpers)",
        "anchors": (0x004156BF, 0x004156C4, 0x004156C5, 0x004156C6,
                    0x004156C8, 0x004156CC, 0x004156D1, 0x004156D2,
                    0x004156D4, 0x004156D9, 0x004156DC, 0x004156DE,
                    0x004156DF, 0x004156E4, 0x004156E8, 0x004156EB,
                    0x004156EC, 0x004156ED, 0x004156EF, 0x004156F3) +
                   READ_HELPER_BODY_ANCHORS + SKIP_HELPER_BODY_ANCHORS +
                   WORD_READER_BODY_ANCHORS,
    },
    0x0043143F: {
        "formula": "12 (EBX=0xc retained across preceding bounded read)",
        "anchors": (0x00431417, 0x0043141C, 0x0043141D, 0x0043141E,
                    0x00431420, 0x00431427, 0x0043142C, 0x00431430,
                    0x00431434, 0x00431435, 0x00431436, 0x00431438,
                    0x0043143F) + READ_HELPER_BODY_ANCHORS,
    },
    0x00437035: {
        "formula": "4 (ESI=4 retained on successful preceding read)",
        "anchors": (0x00437006, 0x0043700B, 0x0043700C, 0x0043700E,
                    0x00437012, 0x00437017, 0x00437019, 0x0043701B,
                    0x00437020, 0x00437025, 0x00437029, 0x0043702D,
                    0x0043702E, 0x0043702F, 0x00437031, 0x00437035) +
                   READ_HELPER_BODY_ANCHORS,
    },
    0x004376A9: {
        "formula": "4 (EBP=4 retained across bounded read and 0x409db0)",
        "anchors": (0x00437671, 0x00437676, 0x00437677, 0x00437678,
                    0x0043767A, 0x0043767E, 0x00437683, 0x00437687,
                    0x0043768C, 0x00437691, 0x00437692, 0x00437694,
                    0x00437699, 0x0043769D, 0x004376A1, 0x004376A2,
                    0x004376A3, 0x004376A5, 0x004376A9) +
                   READ_HELPER_BODY_ANCHORS + VECTOR_SCALE_BODY_ANCHORS,
    },
    0x004376D4: {
        "formula": "4 (EBP=4 retained across bounded read and 0x409db0 calls)",
        "anchors": (0x00437671, 0x00437676, 0x00437677, 0x00437678,
                    0x0043767A, 0x0043767E, 0x00437683, 0x00437687,
                    0x0043768C, 0x00437691, 0x00437692, 0x00437694,
                    0x00437699, 0x0043769D, 0x004376A1, 0x004376A2,
                    0x004376A3, 0x004376A5, 0x004376A9, 0x004376AE,
                    0x004376B2, 0x004376B7, 0x004376B8, 0x004376BD,
                    0x004376BF, 0x004376C4, 0x004376C8, 0x004376CC,
                    0x004376CD, 0x004376CE, 0x004376D0, 0x004376D4) +
                   READ_HELPER_BODY_ANCHORS + VECTOR_SCALE_BODY_ANCHORS,
    },
    0x004223BA: {
        "formula": ("conditional when [esp+0x38] <= 0: 26*A*C + "
                    "4*(A+1)*(C+1); EBX retained across GlobalAlloc/GlobalLock"),
        "anchors": (0x00422265, 0x00422268, 0x0042226B, 0x0042226E,
                    0x00422271, 0x00422274, 0x00422277, 0x0042227A,
                    0x0042227D, 0x0042227F, 0x00422282, 0x00422285,
                    0x0042228B, 0x0042228C, 0x00422292, 0x00422294,
                    0x00422298, 0x0042229A, 0x0042229E, 0x004223AE,
                    0x004223B2, 0x004223B4, 0x004223B5, 0x004223B6,
                    0x004223BA) + READ_HELPER_BODY_ANCHORS,
    },
    0x0042B293: {
        "formula": ("min(capacity DWORD [esp+0x1c]@0x42b1e4, "
                    "record DWORD [base+26*index+0x6]); EDI preserved by 0x45f270"),
        "anchors": (0x0042B1D2, 0x0042B1DA, 0x0042B1E0, 0x0042B1E4,
                    0x0042B1E8, 0x0042B1EC, 0x0042B1EF, 0x0042B1F3,
                    0x0042B1F5, 0x0042B1F7, 0x0042B1F9, 0x0042B1FD,
                    0x0042B226, 0x0042B22A, 0x0042B22C, 0x0042B26D,
                    0x0042B273, 0x0042B274, 0x0042B279, 0x0042B27B,
                    0x0042B27D, 0x0042B27F, 0x0042B283, 0x0042B287,
                    0x0042B288, 0x0042B289, 0x0042B28F, 0x0042B293) +
                   SELECTED_RECORD_HELPER_BODY_ANCHORS,
    },
    0x0042EEEF: {
        "formula": "DWORD [0x0047d050 + 4*(DWORD [esp+0x20] & 0xffff)]",
        "anchors": (0x0042EEB4, 0x0042EEB8, 0x0042EEBF, 0x0042EEC3,
                    0x0042EEC9, 0x0042EED0, 0x0042EED1, 0x0042EED3,
                    0x0042EED7, 0x0042EEDD, 0x0042EEDE, 0x0042EEE4,
                    0x0042EEE8, 0x0042EEEA, 0x0042EEEB, 0x0042EEEC,
                    0x0042EEEF),
    },
    0x0040BE48: {
        "formula": "DWORD [esp+0x14] (local targeted as the buffer by 0x45f370 at 0x40bdd9)",
        "anchors": (0x0040BDD0, 0x0040BDD4, 0x0040BDD8, 0x0040BDD9,
                    0x0040BE24, 0x0040BE26, 0x0040BE2A, 0x0040BE2C,
                    0x0040BE2D, 0x0040BE2F, 0x0040BE3A, 0x0040BE3E,
                    0x0040BE42, 0x0040BE43, 0x0040BE44, 0x0040BE48),
    },
}
EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS = {
    0x0040BDD0: "lea edx,[esp+0x14]",
    0x0040BDD4: "lea ecx,[esp+0x24]",
    0x0040BDD8: "push edx",
    0x0040BDD9: "call 0x45f370",
    0x0040BE24: "mov edx,DWORD PTR [esi]",
    0x0040BE26: "lea eax,[esp+0x1c]",
    0x0040BE2A: "push 0x20",
    0x0040BE2C: "push eax",
    0x0040BE2D: "mov ecx,esi",
    0x0040BE2F: "call DWORD PTR [edx+0x4]",
    0x0040BE3A: "mov edx,DWORD PTR [esp+0x1c]",
    0x0040BE3E: "lea ecx,[esp+0x14]",
    0x0040BE42: "push ecx",
    0x0040BE43: "push edx",
    0x0040BE44: "lea ecx,[esp+0x2c]",
    0x0040BE48: "call 0x45f2d0",
    0x0041578E: "mov ebx,DWORD PTR [edi+0x20]",
    0x00415791: "shl ebx,0x3",
    0x004157A7: "mov DWORD PTR [esp+0x10],ebx",
    0x004157AB: "mov edx,DWORD PTR [edi+0x10]",
    0x004157AE: "lea ecx,[esp+0x10]",
    0x004157B2: "push ecx",
    0x004157B3: "push edx",
    0x004157B4: "mov ecx,esi",
    0x004157B6: "call 0x45f2d0",
    0x004157DD: "mov eax,DWORD PTR [ebp+0x0]",
    0x004157E0: "lea edx,[eax+eax*2]",
    0x004157E3: "lea ebx,[eax+edx*4]",
    0x004157E6: "shl ebx,0x2",
    0x004157E9: "push ebx",
    0x004157EA: "push 0x0",
    0x004157EC: "call DWORD PTR ds:0x4751e8",
    0x004157F2: "push eax",
    0x004157F3: "call DWORD PTR ds:0x4751e4",
    0x004157F9: "mov DWORD PTR [edi+0xc],eax",
    0x004157FC: "mov DWORD PTR [esp+0x10],ebx",
    0x00415800: "mov ecx,DWORD PTR [edi+0xc]",
    0x00415803: "lea eax,[esp+0x10]",
    0x00415807: "push eax",
    0x00415808: "push ecx",
    0x00415809: "mov ecx,esi",
    0x0041580B: "call 0x45f2d0",
    0x0041581F: "fld DWORD PTR [eax-0x4]",
    0x00415829: "add eax,0x34",
    0x00415847: "cmp ecx,DWORD PTR [ebp+0x0]",
    0x0041584A: "jl 0x41581f",
    0x004248A7: "mov eax,DWORD PTR [edi+0xc]",
    0x004248AA: "lea edx,[esp+0x10]",
    0x004248AE: "push edx",
    0x004248AF: "lea ecx,[eax+eax*2]",
    0x004248B2: "shl ecx,0x2",
    0x004248B5: "mov DWORD PTR [esp+0x14],ecx",
    0x004248B9: "mov eax,DWORD PTR [edi+0x14]",
    0x004248BC: "push eax",
    0x004248BD: "mov ecx,ebx",
    0x004248BF: "call 0x45f2d0",
    0x00421FC4: "mov ecx,DWORD PTR [esp+0x28]",
    0x00421FC8: "lea eax,[esp+0x24]",
    0x00421FCC: "push eax",
    0x00421FCD: "lea edx,[ecx*4+0x0]",
    0x00421FD4: "mov ecx,DWORD PTR [esp+0x18]",
    0x00421FD8: "push ecx",
    0x00421FD9: "mov ecx,ebp",
    0x00421FDB: "mov DWORD PTR [esp+0x2c],edx",
    0x00421FDF: "call 0x45f2d0",
    0x004222BC: "lea ecx,[esp+0x24]",
    0x004222C0: "mov esi,eax",
    0x004222C2: "mov eax,DWORD PTR [esp+0x48]",
    0x004222C6: "push ecx",
    0x004222C7: "push esi",
    0x004222C8: "mov ecx,ebp",
    0x004222CA: "mov DWORD PTR [esp+0xb8],edx",
    0x004222D1: "mov DWORD PTR [esp+0xbc],ebx",
    0x004222D8: "mov DWORD PTR [esp+0xc0],0x0",
    0x004222E3: "mov DWORD PTR [esp+0x2c],eax",
    0x004222E7: "call 0x45f2d0",
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
    0x00425D6B: "lea ecx,[esp+0x10]",
    0x00425D6F: "lea edx,[esi+0x4]",
    0x00425D72: "push ecx",
    0x00425D73: "push edx",
    0x00425D74: "mov ecx,ebx",
    0x00425D76: "mov DWORD PTR [esp+0x18],edi",
    0x00425D7A: "call 0x45f2d0",
    0x00425D7F: "lea eax,[esp+0x10]",
    0x00425D83: "lea ecx,[esi+0x8]",
    0x00425D86: "push eax",
    0x00425D87: "push ecx",
    0x00425D88: "mov ecx,ebx",
    0x00425D8A: "mov DWORD PTR [esp+0x18],edi",
    0x00425D8E: "call 0x45f2d0",
    0x00425D93: "lea edx,[esp+0x10]",
    0x00425D97: "lea eax,[esi+0xc]",
    0x00425D9A: "push edx",
    0x00425D9B: "push eax",
    0x00425D9C: "mov ecx,ebx",
    0x00425D9E: "mov DWORD PTR [esp+0x18],edi",
    0x00425DA2: "call 0x45f2d0",
    0x00425DA7: "lea ecx,[esp+0x10]",
    0x00425DAB: "lea edx,[esi+0x1c]",
    0x00425DAE: "push ecx",
    0x00425DAF: "push edx",
    0x00425DB0: "mov ecx,ebx",
    0x00425DB2: "mov DWORD PTR [esp+0x18],edi",
    0x00425DB6: "call 0x45f2d0",
    0x0045F2D3: "push edi",
    0x0045F2D9: "pop edi",
    0x0045F2E0: "ret 0x8",
    0x0045F2E9: "pop edi",
    0x0045F2F0: "ret 0x8",
    0x0045F31E: "pop edi",
    0x0045F325: "ret 0x8",
    0x0045F34E: "pop edi",
    0x0045F357: "ret 0x8",
    0x0045F361: "pop edi",
    0x0045F36B: "ret 0x8",
    0x00429D8A: "mov ecx,DWORD PTR [esp+0x10]",
    0x00429D8E: "lea eax,[esp+0x2c]",
    0x00429D92: "push eax",
    0x00429D93: "lea edx,[ecx*4+0x0]",
    0x00429D9A: "mov DWORD PTR [esp+0x30],edx",
    0x00429D9E: "mov ecx,DWORD PTR [edi]",
    0x00429DA0: "mov edx,DWORD PTR [ecx+0x8]",
    0x00429DA3: "mov ecx,esi",
    0x00429DA5: "push edx",
    0x00429DA6: "call 0x45f2d0",
    0x00424BE4: "movsx edx,WORD PTR [ebp+0x8e]",
    0x00424BEB: "shl edx,0x2",
    0x00424BEE: "mov DWORD PTR [ebp+0x90],eax",
    0x00424BF4: "mov DWORD PTR [esp+0x10],edx",
    0x00424BF8: "mov ecx,DWORD PTR [ebp+0x90]",
    0x00424BFE: "lea eax,[esp+0x10]",
    0x00424C02: "push eax",
    0x00424C03: "push ecx",
    0x00424C04: "mov ecx,ebx",
    0x00424C06: "call 0x45f2d0",
    0x00424C35: "lea ecx,[esp+0x10]",
    0x00424C39: "movsx eax,WORD PTR [ebp+0x8e]",
    0x00424C40: "shl eax,0x4",
    0x00424C43: "mov DWORD PTR [esp+0x10],eax",
    0x00424C47: "mov edx,DWORD PTR [ebp+0x94]",
    0x00424C4D: "push ecx",
    0x00424C4E: "push edx",
    0x00424C4F: "mov ecx,ebx",
    0x00424C51: "call 0x45f2d0",
    0x00425220: "lea ecx,[esp+0x10]",
    0x00425224: "push ecx",
    0x00425225: "mov ecx,ebx",
    0x00425227: "fstp DWORD PTR [esi]",
    0x00425229: "fld DWORD PTR [esi+0x4]",
    0x0042522C: "fmul DWORD PTR ds:0x475600",
    0x00425232: "fstp DWORD PTR [esi+0x4]",
    0x00425235: "fld DWORD PTR [esi+0x8]",
    0x00425238: "fmul DWORD PTR ds:0x475600",
    0x0042523E: "fstp DWORD PTR [esi+0x8]",
    0x00425241: "fld DWORD PTR [edi+0x34]",
    0x00425244: "fmul DWORD PTR ds:0x475600",
    0x0042524A: "lea esi,[edi+0x38]",
    0x0042524D: "push esi",
    0x0042524E: "fstp DWORD PTR [edi+0x34]",
    0x00425251: "mov DWORD PTR [esp+0x18],0x30",
    0x00425259: "call 0x45f2d0",
    0x0042B372: "mov edx,DWORD PTR [esi+0x6]",
    0x0042B375: "lea eax,[esp+0x10]",
    0x0042B379: "mov DWORD PTR [esp+0x10],edx",
    0x0042B37D: "mov ecx,DWORD PTR [esi+0xa]",
    0x0042B380: "push eax",
    0x0042B381: "push ecx",
    0x0042B382: "mov ecx,DWORD PTR [edi+0x11c]",
    0x0042B388: "call 0x45f2d0",
    0x0042B7D2: "mov ebp,0x4",
    0x0042B7D7: "push edx",
    0x0042B7D8: "push eax",
    0x0042B7D9: "mov DWORD PTR [esp+0x38],edi",
    0x0042B7DD: "mov DWORD PTR [esp+0x1c],ebp",
    0x0042B7E1: "call 0x45f2d0",
    0x0042B7E6: "lea ecx,[esp+0x14]",
    0x0042B7EA: "lea edx,[esp+0x18]",
    0x0042B7EE: "push ecx",
    0x0042B7EF: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042B7F5: "push edx",
    0x0042B7F6: "mov DWORD PTR [esp+0x1c],ebp",
    0x0042B7FA: "call 0x45f2d0",
    0x0042B7FF: "lea eax,[esp+0x14]",
    0x0042B803: "lea ecx,[esp+0x20]",
    0x0042B807: "push eax",
    0x0042B808: "push ecx",
    0x0042B809: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042B80F: "mov DWORD PTR [esp+0x1c],ebp",
    0x0042B813: "call 0x45f2d0",
    0x0042CC8F: "lea edx,[esp+0x14]",
    0x0042CC96: "mov eax,DWORD PTR [esp+0x20]",
    0x0042CC9A: "push edx",
    0x0042CC9B: "lea ecx,[eax+eax*2]",
    0x0042CC9E: "shl ecx,0x2",
    0x0042CCA1: "mov DWORD PTR [esp+0x18],ecx",
    0x0042CCA5: "mov eax,DWORD PTR [esi+0x28]",
    0x0042CCA8: "push eax",
    0x0042CCA9: "mov ecx,edi",
    0x0042CCAB: "call 0x45f2d0",
    0x0042BDCC: "mov ecx,DWORD PTR [esp+0x20]",
    0x0042BDD0: "lea edx,[esp+0x14]",
    0x0042BDD4: "mov DWORD PTR [esp+0x14],ecx",
    0x0042BDD8: "mov eax,DWORD PTR [edi+0x28]",
    0x0042BDDB: "imul eax,esi",
    0x0042BDDE: "mov ecx,DWORD PTR [esp+0x1c]",
    0x0042BDE2: "push edx",
    0x0042BDE3: "add eax,ecx",
    0x0042BDE5: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042BDEB: "push eax",
    0x0042BDEC: "call 0x45f2d0",
    0x0042CC01: "lea eax,[esp+0x14]",
    0x0042CC07: "push eax",
    0x0042CC0B: "lea edx,[edi*8+0x0]",
    0x0042CC12: "sub edx,edi",
    0x0042CC14: "mov edi,DWORD PTR [esp+0x40]",
    0x0042CC18: "shl edx,0x3",
    0x0042CC1B: "mov DWORD PTR [esp+0x18],edx",
    0x0042CC1F: "mov ecx,DWORD PTR [esi+0x1c]",
    0x0042CC22: "push ecx",
    0x0042CC23: "mov ecx,edi",
    0x0042CC25: "call 0x45f2d0",
    0x00425266: "lea edx,[esp+0x10]",
    0x0042526A: "lea eax,[esp+0x34]",
    0x0042526E: "push edx",
    0x0042526F: "push eax",
    0x00425270: "mov ecx,ebx",
    0x00425272: "fstp DWORD PTR [esi]",
    0x00425274: "fld DWORD PTR [esi+0x4]",
    0x00425277: "fmul DWORD PTR ds:0x475600",
    0x0042527D: "fstp DWORD PTR [esi+0x4]",
    0x00425280: "fld DWORD PTR [esi+0x8]",
    0x00425283: "fmul DWORD PTR ds:0x475600",
    0x00425289: "fstp DWORD PTR [esi+0x8]",
    0x0042528C: "fld DWORD PTR [esi+0xc]",
    0x0042528F: "fmul DWORD PTR ds:0x475600",
    0x00425295: "fstp DWORD PTR [esi+0xc]",
    0x00425298: "fld DWORD PTR [esi+0x10]",
    0x0042529B: "fmul DWORD PTR ds:0x475600",
    0x004252A1: "fstp DWORD PTR [esi+0x10]",
    0x004252A4: "fld DWORD PTR [esi+0x14]",
    0x004252A7: "fmul DWORD PTR ds:0x475600",
    0x004252AD: "fstp DWORD PTR [esi+0x14]",
    0x004252B0: "fld DWORD PTR [esi+0x18]",
    0x004252B3: "fmul DWORD PTR ds:0x475600",
    0x004252B9: "fstp DWORD PTR [esi+0x18]",
    0x004252BC: "fld DWORD PTR [esi+0x1c]",
    0x004252BF: "fmul DWORD PTR ds:0x475600",
    0x004252C5: "fstp DWORD PTR [esi+0x1c]",
    0x004252C8: "fld DWORD PTR [esi+0x20]",
    0x004252CB: "fmul DWORD PTR ds:0x475600",
    0x004252D1: "fstp DWORD PTR [esi+0x20]",
    0x004252D4: "fld DWORD PTR [esi+0x24]",
    0x004252D7: "fmul DWORD PTR ds:0x475600",
    0x004252DD: "fstp DWORD PTR [esi+0x24]",
    0x004252E0: "fld DWORD PTR [esi+0x28]",
    0x004252E3: "fmul DWORD PTR ds:0x475600",
    0x004252E9: "fstp DWORD PTR [esi+0x28]",
    0x004252EC: "fld DWORD PTR [esi+0x2c]",
    0x004252EF: "fmul DWORD PTR ds:0x475600",
    0x004252F5: "fstp DWORD PTR [esi+0x2c]",
    0x004252F8: "mov DWORD PTR [esp+0x18],0x2",
    0x00425300: "call 0x45f2d0",
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
    0x00424AD0: "lea esi,[ebp+0x38]",
    0x00424AD3: "push esi",
    0x00424AD7: "mov DWORD PTR [esp+0x18],0x30",
    0x00424ADF: "call 0x45f2d0",
    0x00424B5F: "push ecx",
    0x00424B60: "push edx",
    0x00424B7E: "mov DWORD PTR [esp+0x18],0x2",
    0x00424B86: "call 0x45f2d0",
    0x004254A8: "mov edi,0x2",
    0x004254AD: "push edx",
    0x004254AE: "push eax",
    0x004254B1: "mov DWORD PTR [esp+0x18],edi",
    0x004254B5: "call 0x45f2d0",
    0x004254C9: "push ecx",
    0x004254CC: "call 0x45f3d0",
    0x004254D1: "lea edx,[esp+0x10]",
    0x004254D5: "lea eax,[esp+0x14]",
    0x004254D9: "push edx",
    0x004254DA: "push eax",
    0x004254DD: "mov DWORD PTR [esp+0x18],edi",
    0x004254E1: "call 0x45f2d0",
    0x004255F7: "mov esi,0x4",
    0x004255FC: "push ecx",
    0x004255FD: "push edx",
    0x00425600: "mov DWORD PTR [esp+0x18],esi",
    0x00425604: "call 0x45f2d0",
    0x0042560D: "lea ecx,[ebp+0x8]",
    0x00425610: "push eax",
    0x00425611: "push ecx",
    0x00425614: "mov DWORD PTR [esp+0x18],esi",
    0x00425618: "call 0x45f2d0",
    0x0042561D: "lea edx,[esp+0x10]",
    0x00425621: "lea eax,[ebp+0xc]",
    0x00425624: "push edx",
    0x00425625: "push eax",
    0x00425626: "mov ecx,ebx",
    0x00425628: "mov DWORD PTR [esp+0x18],esi",
    0x0042562C: "call 0x45f2d0",
    0x00425BDC: "mov edi,0x30",
    0x00425BF1: "lea ecx,[esp+0x10]",
    0x00425BF5: "push ecx",
    0x00425BF6: "push esi",
    0x00425BF9: "mov DWORD PTR [esp+0x18],edi",
    0x00425BFD: "call 0x45f2d0",
    0x00425C0B: "lea edx,[esp+0x10]",
    0x00425C0F: "lea eax,[esi+0x30]",
    0x00425C12: "push edx",
    0x00425C13: "push eax",
    0x00425C31: "mov DWORD PTR [esp+0x18],edi",
    0x00425C35: "call 0x45f2d0",
    0x00433266: "mov ecx,DWORD PTR [esi+0x22]",
    0x00433269: "mov eax,DWORD PTR [esp+0x14]",
    0x0043326D: "lea edx,[esp+0x68]",
    0x00433271: "mov DWORD PTR [esp+0x68],ecx",
    0x00433275: "push edx",
    0x00433276: "push eax",
    0x00433277: "mov ecx,edi",
    0x00433279: "call 0x45f2d0",
    0x004332B0: "mov ecx,DWORD PTR [esp+0x10]",
    0x004332B4: "lea edx,[esp+0x68]",
    0x004332B8: "mov ebp,eax",
    0x004332BA: "mov DWORD PTR [esp+0x68],ecx",
    0x004332BE: "push edx",
    0x004332BF: "push ebp",
    0x004332C0: "mov ecx,edi",
    0x004332C2: "call 0x45f2d0",
    0x0043570E: "lea ecx,[esp+0x1c]",
    0x00435712: "push ecx",
    0x00435719: "mov eax,DWORD PTR [esp+0x18]",
    0x0043571D: "mov edx,DWORD PTR [esi+0x1b0]",
    0x00435723: "and eax,0xffff",
    0x00435728: "shl eax,0x2",
    0x0043572B: "mov DWORD PTR [esp+0x20],eax",
    0x0043572F: "mov eax,DWORD PTR [edx+edi*4-0x4]",
    0x00435733: "add eax,0x4",
    0x00435736: "push eax",
    0x00435737: "call 0x45f2d0",
    0x00435C01: "mov edx,DWORD PTR [esp+0x1c]",
    0x00435C05: "mov ebp,eax",
    0x00435C07: "lea eax,[esp+0x14]",
    0x00435C0B: "mov ecx,edi",
    0x00435C0D: "push eax",
    0x00435C0E: "push ebp",
    0x00435C0F: "mov DWORD PTR [esp+0x1c],edx",
    0x00435C13: "call 0x45f2d0",
    0x00435D00: "mov eax,DWORD PTR [esp+0x30]",
    0x00435D04: "lea ecx,[esp+0x14]",
    0x00435D08: "mov DWORD PTR [esp+0x14],eax",
    0x00435D0C: "mov eax,DWORD PTR [esi+0x28]",
    0x00435D0F: "imul eax,edi",
    0x00435D12: "push ecx",
    0x00435D13: "mov ecx,DWORD PTR [esp+0x3c]",
    0x00435D17: "add eax,ecx",
    0x00435D19: "mov ecx,ebx",
    0x00435D1B: "push eax",
    0x00435D1C: "call 0x45f2d0",
    0x00426023: "mov eax,DWORD PTR [esi+0x8]",
    0x00426026: "lea ecx,[esp+0x10]",
    0x0042602A: "add eax,ebp",
    0x0042602C: "push ecx",
    0x0042602D: "mov DWORD PTR [esi+0x8],eax",
    0x00426030: "mov ecx,ebx",
    0x00426032: "shl eax,0x4",
    0x00426035: "mov DWORD PTR [esp+0x14],eax",
    0x00426039: "mov edx,DWORD PTR [esi]",
    0x0042603B: "push edx",
    0x0042603C: "call 0x45f2d0",
    0x0042BB8B: "lea ecx,[esp+0x14]",
    0x0042BB91: "mov eax,DWORD PTR [esp+0x28]",
    0x0042BB95: "push ecx",
    0x0042BB96: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042BB9C: "push esi",
    0x0042BB9D: "mov DWORD PTR [esp+0x1c],eax",
    0x0042BBA1: "call 0x45f2d0",
    0x0042BCA3: "mov edx,DWORD PTR [esp+0x28]",
    0x0042BCA7: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042BCAD: "lea eax,[esp+0x14]",
    0x0042BCB1: "mov DWORD PTR [esp+0x14],edx",
    0x0042BCB5: "push eax",
    0x0042BCB6: "push ebp",
    0x0042BCB7: "call 0x45f2d0",
    0x00437760: "mov edx,DWORD PTR [esp+0x20]",
    0x00437764: "lea ecx,[esp+0x24]",
    0x00437768: "push ecx",
    0x00437769: "mov ecx,edi",
    0x0043776B: "lea eax,[edx*4+0x0]",
    0x00437772: "mov DWORD PTR [esp+0x7c],0xffffffff",
    0x0043777A: "mov DWORD PTR [esp+0x28],eax",
    0x0043777E: "mov edx,DWORD PTR [ebp+0x8]",
    0x00437781: "push edx",
    0x00437782: "call 0x45f2d0",
    0x00437787: "mov eax,DWORD PTR [esp+0x18]",
    0x0043778B: "lea edx,[esp+0x24]",
    0x0043778F: "push edx",
    0x00437790: "lea ecx,[eax+eax*1]",
    0x00437793: "mov DWORD PTR [esp+0x28],ecx",
    0x00437797: "mov eax,DWORD PTR [ebp+0x14]",
    0x0043779A: "push eax",
    0x0043779B: "mov ecx,edi",
    0x0043779D: "call 0x45f2d0",
    0x0045F44C: "call 0x45f2d0",
    0x0045F451: "test eax,eax",
    0x0045F453: "jne 0x45f4ba",
    0x0045F455: "mov eax,DWORD PTR [esp+0x10]",
    0x0045F459: "mov esi,DWORD PTR [esp+0x1c]",
    0x0045F45D: "and eax,0xffff",
    0x0045F462: "cmp eax,esi",
    0x0045F464: "mov DWORD PTR [esp+0xc],eax",
    0x0045F468: "jb 0x45f46e",
    0x0045F46A: "mov DWORD PTR [esp+0xc],esi",
    0x0045F46E: "mov edi,DWORD PTR [esp+0x18]",
    0x0045F472: "test edi,edi",
    0x0045F474: "je 0x45f49f",
    0x0045F476: "lea edx,[esp+0xc]",
    0x0045F47A: "mov ecx,ebx",
    0x0045F47C: "push edx",
    0x0045F47D: "push edi",
    0x0045F47E: "call 0x45f2d0",
    0x00422265: "mov eax,DWORD PTR [edi+0x18]",
    0x00422268: "mov ecx,DWORD PTR [edi+0x1c]",
    0x0042226B: "lea edx,[eax+0x1]",
    0x0042226E: "imul eax,ecx",
    0x00422271: "lea esi,[ecx+0x1]",
    0x00422274: "lea ecx,[eax+eax*2]",
    0x00422277: "imul edx,esi",
    0x0042227A: "lea eax,[eax+ecx*4]",
    0x0042227D: "shl eax,1",
    0x0042227F: "lea ebx,[eax+edx*4]",
    0x00422282: "push ebx",
    0x00422285: "call DWORD PTR ds:0x4751e8",
    0x0042228B: "push eax",
    0x0042228C: "call DWORD PTR ds:0x4751e4",
    0x00422292: "mov esi,eax",
    0x00422294: "mov eax,DWORD PTR [esp+0x38]",
    0x00422298: "test eax,eax",
    0x0042229A: "mov DWORD PTR [esp+0x14],esi",
    0x0042229E: "jle 0x4223ae",
    0x004223AE: "lea edx,[esp+0x24]",
    0x004223B2: "mov ecx,ebp",
    0x004223B4: "push edx",
    0x004223B5: "push esi",
    0x004223B6: "mov DWORD PTR [esp+0x2c],ebx",
    0x004223BA: "call 0x45f2d0",
    0x0042B1D2: "mov ebp,DWORD PTR [esp+0xc]",
    0x0042B1DA: "mov edx,DWORD PTR [ebx+0x104]",
    0x0042B1E0: "lea eax,[ebp+ebp*2+0x0]",
    0x0042B1E4: "mov edi,DWORD PTR [esp+0x1c]",
    0x0042B1E8: "lea ecx,[ebp+eax*4+0x0]",
    0x0042B1EC: "lea eax,[edx+ecx*2]",
    0x0042B1EF: "mov ecx,DWORD PTR [edx+ecx*2+0x6]",
    0x0042B1F3: "cmp ecx,edi",
    0x0042B1F5: "jae 0x42b1f9",
    0x0042B1F7: "mov edi,ecx",
    0x0042B1F9: "test BYTE PTR [eax+0xe],0x1",
    0x0042B1FD: "je 0x42b226",
    0x0042B226: "mov eax,DWORD PTR [esp+0x20]",
    0x0042B22A: "test eax,eax",
    0x0042B22C: "je 0x42b26d",
    0x0042B26D: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042B273: "push ebp",
    0x0042B274: "call 0x45f270",
    0x0042B279: "mov esi,eax",
    0x0042B27B: "test esi,esi",
    0x0042B27D: "jne 0x42b29a",
    0x0042B27F: "mov ecx,DWORD PTR [esp+0x18]",
    0x0042B283: "lea eax,[esp+0x1c]",
    0x0042B287: "push eax",
    0x0042B288: "push ecx",
    0x0042B289: "mov ecx,DWORD PTR [ebx+0x11c]",
    0x0042B28F: "mov DWORD PTR [esp+0x24],edi",
    0x0042B293: "call 0x45f2d0",
    0x0045F270: "push ebx",
    0x0045F271: "push esi",
    0x0045F272: "mov esi,ecx",
    0x0045F274: "push edi",
    0x0045F275: "cmp DWORD PTR [esi],0x1",
    0x0045F278: "je 0x45f285",
    0x0045F27A: "pop edi",
    0x0045F27B: "pop esi",
    0x0045F27C: "mov eax,0xfffffffb",
    0x0045F281: "pop ebx",
    0x0045F282: "ret 0x4",
    0x0045F285: "mov edi,DWORD PTR [esp+0x10]",
    0x0045F289: "mov ecx,DWORD PTR [esi+0x2c]",
    0x0045F28C: "mov edx,ecx",
    0x0045F28E: "push 0x0",
    0x0045F290: "lea eax,[edi*8+0x0]",
    0x0045F297: "push 0x0",
    0x0045F299: "sub eax,edi",
    0x0045F29B: "shl eax,1",
    0x0045F29D: "lea ebx,[ecx+eax*1]",
    0x0045F2A0: "mov eax,DWORD PTR [edx+eax*1+0x6]",
    0x0045F2A4: "mov ecx,DWORD PTR [esi+0x1c]",
    0x0045F2A7: "push eax",
    0x0045F2A8: "push ecx",
    0x0045F2A9: "call DWORD PTR ds:0x4750c4",
    0x0045F2AF: "cmp eax,DWORD PTR [ebx+0x6]",
    0x0045F2B2: "je 0x45f2bf",
    0x0045F2B4: "pop edi",
    0x0045F2B5: "pop esi",
    0x0045F2B6: "mov eax,0xfffffffe",
    0x0045F2BB: "pop ebx",
    0x0045F2BC: "ret 0x4",
    0x0045F2BF: "mov edx,DWORD PTR [ebx+0xa]",
    0x0045F2C2: "mov DWORD PTR [esi+0xc],edi",
    0x0045F2C5: "mov DWORD PTR [esi+0x18],edx",
    0x0045F2C8: "pop edi",
    0x0045F2C9: "pop esi",
    0x0045F2CA: "xor eax,eax",
    0x0045F2CC: "pop ebx",
    0x0045F2CD: "ret 0x4",
    0x0042EEB4: "mov eax,DWORD PTR [esp+0x20]",
    0x0042EEB8: "and eax,0xffff",
    0x0042EEBF: "mov ecx,DWORD PTR [esp+0x20]",
    0x0042EEC3: "and ecx,0xffff",
    0x0042EEC9: "mov eax,DWORD PTR [ecx*4+0x47d050]",
    0x0042EED0: "push eax",
    0x0042EED1: "push 0x40",
    0x0042EED3: "mov DWORD PTR [esp+0x38],eax",
    0x0042EED7: "call DWORD PTR ds:0x4751e8",
    0x0042EEDD: "push eax",
    0x0042EEDE: "call DWORD PTR ds:0x4751e4",
    0x0042EEE4: "lea edx,[esp+0x30]",
    0x0042EEE8: "mov ecx,ebp",
    0x0042EEEA: "push edx",
    0x0042EEEB: "push eax",
    0x0042EEEC: "mov DWORD PTR [esi+0x8],eax",
    0x0042EEEF: "call 0x45f2d0",
    0x004156BF: "mov ebx,0x4",
    0x004156C4: "push ecx",
    0x004156C5: "push edx",
    0x004156C6: "mov ecx,esi",
    0x004156C8: "mov DWORD PTR [esp+0x18],ebx",
    0x004156CC: "call 0x45f2d0",
    0x004156D1: "push ebx",
    0x004156D2: "mov ecx,esi",
    0x004156D4: "call 0x45f3d0",
    0x004156D9: "lea ebp,[edi+0x18]",
    0x004156DC: "mov ecx,esi",
    0x004156DE: "push ebp",
    0x004156DF: "call 0x45f370",
    0x004156E4: "lea eax,[esp+0x10]",
    0x004156E8: "lea ecx,[edi+0x1c]",
    0x004156EB: "push eax",
    0x004156EC: "push ecx",
    0x004156ED: "mov ecx,esi",
    0x004156EF: "mov DWORD PTR [esp+0x18],ebx",
    0x004156F3: "call 0x45f2d0",
    0x00431417: "mov ebx,0xc",
    0x0043141C: "push ecx",
    0x0043141D: "push edx",
    0x0043141E: "mov ecx,esi",
    0x00431420: "mov DWORD PTR [esp+0x80],ebx",
    0x00431427: "call 0x45f2d0",
    0x0043142C: "lea eax,[esp+0x78]",
    0x00431430: "lea ecx,[esp+0x50]",
    0x00431434: "push eax",
    0x00431435: "push ecx",
    0x00431436: "mov ecx,esi",
    0x00431438: "mov DWORD PTR [esp+0x80],ebx",
    0x0043143F: "call 0x45f2d0",
    0x00437006: "mov esi,0x4",
    0x0043700B: "push ecx",
    0x0043700C: "mov ecx,ebp",
    0x0043700E: "mov DWORD PTR [esp+0x1c],esi",
    0x00437012: "call 0x45f2d0",
    0x00437017: "test eax,eax",
    0x00437019: "je 0x437025",
    0x0043701B: "mov esi,0xfffffff7",
    0x00437020: "jmp 0x4371b6",
    0x00437025: "lea edx,[esp+0x14]",
    0x00437029: "lea eax,[esp+0x20]",
    0x0043702D: "push edx",
    0x0043702E: "push eax",
    0x0043702F: "mov ecx,ebp",
    0x00437031: "mov DWORD PTR [esp+0x1c],esi",
    0x00437035: "call 0x45f2d0",
    0x00437671: "mov ebp,0x4",
    0x00437676: "push ecx",
    0x00437677: "push edx",
    0x00437678: "mov ecx,edi",
    0x0043767A: "mov DWORD PTR [esp+0x1c],ebp",
    0x0043767E: "call 0x45f2d0",
    0x00437683: "mov eax,DWORD PTR [esp+0x10]",
    0x00437687: "push 0x3f800000",
    0x0043768C: "push 0x3f800000",
    0x00437691: "push eax",
    0x00437692: "mov ecx,ebx",
    0x00437694: "call 0x409db0",
    0x00437699: "lea ecx,[esp+0x14]",
    0x0043769D: "lea edx,[esp+0x10]",
    0x004376A1: "push ecx",
    0x004376A2: "push edx",
    0x004376A3: "mov ecx,edi",
    0x004376A5: "mov DWORD PTR [esp+0x1c],ebp",
    0x004376A9: "call 0x45f2d0",
    0x004376AE: "mov eax,DWORD PTR [esp+0x10]",
    0x004376B2: "push 0x3f800000",
    0x004376B7: "push eax",
    0x004376B8: "push 0x3f800000",
    0x004376BD: "mov ecx,ebx",
    0x004376BF: "call 0x409db0",
    0x004376C4: "lea ecx,[esp+0x14]",
    0x004376C8: "lea edx,[esp+0x10]",
    0x004376CC: "push ecx",
    0x004376CD: "push edx",
    0x004376CE: "mov ecx,edi",
    0x004376D0: "mov DWORD PTR [esp+0x1c],ebp",
    0x004376D4: "call 0x45f2d0",
    0x00409DB0: "lea eax,[ecx+0x10]",
    0x00409DB3: "mov edx,0x3",
    0x00409DB8: "fld DWORD PTR [esp+0x4]",
    0x00409DBC: "fmul DWORD PTR [eax-0x4]",
    0x00409DBF: "add eax,0xc",
    0x00409DC2: "dec edx",
    0x00409DC3: "fstp DWORD PTR [eax-0x10]",
    0x00409DC6: "fld DWORD PTR [esp+0x8]",
    0x00409DCA: "fmul DWORD PTR [eax-0xc]",
    0x00409DCD: "fstp DWORD PTR [eax-0xc]",
    0x00409DD0: "fld DWORD PTR [esp+0xc]",
    0x00409DD4: "fmul DWORD PTR [eax-0x8]",
    0x00409DD7: "fstp DWORD PTR [eax-0x8]",
    0x00409DDA: "jne 0x409db8",
    0x00409DDC: "fld DWORD PTR [ecx+0x30]",
    0x00409DDF: "fdiv DWORD PTR [esp+0x4]",
    0x00409DE3: "fstp DWORD PTR [ecx+0x30]",
    0x00409DE6: "fld DWORD PTR [ecx+0x34]",
    0x00409DE9: "fdiv DWORD PTR [esp+0x8]",
    0x00409DED: "fstp DWORD PTR [ecx+0x34]",
    0x00409DF0: "fld DWORD PTR [ecx+0x38]",
    0x00409DF3: "fdiv DWORD PTR [esp+0xc]",
    0x00409DF7: "fstp DWORD PTR [ecx+0x38]",
    0x00409DFA: "ret 0xc",
    0x0045F2D4: "cmp DWORD PTR [esi],0x1",
    0x0045F2D7: "je 0x45f2e3",
    0x0045F2DA: "mov eax,0xfffffffb",
    0x0045F2DF: "pop esi",
    0x0045F2E3: "cmp DWORD PTR [esi+0xc],0xffffffff",
    0x0045F2E7: "jne 0x45f2f3",
    0x0045F2EA: "mov eax,0xfffffff9",
    0x0045F2EF: "pop esi",
    0x0045F2F3: "mov edi,DWORD PTR [esp+0x10]",
    0x0045F2F7: "mov ecx,DWORD PTR [esi+0x18]",
    0x0045F2FA: "push 0x0",
    0x0045F2FC: "mov eax,DWORD PTR [edi]",
    0x0045F2FE: "cmp eax,ecx",
    0x0045F300: "jbe 0x45f328",
    0x0045F302: "mov edx,DWORD PTR [esi+0x1c]",
    0x0045F305: "lea eax,[esp+0x10]",
    0x0045F309: "push eax",
    0x0045F30A: "push ecx",
    0x0045F30B: "mov ecx,DWORD PTR [esp+0x18]",
    0x0045F30F: "push ecx",
    0x0045F310: "push edx",
    0x0045F311: "call DWORD PTR ds:0x4750c8",
    0x0045F317: "mov DWORD PTR [esi+0x18],0x0",
    0x0045F31F: "mov eax,0xfffffff7",
    0x0045F324: "pop esi",
    0x0045F328: "mov edx,DWORD PTR [esp+0x10]",
    0x0045F32C: "lea ecx,[esp+0x10]",
    0x0045F330: "push ecx",
    0x0045F331: "push eax",
    0x0045F332: "mov eax,DWORD PTR [esi+0x1c]",
    0x0045F335: "push edx",
    0x0045F336: "push eax",
    0x0045F337: "call DWORD PTR ds:0x4750c8",
    0x0045F33D: "test eax,eax",
    0x0045F33F: "mov eax,DWORD PTR [esp+0xc]",
    0x0045F343: "je 0x45f35a",
    0x0045F345: "mov ecx,DWORD PTR [edi]",
    0x0045F347: "cmp eax,ecx",
    0x0045F349: "jne 0x45f35a",
    0x0045F34B: "mov eax,DWORD PTR [esi+0x18]",
    0x0045F34F: "sub eax,ecx",
    0x0045F351: "mov DWORD PTR [esi+0x18],eax",
    0x0045F354: "xor eax,eax",
    0x0045F356: "pop esi",
    0x0045F35A: "mov DWORD PTR [edi],eax",
    0x0045F35C: "mov ecx,DWORD PTR [esi+0x18]",
    0x0045F35F: "sub ecx,eax",
    0x0045F362: "mov DWORD PTR [esi+0x18],ecx",
    0x0045F365: "mov eax,0xfffffffe",
    0x0045F36A: "pop esi",
    0x0045F370: "push ecx",
    0x0045F371: "mov edx,DWORD PTR [esp+0x8]",
    0x0045F375: "lea eax,[esp+0x0]",
    0x0045F379: "push eax",
    0x0045F37A: "push edx",
    0x0045F37B: "mov DWORD PTR [esp+0x8],0x4",
    0x0045F383: "call 0x45f2d0",
    0x0045F388: "test eax,eax",
    0x0045F38A: "jne 0x45f399",
    0x0045F38C: "mov eax,DWORD PTR [esp+0x0]",
    0x0045F390: "sub eax,0x4",
    0x0045F393: "neg eax",
    0x0045F395: "sbb eax,eax",
    0x0045F397: "and al,0xfe",
    0x0045F399: "pop ecx",
    0x0045F39A: "ret 0x4",
    0x0045F2D0: "push esi",
    0x0045F2D1: "mov esi,ecx",
    0x0045F3D0: "push esi",
    0x0045F3D1: "mov esi,ecx",
    0x0045F3D3: "push edi",
    0x0045F3D4: "cmp DWORD PTR [esi],0x1",
    0x0045F3D7: "je 0x45f3e3",
    0x0045F3D9: "pop edi",
    0x0045F3DA: "mov eax,0xfffffffb",
    0x0045F3DF: "pop esi",
    0x0045F3E0: "ret 0x4",
    0x0045F3E3: "cmp DWORD PTR [esi+0xc],0xffffffff",
    0x0045F3E7: "jne 0x45f3f3",
    0x0045F3E9: "pop edi",
    0x0045F3EA: "mov eax,0xfffffff9",
    0x0045F3EF: "pop esi",
    0x0045F3F0: "ret 0x4",
    0x0045F3F3: "mov edi,DWORD PTR [esp+0xc]",
    0x0045F3F7: "mov eax,DWORD PTR [esi+0x18]",
    0x0045F3FA: "cmp edi,eax",
    0x0045F3FC: "jbe 0x45f408",
    0x0045F3FE: "pop edi",
    0x0045F3FF: "mov eax,0xfffffff7",
    0x0045F404: "pop esi",
    0x0045F405: "ret 0x4",
    0x0045F408: "mov eax,DWORD PTR [esi+0x1c]",
    0x0045F40B: "push 0x1",
    0x0045F40D: "push 0x0",
    0x0045F40F: "push edi",
    0x0045F410: "push eax",
    0x0045F411: "call DWORD PTR ds:0x4750c4",
    0x0045F417: "mov eax,DWORD PTR [esi+0x18]",
    0x0045F41A: "sub eax,edi",
    0x0045F41C: "pop edi",
    0x0045F41D: "mov DWORD PTR [esi+0x18],eax",
    0x0045F420: "xor eax,eax",
    0x0045F422: "pop esi",
    0x0045F423: "ret 0x4",
}
EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS = {
    0x00415363: "mov ecx,DWORD PTR [esp+0x8]",
    0x004156A1: "test eax,eax",
    0x004156A3: "jne 0x415763",
    0x004156D1: "push ebx",
    0x004156D4: "call 0x45f3d0",
    0x004156D9: "lea ebp,[edi+0x18]",
    0x004156DE: "push ebp",
    0x004156DF: "call 0x45f370",
    0x004156EF: "mov DWORD PTR [esp+0x18],ebx",
    0x004156F3: "call 0x45f2d0",
    0x004156FE: "call 0x45f370",
    0x0041570A: "call 0x45f370",
    0x00415715: "call 0x45f370",
    0x0041538A: "push ecx",
    0x0041538D: "call 0x4155d0",
    0x004155E7: "mov ebx,DWORD PTR [esp+0x28]",
    0x004155F1: "mov edx,ebx",
    0x004155F3: "shr edx,0x10",
    0x004155F6: "lea ecx,[esi+eax*4]",
    0x004155F9: "mov ebp,DWORD PTR [ecx]",
    0x004155FB: "cmp DWORD PTR [ebp+0x114],edx",
    0x0041560D: "mov esi,DWORD PTR [esi+eax*4]",
    0x00415637: "mov eax,DWORD PTR [esi+0x150]",
    0x00415641: "push 0x4",
    0x00415643: "mov ecx,esi",
    0x00415645: "call 0x41e470",
    0x0041565A: "mov esi,DWORD PTR [esi+0x150]",
    0x0041573D: "and ebx,0xffff",
    0x00415660: "push ebx",
    0x00415661: "push 0x501",
    0x00415666: "mov ecx,esi",
    0x00415668: "call 0x45fa10",
    0x0041566D: "mov ebp,eax",
    0x0041566F: "cmp ebp,0xffffffff",
    0x00415691: "push ebp",
    0x0041569C: "call 0x45f270",
    0x00415756: "inc ecx",
    0x00415757: "push ecx",
    0x0041575A: "call 0x45f270",
    0x004157C2: "mov eax,DWORD PTR [esp+0x18]",
    0x004157C8: "add eax,0x2",
    0x004157CC: "call 0x45f270",
    0x0041E50D: "mov ecx,esi",
    0x0041E50F: "call 0x45ef70",
    0x0041E514: "mov DWORD PTR [edi],esi",
    0x0045FA26: "mov ebx,DWORD PTR [esp+0x14]",
    0x0045FA2A: "mov ebp,DWORD PTR [esp+0x18]",
    0x0045FA2E: "and ebx,0xffff",
    0x0045FA37: "call 0x45fa70",
    0x0045FA3C: "cmp eax,ebx",
    0x0045FA43: "call 0x45faa0",
    0x0045FA4A: "and ecx,0xffff",
    0x0045FA50: "cmp eax,ecx",
    0x0045FA52: "je 0x45fa66",
    0x0045FA57: "inc esi",
    0x0045FA5A: "jl 0x45fa34",
    0x0045FA66: "mov eax,esi",
    0x0045FA8D: "xor eax,eax",
    0x0045FA8F: "mov ax,WORD PTR [edx+ecx*2]",
    0x0045FABD: "xor eax,eax",
    0x0045FABF: "mov ax,WORD PTR [edx+ecx*2+0x2]",
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


def verify_selector_callers(disassembly):
    """Check complete direct-call sets for the observed selector path."""
    observed = {}
    for target, expected in EXPECTED_SELECTOR_CALLERS.items():
        actual = callers(disassembly, target)
        if actual != expected:
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            raise ValueError(
                f"direct callers to 0x{target:08x} differ "
                f"(missing={[hex(value) for value in missing]}, "
                f"unexpected={[hex(value) for value in unexpected]})"
            )
        observed[target] = actual
    return observed


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
    expected_instructions = (EXPECTED_INSTRUCTIONS | EXPECTED_CALLER_INSTRUCTIONS |
                             EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS |
                             EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS)
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
    selector_callers = verify_selector_callers(disassembly)
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
    anchored_formulas = set(EXPECTED_VARIABLE_REQUEST_FORMULAS)
    if not anchored_formulas <= unknown_sizes:
        raise ValueError("anchored request formula was unexpectedly classified as a local constant")
    derived_sites = set(EXPECTED_DERIVED_REQUEST_SIZES)
    if anchored_formulas & derived_sites:
        raise ValueError("request formula duplicates a derived-size anchor")
    remaining_unknown = unknown_sizes - derived_sites - anchored_formulas
    histogram = dict(sorted(Counter(request_sizes.values()).items()))
    print(f"Verified direct transfers to 0x{READ_HELPER:08x}: "
          f"{len(observed)} calls, {len(observed_jumps)} unconditional jumps, "
          f"{len(pointer_literals)} raw address literals; "
          f"verified {len(EXPECTED_INSTRUCTIONS)} helper, "
          f"{len(EXPECTED_CALLER_INSTRUCTIONS)} existing caller, and "
          f"{len(EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS)} variable-size caller, and "
          f"{len(EXPECTED_SELECTOR_LOOKUP_INSTRUCTIONS)} two-word selector lookup and "
          f"{len(EXPECTED_SELECTOR_ARGUMENT_CALLER_INSTRUCTIONS)} upstream argument-source anchors")
    print("Verified direct callers to selector-path routines: " + ", ".join(
        f"0x{target:08x}={len(references)}" for target, references in sorted(selector_callers.items())))
    derived = ", ".join(
        f"0x{address:08x}={expression}"
        for address, expression in sorted(EXPECTED_DERIVED_REQUEST_SIZES.items()))
    print(f"Locally traced constant request sizes: {len(request_sizes)}; "
          f"calls outside constant-only classifier: {len(unknown_sizes)} "
          f"({len(anchored_formulas)} formula-anchored, {len(derived_sites)} derived-size, "
          f"{len(remaining_unknown)} unresolved); derived-size calls: {derived}; "
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
