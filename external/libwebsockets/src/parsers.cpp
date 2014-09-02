/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

unsigned char lextable[] = {
	/* pos 0000:   0 */    0x67 /* 'g' */, 0x25, 0x00  /* (to 0x0025 state   1) */,
	0x70 /* 'p' */, 0x27, 0x00  /* (to 0x002A state   5) */,
	0x6F /* 'o' */, 0x30, 0x00  /* (to 0x0036 state  10) */,
	0x68 /* 'h' */, 0x3C, 0x00  /* (to 0x0045 state  18) */,
	0x63 /* 'c' */, 0x45, 0x00  /* (to 0x0051 state  23) */,
	0x73 /* 's' */, 0x60, 0x00  /* (to 0x006F state  34) */,
	0x75 /* 'u' */, 0x9F, 0x00  /* (to 0x00B1 state  64) */,
	0x0D /* '.' */, 0xB3, 0x00  /* (to 0x00C8 state  84) */,
	0x61 /* 'a' */, 0xEA, 0x00  /* (to 0x0102 state 134) */,
	0x69 /* 'i' */, 0x1D, 0x01  /* (to 0x0138 state 168) */,
	0x64 /* 'd' */, 0x9C, 0x01  /* (to 0x01BA state 270) */,
	0x72 /* 'r' */, 0x9F, 0x01  /* (to 0x01C0 state 275) */,
	0x08, /* fail */
	/* pos 0025:   1 */    0xE5 /* 'e' -> */,
	/* pos 0026:   2 */    0xF4 /* 't' -> */,
	/* pos 0027:   3 */    0xA0 /* ' ' -> */,
	/* pos 0028:   4 */    0x00, 0x00                  /* - terminal marker  0 - */,
	/* pos 002a:   5 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0031 state   6) */,
	0x72 /* 'r' */, 0x4B, 0x01  /* (to 0x0178 state 216) */,
	0x08, /* fail */
	/* pos 0031:   6 */    0xF3 /* 's' -> */,
	/* pos 0032:   7 */    0xF4 /* 't' -> */,
	/* pos 0033:   8 */    0xA0 /* ' ' -> */,
	/* pos 0034:   9 */    0x00, 0x01                  /* - terminal marker  1 - */,
	/* pos 0036:  10 */    0x70 /* 'p' */, 0x07, 0x00  /* (to 0x003D state  11) */,
	0x72 /* 'r' */, 0x81, 0x00  /* (to 0x00BA state  72) */,
	0x08, /* fail */
	/* pos 003d:  11 */    0xF4 /* 't' -> */,
	/* pos 003e:  12 */    0xE9 /* 'i' -> */,
	/* pos 003f:  13 */    0xEF /* 'o' -> */,
	/* pos 0040:  14 */    0xEE /* 'n' -> */,
	/* pos 0041:  15 */    0xF3 /* 's' -> */,
	/* pos 0042:  16 */    0xA0 /* ' ' -> */,
	/* pos 0043:  17 */    0x00, 0x02                  /* - terminal marker  2 - */,
	/* pos 0045:  18 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x004C state  19) */,
	0x74 /* 't' */, 0xB1, 0x00  /* (to 0x00F9 state 126) */,
	0x08, /* fail */
	/* pos 004c:  19 */    0xF3 /* 's' -> */,
	/* pos 004d:  20 */    0xF4 /* 't' -> */,
	/* pos 004e:  21 */    0xBA /* ':' -> */,
	/* pos 004f:  22 */    0x00, 0x03                  /* - terminal marker  3 - */,
	/* pos 0051:  23 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0058 state  24) */,
	0x61 /* 'a' */, 0x2B, 0x01  /* (to 0x017F state 222) */,
	0x08, /* fail */
	/* pos 0058:  24 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x005F state  25) */,
	0x6F /* 'o' */, 0x40, 0x01  /* (to 0x019B state 248) */,
	0x08, /* fail */
	/* pos 005f:  25 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x0066 state  26) */,
	0x74 /* 't' */, 0x3F, 0x01  /* (to 0x01A1 state 253) */,
	0x08, /* fail */
	/* pos 0066:  26 */    0xE5 /* 'e' -> */,
	/* pos 0067:  27 */    0xE3 /* 'c' -> */,
	/* pos 0068:  28 */    0xF4 /* 't' -> */,
	/* pos 0069:  29 */    0xE9 /* 'i' -> */,
	/* pos 006a:  30 */    0xEF /* 'o' -> */,
	/* pos 006b:  31 */    0xEE /* 'n' -> */,
	/* pos 006c:  32 */    0xBA /* ':' -> */,
	/* pos 006d:  33 */    0x00, 0x04                  /* - terminal marker  4 - */,
	/* pos 006f:  34 */    0xE5 /* 'e' -> */,
	/* pos 0070:  35 */    0xE3 /* 'c' -> */,
	/* pos 0071:  36 */    0xAD /* '-' -> */,
	/* pos 0072:  37 */    0xF7 /* 'w' -> */,
	/* pos 0073:  38 */    0xE5 /* 'e' -> */,
	/* pos 0074:  39 */    0xE2 /* 'b' -> */,
	/* pos 0075:  40 */    0xF3 /* 's' -> */,
	/* pos 0076:  41 */    0xEF /* 'o' -> */,
	/* pos 0077:  42 */    0xE3 /* 'c' -> */,
	/* pos 0078:  43 */    0xEB /* 'k' -> */,
	/* pos 0079:  44 */    0xE5 /* 'e' -> */,
	/* pos 007a:  45 */    0xF4 /* 't' -> */,
	/* pos 007b:  46 */    0xAD /* '-' -> */,
	/* pos 007c:  47 */    0x6B /* 'k' */, 0x19, 0x00  /* (to 0x0095 state  48) */,
	0x70 /* 'p' */, 0x28, 0x00  /* (to 0x00A7 state  55) */,
	0x64 /* 'd' */, 0x3F, 0x00  /* (to 0x00C1 state  78) */,
	0x76 /* 'v' */, 0x48, 0x00  /* (to 0x00CD state  87) */,
	0x6F /* 'o' */, 0x4E, 0x00  /* (to 0x00D6 state  95) */,
	0x65 /* 'e' */, 0x53, 0x00  /* (to 0x00DE state 102) */,
	0x61 /* 'a' */, 0x5C, 0x00  /* (to 0x00EA state 113) */,
	0x6E /* 'n' */, 0x61, 0x00  /* (to 0x00F2 state 120) */,
	0x08, /* fail */
	/* pos 0095:  48 */    0xE5 /* 'e' -> */,
	/* pos 0096:  49 */    0xF9 /* 'y' -> */,
	/* pos 0097:  50 */    0x31 /* '1' */, 0x0A, 0x00  /* (to 0x00A1 state  51) */,
	0x32 /* '2' */, 0x0A, 0x00  /* (to 0x00A4 state  53) */,
	0x3A /* ':' */, 0x2E, 0x00  /* (to 0x00CB state  86) */,
	0x08, /* fail */
	/* pos 00a1:  51 */    0xBA /* ':' -> */,
	/* pos 00a2:  52 */    0x00, 0x05                  /* - terminal marker  5 - */,
	/* pos 00a4:  53 */    0xBA /* ':' -> */,
	/* pos 00a5:  54 */    0x00, 0x06                  /* - terminal marker  6 - */,
	/* pos 00a7:  55 */    0xF2 /* 'r' -> */,
	/* pos 00a8:  56 */    0xEF /* 'o' -> */,
	/* pos 00a9:  57 */    0xF4 /* 't' -> */,
	/* pos 00aa:  58 */    0xEF /* 'o' -> */,
	/* pos 00ab:  59 */    0xE3 /* 'c' -> */,
	/* pos 00ac:  60 */    0xEF /* 'o' -> */,
	/* pos 00ad:  61 */    0xEC /* 'l' -> */,
	/* pos 00ae:  62 */    0xBA /* ':' -> */,
	/* pos 00af:  63 */    0x00, 0x07                  /* - terminal marker  7 - */,
	/* pos 00b1:  64 */    0xF0 /* 'p' -> */,
	/* pos 00b2:  65 */    0xE7 /* 'g' -> */,
	/* pos 00b3:  66 */    0xF2 /* 'r' -> */,
	/* pos 00b4:  67 */    0xE1 /* 'a' -> */,
	/* pos 00b5:  68 */    0xE4 /* 'd' -> */,
	/* pos 00b6:  69 */    0xE5 /* 'e' -> */,
	/* pos 00b7:  70 */    0xBA /* ':' -> */,
	/* pos 00b8:  71 */    0x00, 0x08                  /* - terminal marker  8 - */,
	/* pos 00ba:  72 */    0xE9 /* 'i' -> */,
	/* pos 00bb:  73 */    0xE7 /* 'g' -> */,
	/* pos 00bc:  74 */    0xE9 /* 'i' -> */,
	/* pos 00bd:  75 */    0xEE /* 'n' -> */,
	/* pos 00be:  76 */    0xBA /* ':' -> */,
	/* pos 00bf:  77 */    0x00, 0x09                  /* - terminal marker  9 - */,
	/* pos 00c1:  78 */    0xF2 /* 'r' -> */,
	/* pos 00c2:  79 */    0xE1 /* 'a' -> */,
	/* pos 00c3:  80 */    0xE6 /* 'f' -> */,
	/* pos 00c4:  81 */    0xF4 /* 't' -> */,
	/* pos 00c5:  82 */    0xBA /* ':' -> */,
	/* pos 00c6:  83 */    0x00, 0x0A                  /* - terminal marker 10 - */,
	/* pos 00c8:  84 */    0x8A /* '.' -> */,
	/* pos 00c9:  85 */    0x00, 0x0B                  /* - terminal marker 11 - */,
	/* pos 00cb:  86 */    0x00, 0x0C                  /* - terminal marker 12 - */,
	/* pos 00cd:  87 */    0xE5 /* 'e' -> */,
	/* pos 00ce:  88 */    0xF2 /* 'r' -> */,
	/* pos 00cf:  89 */    0xF3 /* 's' -> */,
	/* pos 00d0:  90 */    0xE9 /* 'i' -> */,
	/* pos 00d1:  91 */    0xEF /* 'o' -> */,
	/* pos 00d2:  92 */    0xEE /* 'n' -> */,
	/* pos 00d3:  93 */    0xBA /* ':' -> */,
	/* pos 00d4:  94 */    0x00, 0x0D                  /* - terminal marker 13 - */,
	/* pos 00d6:  95 */    0xF2 /* 'r' -> */,
	/* pos 00d7:  96 */    0xE9 /* 'i' -> */,
	/* pos 00d8:  97 */    0xE7 /* 'g' -> */,
	/* pos 00d9:  98 */    0xE9 /* 'i' -> */,
	/* pos 00da:  99 */    0xEE /* 'n' -> */,
	/* pos 00db: 100 */    0xBA /* ':' -> */,
	/* pos 00dc: 101 */    0x00, 0x0E                  /* - terminal marker 14 - */,
	/* pos 00de: 102 */    0xF8 /* 'x' -> */,
	/* pos 00df: 103 */    0xF4 /* 't' -> */,
	/* pos 00e0: 104 */    0xE5 /* 'e' -> */,
	/* pos 00e1: 105 */    0xEE /* 'n' -> */,
	/* pos 00e2: 106 */    0xF3 /* 's' -> */,
	/* pos 00e3: 107 */    0xE9 /* 'i' -> */,
	/* pos 00e4: 108 */    0xEF /* 'o' -> */,
	/* pos 00e5: 109 */    0xEE /* 'n' -> */,
	/* pos 00e6: 110 */    0xF3 /* 's' -> */,
	/* pos 00e7: 111 */    0xBA /* ':' -> */,
	/* pos 00e8: 112 */    0x00, 0x0F                  /* - terminal marker 15 - */,
	/* pos 00ea: 113 */    0xE3 /* 'c' -> */,
	/* pos 00eb: 114 */    0xE3 /* 'c' -> */,
	/* pos 00ec: 115 */    0xE5 /* 'e' -> */,
	/* pos 00ed: 116 */    0xF0 /* 'p' -> */,
	/* pos 00ee: 117 */    0xF4 /* 't' -> */,
	/* pos 00ef: 118 */    0xBA /* ':' -> */,
	/* pos 00f0: 119 */    0x00, 0x10                  /* - terminal marker 16 - */,
	/* pos 00f2: 120 */    0xEF /* 'o' -> */,
	/* pos 00f3: 121 */    0xEE /* 'n' -> */,
	/* pos 00f4: 122 */    0xE3 /* 'c' -> */,
	/* pos 00f5: 123 */    0xE5 /* 'e' -> */,
	/* pos 00f6: 124 */    0xBA /* ':' -> */,
	/* pos 00f7: 125 */    0x00, 0x11                  /* - terminal marker 17 - */,
	/* pos 00f9: 126 */    0xF4 /* 't' -> */,
	/* pos 00fa: 127 */    0xF0 /* 'p' -> */,
	/* pos 00fb: 128 */    0xAF /* '/' -> */,
	/* pos 00fc: 129 */    0xB1 /* '1' -> */,
	/* pos 00fd: 130 */    0xAE /* '.' -> */,
	/* pos 00fe: 131 */    0xB1 /* '1' -> */,
	/* pos 00ff: 132 */    0xA0 /* ' ' -> */,
	/* pos 0100: 133 */    0x00, 0x12                  /* - terminal marker 18 - */,
	/* pos 0102: 134 */    0x63 /* 'c' */, 0x07, 0x00  /* (to 0x0109 state 135) */,
	0x75 /* 'u' */, 0x88, 0x00  /* (to 0x018D state 235) */,
	0x08, /* fail */
	/* pos 0109: 135 */    0xE3 /* 'c' -> */,
	/* pos 010a: 136 */    0xE5 /* 'e' -> */,
	/* pos 010b: 137 */    0x70 /* 'p' */, 0x07, 0x00  /* (to 0x0112 state 138) */,
	0x73 /* 's' */, 0x0E, 0x00  /* (to 0x011C state 141) */,
	0x08, /* fail */
	/* pos 0112: 138 */    0xF4 /* 't' -> */,
	/* pos 0113: 139 */    0x3A /* ':' */, 0x07, 0x00  /* (to 0x011A state 140) */,
	0x2D /* '-' */, 0x47, 0x00  /* (to 0x015D state 197) */,
	0x08, /* fail */
	/* pos 011a: 140 */    0x00, 0x13                  /* - terminal marker 19 - */,
	/* pos 011c: 141 */    0xF3 /* 's' -> */,
	/* pos 011d: 142 */    0xAD /* '-' -> */,
	/* pos 011e: 143 */    0xE3 /* 'c' -> */,
	/* pos 011f: 144 */    0xEF /* 'o' -> */,
	/* pos 0120: 145 */    0xEE /* 'n' -> */,
	/* pos 0121: 146 */    0xF4 /* 't' -> */,
	/* pos 0122: 147 */    0xF2 /* 'r' -> */,
	/* pos 0123: 148 */    0xEF /* 'o' -> */,
	/* pos 0124: 149 */    0xEC /* 'l' -> */,
	/* pos 0125: 150 */    0xAD /* '-' -> */,
	/* pos 0126: 151 */    0xF2 /* 'r' -> */,
	/* pos 0127: 152 */    0xE5 /* 'e' -> */,
	/* pos 0128: 153 */    0xF1 /* 'q' -> */,
	/* pos 0129: 154 */    0xF5 /* 'u' -> */,
	/* pos 012a: 155 */    0xE5 /* 'e' -> */,
	/* pos 012b: 156 */    0xF3 /* 's' -> */,
	/* pos 012c: 157 */    0xF4 /* 't' -> */,
	/* pos 012d: 158 */    0xAD /* '-' -> */,
	/* pos 012e: 159 */    0xE8 /* 'h' -> */,
	/* pos 012f: 160 */    0xE5 /* 'e' -> */,
	/* pos 0130: 161 */    0xE1 /* 'a' -> */,
	/* pos 0131: 162 */    0xE4 /* 'd' -> */,
	/* pos 0132: 163 */    0xE5 /* 'e' -> */,
	/* pos 0133: 164 */    0xF2 /* 'r' -> */,
	/* pos 0134: 165 */    0xF3 /* 's' -> */,
	/* pos 0135: 166 */    0xBA /* ':' -> */,
	/* pos 0136: 167 */    0x00, 0x14                  /* - terminal marker 20 - */,
	/* pos 0138: 168 */    0xE6 /* 'f' -> */,
	/* pos 0139: 169 */    0xAD /* '-' -> */,
	/* pos 013a: 170 */    0x6D /* 'm' */, 0x07, 0x00  /* (to 0x0141 state 171) */,
	0x6E /* 'n' */, 0x14, 0x00  /* (to 0x0151 state 186) */,
	0x08, /* fail */
	/* pos 0141: 171 */    0xEF /* 'o' -> */,
	/* pos 0142: 172 */    0xE4 /* 'd' -> */,
	/* pos 0143: 173 */    0xE9 /* 'i' -> */,
	/* pos 0144: 174 */    0xE6 /* 'f' -> */,
	/* pos 0145: 175 */    0xE9 /* 'i' -> */,
	/* pos 0146: 176 */    0xE5 /* 'e' -> */,
	/* pos 0147: 177 */    0xE4 /* 'd' -> */,
	/* pos 0148: 178 */    0xAD /* '-' -> */,
	/* pos 0149: 179 */    0xF3 /* 's' -> */,
	/* pos 014a: 180 */    0xE9 /* 'i' -> */,
	/* pos 014b: 181 */    0xEE /* 'n' -> */,
	/* pos 014c: 182 */    0xE3 /* 'c' -> */,
	/* pos 014d: 183 */    0xE5 /* 'e' -> */,
	/* pos 014e: 184 */    0xBA /* ':' -> */,
	/* pos 014f: 185 */    0x00, 0x15                  /* - terminal marker 21 - */,
	/* pos 0151: 186 */    0xEF /* 'o' -> */,
	/* pos 0152: 187 */    0xEE /* 'n' -> */,
	/* pos 0153: 188 */    0xE5 /* 'e' -> */,
	/* pos 0154: 189 */    0xAD /* '-' -> */,
	/* pos 0155: 190 */    0xED /* 'm' -> */,
	/* pos 0156: 191 */    0xE1 /* 'a' -> */,
	/* pos 0157: 192 */    0xF4 /* 't' -> */,
	/* pos 0158: 193 */    0xE3 /* 'c' -> */,
	/* pos 0159: 194 */    0xE8 /* 'h' -> */,
	/* pos 015a: 195 */    0xBA /* ':' -> */,
	/* pos 015b: 196 */    0x00, 0x16                  /* - terminal marker 22 - */,
	/* pos 015d: 197 */    0x65 /* 'e' */, 0x07, 0x00  /* (to 0x0164 state 198) */,
	0x6C /* 'l' */, 0x0E, 0x00  /* (to 0x016E state 207) */,
	0x08, /* fail */
	/* pos 0164: 198 */    0xEE /* 'n' -> */,
	/* pos 0165: 199 */    0xE3 /* 'c' -> */,
	/* pos 0166: 200 */    0xEF /* 'o' -> */,
	/* pos 0167: 201 */    0xE4 /* 'd' -> */,
	/* pos 0168: 202 */    0xE9 /* 'i' -> */,
	/* pos 0169: 203 */    0xEE /* 'n' -> */,
	/* pos 016a: 204 */    0xE7 /* 'g' -> */,
	/* pos 016b: 205 */    0xBA /* ':' -> */,
	/* pos 016c: 206 */    0x00, 0x17                  /* - terminal marker 23 - */,
	/* pos 016e: 207 */    0xE1 /* 'a' -> */,
	/* pos 016f: 208 */    0xEE /* 'n' -> */,
	/* pos 0170: 209 */    0xE7 /* 'g' -> */,
	/* pos 0171: 210 */    0xF5 /* 'u' -> */,
	/* pos 0172: 211 */    0xE1 /* 'a' -> */,
	/* pos 0173: 212 */    0xE7 /* 'g' -> */,
	/* pos 0174: 213 */    0xE5 /* 'e' -> */,
	/* pos 0175: 214 */    0xBA /* ':' -> */,
	/* pos 0176: 215 */    0x00, 0x18                  /* - terminal marker 24 - */,
	/* pos 0178: 216 */    0xE1 /* 'a' -> */,
	/* pos 0179: 217 */    0xE7 /* 'g' -> */,
	/* pos 017a: 218 */    0xED /* 'm' -> */,
	/* pos 017b: 219 */    0xE1 /* 'a' -> */,
	/* pos 017c: 220 */    0xBA /* ':' -> */,
	/* pos 017d: 221 */    0x00, 0x19                  /* - terminal marker 25 - */,
	/* pos 017f: 222 */    0xE3 /* 'c' -> */,
	/* pos 0180: 223 */    0xE8 /* 'h' -> */,
	/* pos 0181: 224 */    0xE5 /* 'e' -> */,
	/* pos 0182: 225 */    0xAD /* '-' -> */,
	/* pos 0183: 226 */    0xE3 /* 'c' -> */,
	/* pos 0184: 227 */    0xEF /* 'o' -> */,
	/* pos 0185: 228 */    0xEE /* 'n' -> */,
	/* pos 0186: 229 */    0xF4 /* 't' -> */,
	/* pos 0187: 230 */    0xF2 /* 'r' -> */,
	/* pos 0188: 231 */    0xEF /* 'o' -> */,
	/* pos 0189: 232 */    0xEC /* 'l' -> */,
	/* pos 018a: 233 */    0xBA /* ':' -> */,
	/* pos 018b: 234 */    0x00, 0x1A                  /* - terminal marker 26 - */,
	/* pos 018d: 235 */    0xF4 /* 't' -> */,
	/* pos 018e: 236 */    0xE8 /* 'h' -> */,
	/* pos 018f: 237 */    0xEF /* 'o' -> */,
	/* pos 0190: 238 */    0xF2 /* 'r' -> */,
	/* pos 0191: 239 */    0xE9 /* 'i' -> */,
	/* pos 0192: 240 */    0xFA /* 'z' -> */,
	/* pos 0193: 241 */    0xE1 /* 'a' -> */,
	/* pos 0194: 242 */    0xF4 /* 't' -> */,
	/* pos 0195: 243 */    0xE9 /* 'i' -> */,
	/* pos 0196: 244 */    0xEF /* 'o' -> */,
	/* pos 0197: 245 */    0xEE /* 'n' -> */,
	/* pos 0198: 246 */    0xBA /* ':' -> */,
	/* pos 0199: 247 */    0x00, 0x1B                  /* - terminal marker 27 - */,
	/* pos 019b: 248 */    0xEB /* 'k' -> */,
	/* pos 019c: 249 */    0xE9 /* 'i' -> */,
	/* pos 019d: 250 */    0xE5 /* 'e' -> */,
	/* pos 019e: 251 */    0xBA /* ':' -> */,
	/* pos 019f: 252 */    0x00, 0x1C                  /* - terminal marker 28 - */,
	/* pos 01a1: 253 */    0xE5 /* 'e' -> */,
	/* pos 01a2: 254 */    0xEE /* 'n' -> */,
	/* pos 01a3: 255 */    0xF4 /* 't' -> */,
	/* pos 01a4: 256 */    0xAD /* '-' -> */,
	/* pos 01a5: 257 */    0x6C /* 'l' */, 0x07, 0x00  /* (to 0x01AC state 258) */,
	0x74 /* 't' */, 0x0C, 0x00  /* (to 0x01B4 state 265) */,
	0x08, /* fail */
	/* pos 01ac: 258 */    0xE5 /* 'e' -> */,
	/* pos 01ad: 259 */    0xEE /* 'n' -> */,
	/* pos 01ae: 260 */    0xE7 /* 'g' -> */,
	/* pos 01af: 261 */    0xF4 /* 't' -> */,
	/* pos 01b0: 262 */    0xE8 /* 'h' -> */,
	/* pos 01b1: 263 */    0xBA /* ':' -> */,
	/* pos 01b2: 264 */    0x00, 0x1D                  /* - terminal marker 29 - */,
	/* pos 01b4: 265 */    0xF9 /* 'y' -> */,
	/* pos 01b5: 266 */    0xF0 /* 'p' -> */,
	/* pos 01b6: 267 */    0xE5 /* 'e' -> */,
	/* pos 01b7: 268 */    0xBA /* ':' -> */,
	/* pos 01b8: 269 */    0x00, 0x1E                  /* - terminal marker 30 - */,
	/* pos 01ba: 270 */    0xE1 /* 'a' -> */,
	/* pos 01bb: 271 */    0xF4 /* 't' -> */,
	/* pos 01bc: 272 */    0xE5 /* 'e' -> */,
	/* pos 01bd: 273 */    0xBA /* ':' -> */,
	/* pos 01be: 274 */    0x00, 0x1F                  /* - terminal marker 31 - */,
	/* pos 01c0: 275 */    0x61 /* 'a' */, 0x07, 0x00  /* (to 0x01C7 state 276) */,
	0x65 /* 'e' */, 0x0A, 0x00  /* (to 0x01CD state 281) */,
	0x08, /* fail */
	/* pos 01c7: 276 */    0xEE /* 'n' -> */,
	/* pos 01c8: 277 */    0xE7 /* 'g' -> */,
	/* pos 01c9: 278 */    0xE5 /* 'e' -> */,
	/* pos 01ca: 279 */    0xBA /* ':' -> */,
	/* pos 01cb: 280 */    0x00, 0x20                  /* - terminal marker 32 - */,
	/* pos 01cd: 281 */    0xE6 /* 'f' -> */,
	/* pos 01ce: 282 */    0xE5 /* 'e' -> */,
	/* pos 01cf: 283 */    0xF2 /* 'r' -> */,
	/* pos 01d0: 284 */    0xE5 /* 'e' -> */,
	/* pos 01d1: 285 */    0xF2 /* 'r' -> */,
	/* pos 01d2: 286 */    0xBA /* ':' -> */,
	/* pos 01d3: 287 */    0x00, 0x21                  /* - terminal marker 33 - */,
	/* total size 469 bytes */

};

#define FAIL_CHAR 0x08

int lextable_decode(int pos, char c)
{

	c = tolower(c);

	while (1) {
		if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
			if ((lextable[pos] & 0x7f) != c)
				return -1;
			/* fall thru */
			pos++;
			if (lextable[pos] == FAIL_CHAR)
				return -1;
			return pos;
		}
		/* b7 = 0, end or 3-byte */
		if (lextable[pos] < FAIL_CHAR) /* terminal marker */
			return pos;

		if (lextable[pos] == c) /* goto */
			return pos + (lextable[pos + 1]) +
						(lextable[pos + 2] << 8);
		/* fall thru goto */
		pos += 3;
		/* continue */
	}
}

int lws_allocate_header_table(struct libwebsocket *wsi)
{
	wsi->u.hdr.ah = (allocated_headers*)malloc(sizeof(*wsi->u.hdr.ah));
	if (wsi->u.hdr.ah == NULL) {
		lwsl_err("Out of memory\n");
		return -1;
	}
	memset(wsi->u.hdr.ah->frag_index, 0, sizeof(wsi->u.hdr.ah->frag_index));
	wsi->u.hdr.ah->next_frag_index = 0;
	wsi->u.hdr.ah->pos = 0;

	return 0;
}

LWS_VISIBLE int lws_hdr_total_length(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return len;
}

LWS_VISIBLE int lws_hdr_copy(struct libwebsocket *wsi, char *dest, int len,
						enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;

	if (toklen >= len)
		return -1;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;

	do {
		strcpy(dest,
			&wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset]);
		dest += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return toklen;
}

char *lws_hdr_simple_ptr(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return NULL;

	return &wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset];
}

int lws_hdr_simple_create(struct libwebsocket *wsi,
				enum lws_token_indexes h, const char *s)
{
	wsi->u.hdr.ah->next_frag_index++;
	if (wsi->u.hdr.ah->next_frag_index ==
	       sizeof(wsi->u.hdr.ah->frags) / sizeof(wsi->u.hdr.ah->frags[0])) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->u.hdr.ah->frag_index[h] = wsi->u.hdr.ah->next_frag_index;

	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].next_frag_index =
									      0;

	do {
		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_err("Ran out of header data space\n");
			return -1;
		}
		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = *s;
		if (*s)
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len++;
	} while (*s++);

	return 0;
}

static char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static int issue_char(struct libwebsocket *wsi, unsigned char c)
{
	if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
		lwsl_warn("excessive header content\n");
		return -1;
	}

	if( wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len >= 
		wsi->u.hdr.current_token_limit) {
		lwsl_warn("header %i exceeds limit\n", wsi->u.hdr.parser_state);
		return 1;
	};

	wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
	if (c)
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;

	return 0;
}

int libwebsocket_parse(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->u.hdr.parser_state) {
	case WSI_TOKEN_GET_URI:
	case WSI_TOKEN_POST_URI:
	case WSI_TOKEN_OPTIONS_URI:
	case WSI_TOKEN_HOST:
	case WSI_TOKEN_CONNECTION:
	case WSI_TOKEN_KEY1:
	case WSI_TOKEN_KEY2:
	case WSI_TOKEN_PROTOCOL:
	case WSI_TOKEN_UPGRADE:
	case WSI_TOKEN_ORIGIN:
	case WSI_TOKEN_SWORIGIN:
	case WSI_TOKEN_DRAFT:
	case WSI_TOKEN_CHALLENGE:
	case WSI_TOKEN_KEY:
	case WSI_TOKEN_VERSION:
	case WSI_TOKEN_ACCEPT:
	case WSI_TOKEN_NONCE:
	case WSI_TOKEN_EXTENSIONS:
	case WSI_TOKEN_HTTP:
	case WSI_TOKEN_HTTP_ACCEPT:
	case WSI_TOKEN_HTTP_AC_REQUEST_HEADERS:
	case WSI_TOKEN_HTTP_IF_MODIFIED_SINCE:
	case WSI_TOKEN_HTTP_IF_NONE_MATCH:
	case WSI_TOKEN_HTTP_ACCEPT_ENCODING:
	case WSI_TOKEN_HTTP_ACCEPT_LANGUAGE:
	case WSI_TOKEN_HTTP_PRAGMA:
	case WSI_TOKEN_HTTP_CACHE_CONTROL:
	case WSI_TOKEN_HTTP_AUTHORIZATION:
	case WSI_TOKEN_HTTP_COOKIE:
	case WSI_TOKEN_HTTP_CONTENT_LENGTH:
	case WSI_TOKEN_HTTP_CONTENT_TYPE:
	case WSI_TOKEN_HTTP_DATE:
	case WSI_TOKEN_HTTP_RANGE:
	case WSI_TOKEN_HTTP_REFERER:


		lwsl_parser("WSI_TOK_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional initial space swallow */
		if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->frag_index[
				      wsi->u.hdr.parser_state]].len && c == ' ')
			break;

		if ((wsi->u.hdr.parser_state != WSI_TOKEN_GET_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_POST_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_OPTIONS_URI))
			goto check_eol;

		/* special URI processing... end at space */

		if (c == ' ') {
			/* enforce starting with / */
			if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len)
				if (issue_char(wsi, '/') < 0)
					return -1;
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			goto spill;
		}

		/* special URI processing... convert %xx */

		switch (wsi->u.hdr.ues) {
		case URIES_IDLE:
			if (c == '%') {
				wsi->u.hdr.ues = URIES_SEEN_PERCENT;
				goto swallow;
			}
			break;
		case URIES_SEEN_PERCENT:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				if (issue_char(wsi, '%') < 0)
					return -1;
				wsi->u.hdr.ues = URIES_IDLE;
				/* continue on to assess c */
				break;
			}
			wsi->u.hdr.esc_stash = c;
			wsi->u.hdr.ues = URIES_SEEN_PERCENT_H1;
			goto swallow;
			
		case URIES_SEEN_PERCENT_H1:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				issue_char(wsi, '%');
				wsi->u.hdr.ues = URIES_IDLE;
				/* regurgitate + assess */
				if (libwebsocket_parse(context, wsi, wsi->u.hdr.esc_stash) < 0)
					return -1;
				/* continue on to assess c */
				break;
			}
			c = (char_to_hex(wsi->u.hdr.esc_stash) << 4) |
					char_to_hex(c);
			wsi->u.hdr.ues = URIES_IDLE;
			break;
		}

		/*
		 * special URI processing... 
		 *  convert /.. or /... or /../ etc to /
		 *  convert /./ to /
		 *  convert // or /// etc to /
		 *  leave /.dir or whatever alone
		 */

		switch (wsi->u.hdr.ups) {
		case URIPS_IDLE:
			/* issue the first / always */
			if (c == '/')
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_SEEN_SLASH:
			/* swallow subsequent slashes */
			if (c == '/')
				goto swallow;
			/* track and swallow the first . after / */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT;
				goto swallow;
			} else
				wsi->u.hdr.ups = URIPS_IDLE;
			break;
		case URIPS_SEEN_SLASH_DOT:
			/* swallow second . */
			if (c == '.') {
				/* 
				 * back up one dir level if possible
				 * safe against header fragmentation because
				 * the method URI can only be in 1 fragment
				 */
				if (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 2) {
					wsi->u.hdr.ah->pos--;
					wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					do {
						wsi->u.hdr.ah->pos--;
						wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					} while (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 1 &&
							wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos] != '/');
				}
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT_DOT;
				goto swallow;
			}
			/* change /./ to / */
			if (c == '/') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				goto swallow;
			}
			/* it was like /.dir ... regurgitate the . */
			wsi->u.hdr.ups = URIPS_IDLE;
			issue_char(wsi, '.');
			break;
			
		case URIPS_SEEN_SLASH_DOT_DOT:
			/* swallow prior .. chars and any subsequent . */
			if (c == '.')
				goto swallow;
			/* last issued was /, so another / == // */
			if (c == '/')
				goto swallow;
			else /* last we issued was / so SEEN_SLASH */
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_ARGUMENTS:
			/* leave them alone */
			break;
		}

check_eol:

		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE &&
								  c == '\x0d') {
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			lwsl_parser("*\n");
		}

		if (c == '?') { /* start of URI arguments */
			/* seal off uri header */
			wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = '\0';

			/* move to using WSI_TOKEN_HTTP_URI_ARGS */
			wsi->u.hdr.ah->next_frag_index++;
			wsi->u.hdr.ah->frags[
				wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len = 0;
			wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

			wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] =
						 wsi->u.hdr.ah->next_frag_index;

			/* defeat normal uri path processing */
			wsi->u.hdr.ups = URIPS_ARGUMENTS;
			goto swallow;
		}

spill:
		{
			int issue_result = issue_char(wsi, c);
			if (issue_result < 0) {
				return -1;
			}
			else if(issue_result > 0) {
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			};
		};
swallow:
		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
			goto set_parsing_complete;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		lwsl_parser("WSI_TOKEN_NAME_PART '%c'\n", c);

		wsi->u.hdr.lextable_pos =
				lextable_decode(wsi->u.hdr.lextable_pos, c);

		if (wsi->u.hdr.lextable_pos < 0) {
			/* this is not a header we know about */
			if (wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP]) {
				/*
				 * altready had the method, no idea what
				 * this crap is, ignore
				 */
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			/*
			 * hm it's an unknown http method in fact,
			 * treat as dangerous
			 */

			lwsl_info("Unknown method - dropping\n");
			return -1;
		}
		if (lextable[wsi->u.hdr.lextable_pos] < FAIL_CHAR) {

			/* terminal state */

			n = (lextable[wsi->u.hdr.lextable_pos] << 8) | lextable[wsi->u.hdr.lextable_pos + 1];

			lwsl_parser("known hdr %d\n", n);
			if (n == WSI_TOKEN_GET_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI]) {
				lwsl_warn("Duplicated GET\n");
				return -1;
			} else if (n == WSI_TOKEN_POST_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI]) {
				lwsl_warn("Duplicated POST\n");
				return -1;
			} else if (n == WSI_TOKEN_OPTIONS_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI]) {
				lwsl_warn("Duplicated OPTIONS\n");
				return -1;
			}

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->u.hdr.parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);

			if( context->token_limits ) {
				wsi->u.hdr.current_token_limit = \
					context->token_limits->token_limit[wsi->u.hdr.parser_state];
			}
			else {
				wsi->u.hdr.current_token_limit = sizeof(wsi->u.hdr.ah->data);
			};

			if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;

			goto start_fragment;
		}
		break;

start_fragment:
		wsi->u.hdr.ah->next_frag_index++;
		if (wsi->u.hdr.ah->next_frag_index ==
				sizeof(wsi->u.hdr.ah->frags) /
					      sizeof(wsi->u.hdr.ah->frags[0])) {
			lwsl_warn("More hdr frags than we can deal with\n");
			return -1;
		}

		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
		wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

		n = wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state];
		if (!n) { /* first fragment */
			wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state] =
						 wsi->u.hdr.ah->next_frag_index;
			break;
		}
		/* continuation */
		while (wsi->u.hdr.ah->frags[n].next_frag_index)
				n = wsi->u.hdr.ah->frags[n].next_frag_index;
		wsi->u.hdr.ah->frags[n].next_frag_index =
						 wsi->u.hdr.ah->next_frag_index;

		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_warn("excessive header content\n");
			return -1;
		}

		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = ' ';
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;
		break;

		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
		lwsl_parser("WSI_TOKEN_SKIPPING '%c'\n", c);

		if (c == '\x0d')
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;

	case WSI_TOKEN_SKIPPING_SAW_CR:
		lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a') {
			wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.hdr.lextable_pos = 0;
		} else
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
		break;
		/* we're done, ignore anything else */

	case WSI_PARSING_COMPLETE:
		lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
		break;

	default:	/* keep gcc happy */
		break;
	}

	return 0;

set_parsing_complete:

	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		lwsl_parser("v%02d hdrs completed\n", wsi->ietf_spec_revision);
	}
	wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return 0;
}


/**
 * lws_frame_is_binary: true if the current frame was sent in binary mode
 *
 * @wsi: the connection we are inquiring about
 *
 * This is intended to be called from the LWS_CALLBACK_RECEIVE callback if
 * it's interested to see if the frame it's dealing with was sent in binary
 * mode.
 */

LWS_VISIBLE int lws_frame_is_binary(struct libwebsocket *wsi)
{
	return wsi->u.ws.frame_is_binary;
}

int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	struct lws_tokens eff_buf;
	int ret = 0;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:

		switch (wsi->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->u.ws.all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_rx_sm: unknown spec version %d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_MASK_NONCE_1:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_2;
		break;
	case LWS_RXPS_04_MASK_NONCE_2:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_3;
		break;
	case LWS_RXPS_04_MASK_NONCE_3:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->u.ws.frame_mask_index = 0;

		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_1;
		break;

	/*
	 *  04 logical framing from the spec (all this is masked when incoming
	 *  and has to be unmasked)
	 *
	 * We ignore the possibility of extension data because we don't
	 * negotiate any extensions at the moment.
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-------+-+-------------+-------------------------------+
	 *   |F|R|R|R| opcode|R| Payload len |    Extended payload length    |
	 *   |I|S|S|S|  (4)  |S|     (7)     |             (16/63)           |
	 *   |N|V|V|V|       |V|             |   (if payload len==126/127)   |
	 *   | |1|2|3|       |4|             |                               |
	 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 *   |     Extended payload length continued, if payload len == 127  |
	 *   + - - - - - - - - - - - - - - - +-------------------------------+
	 *   |                               |         Extension data        |
	 *   +-------------------------------+ - - - - - - - - - - - - - - - +
	 *   :                                                               :
	 *   +---------------------------------------------------------------+
	 *   :                       Application data                        :
	 *   +---------------------------------------------------------------+
	 *
	 *  We pass payload through to userland as soon as we get it, ignoring
	 *  FIN.  It's up to userland to buffer it up if it wants to see a
	 *  whole unfragmented block of the original size (which may be up to
	 *  2^63 long!)
	 */

	case LWS_RXPS_04_FRAME_HDR_1:
handle_first:

		wsi->u.ws.opcode = c & 0xf;
		wsi->u.ws.rsv = c & 0x70;
		wsi->u.ws.final = !!((c >> 7) & 1);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			wsi->u.ws.frame_is_binary =
			     wsi->u.ws.opcode == LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		}
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		wsi->u.ws.this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->u.ws.rx_packet_length = c & 0x7f;
			if (wsi->u.ws.this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->u.ws.rx_packet_length)
					wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
				else {
					wsi->lws_rx_parse_state = LWS_RXPS_NEW;
					goto spill;
				}
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		wsi->u.ws.rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->u.ws.rx_packet_length |= c;
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (c & 0x80) {
			lwsl_warn("b63 of length must be zero\n");
			/* kill the connection */
			return -1;
		}
#if defined __LP64__
		wsi->u.ws.rx_packet_length = ((size_t)c) << 56;
#else
		wsi->u.ws.rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->u.ws.rx_packet_length |= ((size_t)c);
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->u.ws.frame_masking_nonce_04[0] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->u.ws.frame_mask_index = 0;
		if (wsi->u.ws.rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:

		if (!wsi->u.ws.rx_user_buffer)
			lwsl_err("NULL user buffer...\n");

		if (wsi->u.ws.all_zero_nonce)
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] = c;
		else
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] =
				   c ^ wsi->u.ws.frame_masking_nonce_04[
					    (wsi->u.ws.frame_mask_index++) & 3];

		if (--wsi->u.ws.rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to LWS_MAX_SOCKET_IO_BUF
		 */

		if (!wsi->protocol->rx_buffer_size &&
			 		wsi->u.ws.rx_user_buffer_head !=
			 				  LWS_MAX_SOCKET_IO_BUF)
			break;
		else
			if (wsi->protocol->rx_buffer_size &&
					wsi->u.ws.rx_user_buffer_head !=
						  wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__CLOSE:
			/* is this an acknowledgement of our close? */
			if (wsi->state == WSI_STATE_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen client close ack\n");
				return -1;
			}
			lwsl_parser("server sees client close packet\n");
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
				&wsi->u.ws.rx_user_buffer[
					LWS_SEND_BUFFER_PRE_PADDING],
					wsi->u.ws.rx_user_buffer_head,
							       LWS_WRITE_CLOSE);
			if (n < 0)
				lwsl_info("write of close ack failed %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->u.ws.rx_user_buffer_head);
			lwsl_hexdump(&wsi->u.ws.rx_user_buffer[
					LWS_SEND_BUFFER_PRE_PADDING],
						 wsi->u.ws.rx_user_buffer_head);
			/* parrot the ping packet payload back as a pong */
			n = libwebsocket_write(wsi, (unsigned char *)
			&wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				 wsi->u.ws.rx_user_buffer_head, LWS_WRITE_PONG);
			if (n < 0)
				return -1;
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__PONG:
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
		case LWS_WS_OPCODE_07__CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
							wsi->u.ws.opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->u.ws.rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;

			if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX,
					&eff_buf, 0) <= 0) /* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
							      wsi->u.ws.opcode);

			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using libwebsocket_write
		 */

		eff_buf.token = &wsi->u.ws.rx_user_buffer[
						LWS_SEND_BUFFER_PRE_PADDING];
		eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;
		
		if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_PAYLOAD_RX, &eff_buf, 0) < 0)
			return -1;

		if (eff_buf.token_len > 0) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback)
				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi->protocol->owning_server,
						wsi, LWS_CALLBACK_RECEIVE,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
		    else
			    lwsl_err("No callback on payload spill!\n");
		}

		wsi->u.ws.rx_user_buffer_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
}


/**
 * libwebsockets_remaining_packet_payload() - Bytes to come before "overall"
 *					      rx packet is complete
 * @wsi:		Websocket instance (available from user callback)
 *
 *	This function is intended to be called from the callback if the
 *  user code is interested in "complete packets" from the client.
 *  libwebsockets just passes through payload as it comes and issues a buffer
 *  additionally when it hits a built-in limit.  The LWS_CALLBACK_RECEIVE
 *  callback handler can use this API to find out if the buffer it has just
 *  been given is the last piece of a "complete packet" from the client --
 *  when that is the case libwebsockets_remaining_packet_payload() will return
 *  0.
 *
 *  Many protocols won't care becuse their packets are always small.
 */

LWS_VISIBLE size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi)
{
	return wsi->u.ws.rx_packet_length;
}
