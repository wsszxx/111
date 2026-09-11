#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence

# --------------------------
# KAW pure codec
# --------------------------

KEYSTREAM_HEX = (
    "0ffe08670661873589cbef490dde3382e6352c9b65d2ca0adf391fdd214665f2cc7d5b16659029d554ac90cdf25d69a6"
    "9a3972405b3deba8dd0ea165f311752906add71ad13e359f3951a840dc7b8810527e2c3c7819198a0590f064e13ccd21"
    "b46f96a581a8217fdce4abb0760a49f29a225e30cdf1132cebad2dc6f34713a0df9259292d687014cccb49c238f67d32"
    "468b0664f07aef1caf73d867f87d2260e0cd635dfd80e9365c2b42c1a8db8ebbc84d8244a2f690a3b5f966283387cde7"
    "04a1fa9a9f2049770f12cd997a72fd0efaf91b7a4c59be880fdc38d202ff45597df4a2f1e7ba78a5080db0b912afc02f"
    "59e3d17526c64321f6958daa158125d69b6cc1cb75533ecdc679ba11c344d89ba674d129fffc350d72bf88c619642788"
    "9397e1b3cb262f515401378a29e6e8bf019de19a0328b48ea0e2473585289503942fd822910be31a6914c377fdcfa243"
    "157ab2a7a89bcd2bedec3419e486b7eaa1972c849cb1594061560da56e0ca63ee3c2d3c3be380715cd4a3ac1009383a7"
    "e091ccff7aa887d9a7cb94f66489bce574cd1430519d4adfc84bb216fc571d1ba38dfe198dee7246e0fe838516264a7a"
    "1e0399bff02a987b4402dc1e7e9b965ebace38fbdadde6d2a4e76b45e087c975c82b6bfca243d93f32a77ca15cd9b393"
    "35f9ea78419801c986afa0d141628a724ef9bda7a9b8565a5ed62b2cc210adffa89e246291775aa2ab923f9a7236402b"
    "ac2a4185c7ba608b857636c8684a4a0de42bb4774ca62267d198b4c7a0f24e261817d7becf1d933f34af93d53a4b8b05"
    "f3063e78851098e88c1afd3172cdb8c3c355c0686108d86cca01ff6226de5944c8801b89b903dbfa22f799c256122bd9"
    "f0d7f479ba1fa184d9f73bd1a22ef21628c6353e18876fe994e467973db565a6e148ee8918e9e015e002da6846bfb09f"
    "f1286f10c8334d015bed3401ae79a3c983286edb2d6930f22f7fc956c8bcb07016ff61e642e929e3d670d01c6845b155"
    "2949dcee963202945ce23d9698131014c25f293c5624eda6209d7ad0896c2e1157d822b64eac81763f9543b2657e2421"
    "93afa6630428a01509036bdb0d4402eb7233f71c415cc94c2c2ae11acf7dc430"
)
KEYSTREAM = bytes.fromhex(KEYSTREAM_HEX)

XOR_CONST = 0x55
RAW_PREFIX = b"02"
RAW_SUFFIX = b"\x00"


@dataclass
class KawPayload:
    raw_plain: bytes

    @property
    def magic_le(self) -> int:
        return int.from_bytes(self.raw_plain[0:4], "little")

    @property
    def seq_le(self) -> int:
        return int.from_bytes(self.raw_plain[4:8], "little")

    @property
    def body_text(self) -> str:
        return self.raw_plain[8:].decode("utf-8", errors="replace")

    @property
    def body_fields(self) -> List[str]:
        return self.body_text.split("|")


def _extract_cipher(kaw_b64: str) -> bytes:
    raw = base64.b64decode(kaw_b64)
    if len(raw) < 3:
        raise ValueError("invalid kaw: decoded bytes too short")
    if raw[:2] != RAW_PREFIX:
        raise ValueError(f"unexpected kaw prefix: {raw[:2].hex()} expected {RAW_PREFIX.hex()}")
    if raw[-1:] != RAW_SUFFIX:
        raise ValueError(f"unexpected kaw suffix: {raw[-1:].hex()} expected {RAW_SUFFIX.hex()}")
    return raw[2:-1]


def _xor_with_stream(data: bytes, stream: bytes = KEYSTREAM) -> bytes:
    if len(data) > len(stream):
        raise ValueError(f"payload length {len(data)} exceeds keystream length {len(stream)}")
    return bytes((data[i] ^ stream[i] ^ XOR_CONST) & 0xFF for i in range(len(data)))


def decode_kaw(kaw_b64: str) -> KawPayload:
    cipher = _extract_cipher(kaw_b64)
    plain = _xor_with_stream(cipher, KEYSTREAM)
    return KawPayload(raw_plain=plain)


def encode_kaw(plain_payload: bytes) -> str:
    cipher = _xor_with_stream(plain_payload, KEYSTREAM)
    raw = RAW_PREFIX + cipher + RAW_SUFFIX
    return base64.b64encode(raw).decode("ascii")


def build_plain_payload(body_text: str, seq_le: int, magic_le: int = 0x00003D2D) -> bytes:
    return (
        int(magic_le).to_bytes(4, "little", signed=False)
        + int(seq_le).to_bytes(4, "little", signed=False)
        + body_text.encode("utf-8")
    )


@dataclass
class KawTemplate:
    magic_le: int
    seq_le: int
    fields: List[str]

    @classmethod
    def from_kaw(cls, kaw_b64: str) -> "KawTemplate":
        p = decode_kaw(kaw_b64)
        return cls(magic_le=p.magic_le, seq_le=p.seq_le, fields=p.body_fields)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "KawTemplate":
        return cls(
            magic_le=int(data["magic_le"]),
            seq_le=int(data["seq_le"]),
            fields=[str(x) for x in data["fields"]],
        )

    def to_dict(self) -> Dict[str, object]:
        return {"magic_le": self.magic_le, "seq_le": self.seq_le, "fields": self.fields}

    def body_text(self, now_ts: int | None = None, field_overrides: Dict[int, str] | None = None) -> str:
        fs = list(self.fields)
        if now_ts is not None and len(fs) > 1:
            fs[1] = str(int(now_ts))
        if field_overrides:
            for idx, value in field_overrides.items():
                if idx < 0 or idx >= len(fs):
                    raise ValueError(f"field index out of range: {idx}")
                fs[idx] = str(value)
        return "|".join(fs)

    def generate_kaw(
        self,
        seq_le: int | None = None,
        now_ts: int | None = None,
        field_overrides: Dict[int, str] | None = None,
    ) -> str:
        body = self.body_text(now_ts=now_ts, field_overrides=field_overrides)
        plain = build_plain_payload(
            body_text=body,
            seq_le=self.seq_le if seq_le is None else int(seq_le),
            magic_le=self.magic_le,
        )
        return encode_kaw(plain)


def _parse_set(items: List[str]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"invalid --set item: {item!r}, expected index=value")
        k, v = item.split("=", 1)
        out[int(k)] = v
    return out


def _load_template(sample_kaw: str | None, template_json: str | None, template_file: str | None) -> KawTemplate:
    if sample_kaw:
        return KawTemplate.from_kaw(sample_kaw)
    if template_json:
        return KawTemplate.from_dict(json.loads(template_json))
    if template_file:
        with open(template_file, "r", encoding="utf-8") as f:
            return KawTemplate.from_dict(json.load(f))
    raise ValueError("template source required: --sample-kaw OR --template-json OR --template-file")


# --------------------------
# KAS pure (no so)
# --------------------------

IVP32 = (
    0xAB99184E,
    0xF3CCD768,
    0x99531AAE,
    0x669781D3,
    0x125FD5B4,
    0x9883595E,
    0x74F4CBCD,
    0x98C26A78,
)

SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)

BASE_15EAC = bytes.fromhex("3f083270fe31ce727130580c300cc2e0")
XOR_1B598 = bytes.fromhex("2dd345c0") * 4


def _rotr32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _g(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + (x & 0xFFFFFFFF)) & 0xFFFFFFFF
    v[d] = _rotr32(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = _rotr32(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + (y & 0xFFFFFFFF)) & 0xFFFFFFFF
    v[d] = _rotr32(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = _rotr32(v[b] ^ v[c], 7)


def _compress_once(h: Sequence[int], m16: Sequence[int], t32: int, last: bool) -> list[int]:
    v = [x & 0xFFFFFFFF for x in h] + [x & 0xFFFFFFFF for x in IVP32]
    v[12] ^= (t32 & 0xFFFFFFFF)
    if last:
        v[14] ^= 0xFFFFFFFF
    for s in SIGMA:
        _g(v, 0, 4, 8, 12, m16[s[0]], m16[s[1]])
        _g(v, 1, 5, 9, 13, m16[s[2]], m16[s[3]])
        _g(v, 2, 6, 10, 14, m16[s[4]], m16[s[5]])
        _g(v, 3, 7, 11, 15, m16[s[6]], m16[s[7]])
        _g(v, 0, 5, 10, 15, m16[s[8]], m16[s[9]])
        _g(v, 1, 6, 11, 12, m16[s[10]], m16[s[11]])
        _g(v, 2, 7, 8, 13, m16[s[12]], m16[s[13]])
        _g(v, 3, 4, 9, 14, m16[s[14]], m16[s[15]])
    return [(h[i] ^ v[i] ^ v[i + 8]) & 0xFFFFFFFF for i in range(8)]


def _fold_qwords_8(buf: bytes, qcount: int) -> list[int]:
    r = [0] * 8
    for i in range(qcount):
        q = struct.unpack_from("<Q", buf, i * 8)[0]
        r[i & 7] ^= q
    return r


def _q64_to_m16_words(r8: Sequence[int]) -> list[int]:
    m: list[int] = []
    for q in r8:
        m.append(q & 0xFFFFFFFF)
        m.append((q >> 32) & 0xFFFFFFFF)
    return m


def stage1_words_from_d(d: str) -> tuple[int, ...]:
    b = base64.b64encode(d.encode("utf-8"))
    if len(b) < 256 or (len(b) % 4) != 0:
        raise ValueError(f"invalid base64(d) length: {len(b)}")

    # pass1
    x2_1, x3_1 = 64, 64
    qcount1 = x3_1 >> 1
    r1 = _fold_qwords_8(b[: qcount1 * 8], qcount1)
    m1 = _q64_to_m16_words(r1)
    h = list(IVP32)
    h[0] ^= 0x01010020
    h = _compress_once(h, m1, t32=x2_1, last=False)

    # pass2
    x2_2 = len(b) // 4
    x3_2 = x2_2 - 64
    call2_raw = b[256 : 256 + 4 * x3_2]
    qcount2 = (x3_2 + 1) >> 1
    if len(call2_raw) % 8:
        call2 = call2_raw + b"\x00" * (8 - (len(call2_raw) % 8))
    else:
        call2 = call2_raw
    r2 = _fold_qwords_8(call2, qcount2)
    m2 = _q64_to_m16_words(r2)
    h = _compress_once(h, m2, t32=x2_2, last=True)
    return tuple(h)


def _words_to_in64(words: Sequence[int]) -> str:
    if len(words) != 8:
        raise ValueError(f"words length must be 8, got {len(words)}")
    return "".join(f"{(w & 0xFFFFFFFF):08x}" for w in words)


def _stage_15eac_from_in64(in64: str) -> bytes:
    deltas = bytes(((ord(c) ^ 0x30) & 0xFF) for c in in64[:16])
    return bytes((BASE_15EAC[i] ^ deltas[i]) & 0xFF for i in range(16))


def kas_from_d(d: str) -> str:
    words = stage1_words_from_d(d)
    in64 = _words_to_in64(words)
    out16 = _stage_15eac_from_in64(in64)
    tail = bytes((out16[i] ^ XOR_1B598[i]) & 0xFF for i in range(16))
    return "00" + tail.hex()


def _cmd_kaw_extract(args: argparse.Namespace) -> None:
    tpl = KawTemplate.from_kaw(args.sample_kaw)
    print(json.dumps(tpl.to_dict(), ensure_ascii=False, indent=2 if args.pretty else None))


def _cmd_kaw_replay(args: argparse.Namespace) -> None:
    tpl = KawTemplate.from_kaw(args.sample_kaw)
    rebuilt = tpl.generate_kaw(seq_le=tpl.seq_le)
    print("match=", rebuilt == args.sample_kaw)
    if rebuilt != args.sample_kaw:
        print("expected=", args.sample_kaw)
        print("actual  =", rebuilt)


def _cmd_kaw_generate(args: argparse.Namespace) -> None:
    tpl = _load_template(args.sample_kaw, args.template_json, args.template_file)
    if args.ts is not None and args.now:
        raise SystemExit("use one: --now OR --ts")
    ts = int(time.time()) if args.now else args.ts
    sets = _parse_set(args.set)
    body = tpl.body_text(now_ts=ts, field_overrides=sets)
    kaw = tpl.generate_kaw(seq_le=args.seq, now_ts=ts, field_overrides=sets)
    print(kaw)
    if args.show_body:
        print("body_text=", body)


def _cmd_kas_from_d(args: argparse.Namespace) -> None:
    words = stage1_words_from_d(args.d)
    kas = kas_from_d(args.d)
    print("words=", [f"{x:08x}" for x in words])
    print("kas  =", kas)


def _cmd_both(args: argparse.Namespace) -> None:
    tpl = _load_template(args.sample_kaw, args.template_json, args.template_file)
    if args.ts is not None and args.now:
        raise SystemExit("use one: --now OR --ts")
    ts = int(time.time()) if args.now else args.ts
    sets = _parse_set(args.set)
    kaw = tpl.generate_kaw(seq_le=args.seq, now_ts=ts, field_overrides=sets)
    d = args.path + kaw
    words = stage1_words_from_d(d)
    kas = kas_from_d(d)
    print("kaw=", kaw)
    print("d  =", d)
    print("words=", [f"{x:08x}" for x in words])
    print("kas=", kas)


def main() -> None:
    ap = argparse.ArgumentParser(description="All-in-one pure Python tool for kaw + kas (no so calls).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ke = sub.add_parser("kaw-extract", help="extract kaw template from captured kaw")
    p_ke.add_argument("--sample-kaw", required=True)
    p_ke.add_argument("--pretty", action="store_true")
    p_ke.set_defaults(func=_cmd_kaw_extract)

    p_kr = sub.add_parser("kaw-replay", help="replay check on captured kaw")
    p_kr.add_argument("--sample-kaw", required=True)
    p_kr.set_defaults(func=_cmd_kaw_replay)

    p_kg = sub.add_parser("kaw-generate", help="generate kaw from template")
    p_kg.add_argument("--sample-kaw")
    p_kg.add_argument("--template-json")
    p_kg.add_argument("--template-file")
    p_kg.add_argument("--seq", type=int)
    p_kg.add_argument("--now", action="store_true")
    p_kg.add_argument("--ts", type=int)
    p_kg.add_argument("--set", action="append", default=[])
    p_kg.add_argument("--show-body", action="store_true")
    p_kg.set_defaults(func=_cmd_kaw_generate)

    p_kd = sub.add_parser("kas-from-d", help="generate kas from d=path+kaw")
    p_kd.add_argument("--d", required=True)
    p_kd.set_defaults(func=_cmd_kas_from_d)

    p_b = sub.add_parser("both", help="generate kaw then kas from path+kaw")
    p_b.add_argument("--path", required=True, help="request path, e.g. /f/a/p")
    p_b.add_argument("--sample-kaw")
    p_b.add_argument("--template-json")
    p_b.add_argument("--template-file")
    p_b.add_argument("--seq", type=int)
    p_b.add_argument("--now", action="store_true")
    p_b.add_argument("--ts", type=int)
    p_b.add_argument("--set", action="append", default=[])
    p_b.set_defaults(func=_cmd_both)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
