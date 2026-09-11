import base64
import hashlib
import hmac
import os
import random
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import Dict, Optional, Sequence, Union
import urllib
from urllib.parse import parse_qs, unquote

# Avoid local collision with stdlib `re` from sibling file `re.py` in repo root.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path = [p for p in sys.path if p not in ("", str(_ROOT))]
_KAW_DIR = _ROOT / "kaw"
if str(_KAW_DIR) not in sys.path:
    sys.path.append(str(_KAW_DIR))

from fastapi import FastAPI, HTTPException, Query, Request
from Crypto.Cipher import AES
from kaw_kas_pure_onefile import KawTemplate, kas_from_d


app = FastAPI(title="Atlas Demo API", version="1.0.0")


HMAC_KEY_HEX = (
    "686E6E613653616E4664316E34337A4C6A4352726479764C7168794A42773441"
    "6F384E705263456669785648537565546D4F4A44616F344B73554453326E6B50"
)
AES_KEY_HEX = "526B327130707662557A5A644375736B"

RAW_MAGIC_HEX = "dec0adde2000"
RAW_MID_HEX = "cf0700"
LONG_RAW_SUFFIX5_HEX = "9d9ec1b102"
LONG_PREFIX8_HEX = "5a54eecde4d4ea61"
WRAP_XOR_KEY_ASCII = "M70gN2gdHXA34uIc"
WB_PERMUTE_INDEX = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)

SIGN64_PREFIX_HEX = "5a54eecde4d4ea61"
MW_HMAC_KEY_ASCII = "ndjrNsJq6F6Qk8uavcZT56G2RSsbbeTQX6ROeIdpXAUUm5Xh3BlJtIWZv2ibwyVD"
PRE_F1_CONST = 0x00025141
PRE_F6_CONST = 0x000D01
XOR_F1_F5 = 0x03545329
XOR_F2_F6 = 0x0003562A
XOR_F3 = 0x57253C2C
XOR_F4 = 0x072D1150
FINAL_KEY_XOR_CONST = 0x64
DEFAULT_KAW_BODY_TEXT = (
    "2|1774835779|MI 8 Lite|1717216100|10.93|36|0|0|0|116|6|1762647442|39|00000|00000|0000|0|0000000|00|0|17|17%|0|1736155659|0|9.6.7|ea6b06ac1997a8a3|0#1|000|a_60856344476e1ddd|114323877888"
)
SM_AES_KEY = b"ksfenxi_aes_key!"


class SignatureUtil:
    FANS_SALT = "772867c19925"

    @staticmethod
    def gen_signature(params, salt):
        if not params:
            return None

        sorted_keys = sorted(params.keys())
        sb = []

        for key in sorted_keys:
            if key in ["sig", "__NStokensig"]:
                continue

            value = params[key]
            try:
                value = urllib.parse.unquote(value)
            except Exception:
                pass

            sb.append(f"{key}={value}")

        uri_string = "".join(sb) + salt
        sign = hashlib.md5(uri_string.encode("utf-8")).hexdigest()
        return sign

    @staticmethod
    def get_map_from_str(str_):
        if not str_:
            return None

        params = {}
        arr = str_.split("&")
        for item in arr:
            parts = item.split("=", 1)
            if len(parts) == 2:
                params[parts[0]] = parts[1]
        return params

    @staticmethod
    def main(src_str, client_salt):
        params = SignatureUtil.get_map_from_str(src_str)
        signature = SignatureUtil.gen_signature(params, SignatureUtil.FANS_SALT)
        nstokensig = hashlib.sha256((signature + client_salt).encode("utf-8")).hexdigest()

        return {
            "nstokensig": nstokensig,
            "sig": signature,
        }


def _extract_mod_model_from_data(data_str: str) -> Optional[str]:
    """
    Extract model part from `mod` in data query string.
    Examples:
    - realme%28RMX5010%29 -> RMX5010
    - Xiaomi%28MI%208%20Lite%29 -> MI 8 Lite
    - Xiaomi(MI 8 Lite) -> MI 8 Lite
    """
    if not data_str:
        return None

    try:
        pairs = parse_qs(data_str, keep_blank_values=True)
        mod_val = (pairs.get("mod") or [None])[0]
    except Exception:
        mod_val = None

    if not mod_val:
        return None

    raw = unquote(str(mod_val)).strip()
    if not raw:
        return None

    # Prefer text inside (...) if present.
    left = raw.find("(")
    right = raw.rfind(")")
    if left >= 0 and right > left:
        inside = raw[left + 1 : right].strip()
        if inside:
            return inside

    # Fallback: support unresolved encoded style.
    if "%28" in raw:
        seg = raw.split("%28", 1)[1]
        seg = seg.split("%29", 1)[0].strip()
        if seg:
            return unquote(seg).strip()

    return None


def _extract_did_suffix_from_data(data_str: str) -> Optional[str]:
    if not data_str:
        return None

    try:
        pairs = parse_qs(data_str, keep_blank_values=True)
        did_val = (pairs.get("did") or [None])[0]
    except Exception:
        did_val = None

    if not did_val:
        return None

    raw = unquote(str(did_val)).strip()
    if not raw:
        return None

    upper = raw.upper()
    if upper.startswith("ANDROID_"):
        return raw[8:].strip() or None
    return raw


def _u32_to_le_hex(v: int) -> str:
    return (v & 0xFFFFFFFF).to_bytes(4, "little").hex()


def _u32_le(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def _be_hex_to_le_hex(hex8: str) -> str:
    return bytes.fromhex(hex8)[::-1].hex()


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return data[:-pad_len]


def _decrypt_sm_header(sm_value: str) -> str:
    token = (sm_value or "").strip()
    if not token:
        raise ValueError("empty SM payload")
    if ":" in token or ";" in token:
        raise ValueError("SM must be raw hex only")
    cipher_bytes = bytes.fromhex(token)
    if len(cipher_bytes) % 16 != 0:
        raise ValueError("invalid SM ciphertext length")
    plain_padded = AES.new(SM_AES_KEY, AES.MODE_ECB).decrypt(cipher_bytes)
    plain = _pkcs7_unpad(plain_padded)
    return plain.decode("utf-8")


def _to_bytes(data: Union[bytes, bytearray, Sequence[int]]) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return bytes(((int(v) % 256 + 256) % 256) for v in data)


def _tick_ascii9(tick: Optional[int] = None) -> bytes:
    v = int(tick if tick is not None else (time.monotonic() * 1000))
    return str(v % 1_000_000_000).rjust(9, "0").encode("ascii")


def _decode_b64(data_b64: str) -> bytes:
    try:
        return base64.b64decode(data_b64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid base64 data: {exc}") from exc


def _decode_tail_raw(sign64_hex: str) -> bytes:
    b = bytearray.fromhex(sign64_hex[16:])
    key = b[23]
    for i in range(23):
        b[i] ^= (key ^ i) & 0xFF
    return bytes(b)


def _append_mix_key(raw23: bytes, key_byte: Optional[int] = None) -> bytes:
    if len(raw23) != 23:
        raise ValueError("raw23 must be 23 bytes")
    if key_byte is None:
        raise ValueError("key_byte is required")
    key = int(key_byte)
    if key < 0 or key > 0xFF:
        raise ValueError("key_byte must be in [0, 255]")
    return raw23 + bytes([key])


def _obfuscate_tail24(raw24: bytes) -> bytes:
    if len(raw24) != 24:
        raise ValueError("raw24 must be 24 bytes")
    out = bytearray(raw24)
    key = out[23]
    for i in range(23):
        out[i] ^= (key ^ i) & 0xFF
    return bytes(out)


def _get_env_int(name: str, default: Optional[int] = None) -> Optional[int]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value, 0)


def _seed_state_from_seed_sign(seed_sign: str) -> Optional[Dict[str, object]]:
    seed = (seed_sign or "").strip().lower()
    if len(seed) != 64:
        return None
    if not all(c in "0123456789abcdef" for c in seed):
        return None
    try:
        raw = _decode_tail_raw(seed)
        f2 = int.from_bytes(raw[4:8], "little")
        f3 = int.from_bytes(raw[8:12], "little")
        pre_f2 = (f2 ^ XOR_F2_F6) & 0xFFFFFFFF
        pre_f3 = (f3 ^ XOR_F3) & 0xFFFFFFFF
        return {
            "str2_hex": pre_f2.to_bytes(4, "little").hex(),
            "counter_next": (pre_f3 + 1) & 0xFFFFFFFF,
        }
    except Exception:
        return None


class Sig3Service:
    def __init__(self):
        self._lock = threading.Lock()
        self.hmac_key = bytes.fromhex(HMAC_KEY_HEX)
        self.aes_key = bytes.fromhex(AES_KEY_HEX)
        self.str2_hex = os.environ.get("SIG3_STR2") or os.urandom(4).hex()
        self.counter = int(os.environ.get("SIG3_COUNTER", "1")) & 0xFFFFFFFF
        self.str6_hex = os.environ.get("SIG3_STR6", "110d00").lower()

    @staticmethod
    def _xor_obfuscate(hex_string: str) -> str:
        last_two = hex_string[-2:]
        key = int("0xfffff9" + last_two, 16)
        data = bytearray.fromhex(hex_string)
        for i in range(0x17):
            data[i] ^= ((key ^ i) & 0xFF)
        return data.hex()

    @staticmethod
    def _checksum(hex_string: str) -> str:
        buf = bytes.fromhex(hex_string)
        w9 = sum(buf) & 0xFFFFFFFF
        if w9 > 0xFF:
            w9 = (-w9) & 0xFFFFFFFF
        shifted = (w9 << 24) & 0xFFFFFFF0
        result = 0x0D00 | shifted
        check = result.to_bytes(4, "little").hex()[-2:]
        return hex_string + check

    def _user_data_encrypt(self, data_hex: str) -> str:
        h = hmac.new(self.hmac_key, bytes.fromhex(data_hex), hashlib.sha256).hexdigest()
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        pad_len = 16 - (len(h) // 2) % 16
        padded = bytes.fromhex(h) + bytes([pad_len]) * pad_len
        aes_out = cipher.encrypt(padded).hex()
        crc32_hex = f"{zlib.crc32(bytes.fromhex(aes_out)) & 0xFFFFFFFF:08x}"
        return _be_hex_to_le_hex(crc32_hex)

    def make_sig3(self, data: str, timestamp: Optional[int] = None) -> Dict[str, object]:
        ts = int(timestamp if timestamp is not None else time.time())
        data_hex = data.encode("utf-8").hex()
        with self._lock:
            str2 = self.str2_hex
            str3 = _u32_to_le_hex(self.counter)
            self.counter = (self.counter + 1) & 0xFFFFFFFF

        raw = self._checksum(
            "41512700"
            + str2
            + str3
            + self._user_data_encrypt(data_hex)
            + _u32_to_le_hex(ts)
            + self.str6_hex
        )
        return {
            "sig3": self._xor_obfuscate(raw),
            "timestamp": ts,
            "str2": str2,
            "counter": int.from_bytes(bytes.fromhex(str3), "little"),
        }


class WhiteboxEncryptor:
    def __init__(self, round_table_path: Union[str, Path], final_table_path: Union[str, Path]):
        self.round_blob = Path(round_table_path).read_bytes()
        self.final_blob = Path(final_table_path).read_bytes()
        if len(self.round_blob) != 0x24000:
            raise ValueError(f"invalid wb round table size: {len(self.round_blob)} != 0x24000")
        if len(self.final_blob) < 0xA000:
            raise ValueError(f"invalid wb final table size: {len(self.final_blob)} < 0xA000")

    @staticmethod
    def _permute_24f48(state16: Union[bytes, bytearray]) -> bytearray:
        src = _to_bytes(state16)
        out = bytearray(16)
        for i, p in enumerate(WB_PERMUTE_INDEX):
            out[i] = src[p]
        return out

    def _round_mix_25240(self, state16: Union[bytes, bytearray], round_idx: int) -> bytearray:
        s = _to_bytes(state16)
        out = bytearray(16)
        base = int(round_idx) * 0x4000
        rb = self.round_blob
        for g in range(4):
            b0, b1, b2, b3 = s[4 * g : 4 * g + 4]
            t0 = int.from_bytes(rb[base + (4 * g + 0) * 0x400 + b0 * 4 : base + (4 * g + 0) * 0x400 + b0 * 4 + 4], "little")
            t1 = int.from_bytes(rb[base + (4 * g + 1) * 0x400 + b1 * 4 : base + (4 * g + 1) * 0x400 + b1 * 4 + 4], "little")
            t2 = int.from_bytes(rb[base + (4 * g + 2) * 0x400 + b2 * 4 : base + (4 * g + 2) * 0x400 + b2 * 4 + 4], "little")
            t3 = int.from_bytes(rb[base + (4 * g + 3) * 0x400 + b3 * 4 : base + (4 * g + 3) * 0x400 + b3 * 4 + 4], "little")
            w = (t0 ^ t1 ^ t2 ^ t3) & 0xFFFFFFFF
            out[4 * g + 0] = (w >> 24) & 0xFF
            out[4 * g + 1] = (w >> 16) & 0xFF
            out[4 * g + 2] = (w >> 8) & 0xFF
            out[4 * g + 3] = w & 0xFF
        return out

    def _final_sub_257a4(self, state16: Union[bytes, bytearray]) -> bytearray:
        s = _to_bytes(state16)
        fb = self.final_blob
        out = bytearray(16)
        for i, b in enumerate(s):
            out[i] = fb[0x9000 + i * 0x100 + b]
        return out

    def encrypt_u(self, data: Union[bytes, bytearray, Sequence[int]]) -> bytes:
        src = _to_bytes(data)
        padded = _pkcs7_pad(src, 16)
        out = bytearray()
        for off in range(0, len(padded), 16):
            s = bytearray(padded[off : off + 16])
            for r in range(9):
                s = self._permute_24f48(s)
                s = self._round_mix_25240(s, r)
            s = self._permute_24f48(s)
            s = self._final_sub_257a4(s)
            out.extend(s)
        return bytes(out)


class AtlasLongFrameService:
    def __init__(self, round_table_path: Path, final_table_path: Path):
        self.round_blob = round_table_path.read_bytes()
        self.final_blob = final_table_path.read_bytes()
        if len(self.round_blob) != 0x24000:
            raise ValueError(f"invalid wb round table size: {len(self.round_blob)}")
        if len(self.final_blob) < 0xA000:
            raise ValueError(f"invalid wb final table size: {len(self.final_blob)}")

    @staticmethod
    def _permute_24f48(state16: Union[bytes, bytearray]) -> bytearray:
        src = _to_bytes(state16)
        out = bytearray(16)
        for i, p in enumerate(WB_PERMUTE_INDEX):
            out[i] = src[p]
        return out

    def _round_mix_25240(self, state16: Union[bytes, bytearray], round_idx: int) -> bytearray:
        s = _to_bytes(state16)
        out = bytearray(16)
        base = int(round_idx) * 0x4000
        rb = self.round_blob
        for g in range(4):
            b0, b1, b2, b3 = s[4 * g : 4 * g + 4]
            t0 = int.from_bytes(rb[base + (4 * g + 0) * 0x400 + b0 * 4 : base + (4 * g + 0) * 0x400 + b0 * 4 + 4], "little")
            t1 = int.from_bytes(rb[base + (4 * g + 1) * 0x400 + b1 * 4 : base + (4 * g + 1) * 0x400 + b1 * 4 + 4], "little")
            t2 = int.from_bytes(rb[base + (4 * g + 2) * 0x400 + b2 * 4 : base + (4 * g + 2) * 0x400 + b2 * 4 + 4], "little")
            t3 = int.from_bytes(rb[base + (4 * g + 3) * 0x400 + b3 * 4 : base + (4 * g + 3) * 0x400 + b3 * 4 + 4], "little")
            w = (t0 ^ t1 ^ t2 ^ t3) & 0xFFFFFFFF
            out[4 * g + 0] = (w >> 24) & 0xFF
            out[4 * g + 1] = (w >> 16) & 0xFF
            out[4 * g + 2] = (w >> 8) & 0xFF
            out[4 * g + 3] = w & 0xFF
        return out

    def _final_sub_257a4(self, state16: Union[bytes, bytearray]) -> bytearray:
        s = _to_bytes(state16)
        fb = self.final_blob
        out = bytearray(16)
        for i, b in enumerate(s):
            out[i] = fb[0x9000 + i * 0x100 + b]
        return out

    def _encrypt_u(self, data: Union[bytes, bytearray, Sequence[int]]) -> bytes:
        src = _to_bytes(data)
        padded = _pkcs7_pad(src, 16)
        out = bytearray()
        for off in range(0, len(padded), 16):
            s = bytearray(padded[off : off + 16])
            for r in range(9):
                s = self._permute_24f48(s)
                s = self._round_mix_25240(s, r)
            s = self._permute_24f48(s)
            s = self._final_sub_257a4(s)
            out.extend(s)
        return bytes(out)

    def encrypt_long_frame(self, data: Union[str, bytes], tick: Optional[int] = None) -> Dict[str, str]:
        src = data.encode("utf-8") if isinstance(data, str) else data
        u = self._encrypt_u(src)
        tick_ascii9 = _tick_ascii9(tick)

        raw_prefix = (
            bytes.fromhex(RAW_MAGIC_HEX)
            + tick_ascii9
            + b"\x00"
            + bytes.fromhex(RAW_MID_HEX)
            + bytes.fromhex(LONG_RAW_SUFFIX5_HEX)
        )
        crc_u_le = (zlib.crc32(u) & 0xFFFFFFFF).to_bytes(4, "little")
        u_len_le = len(u).to_bytes(4, "little")
        raw64 = raw_prefix + crc_u_le + u_len_le + u

        wrap_key = WRAP_XOR_KEY_ASCII.encode("ascii")
        wrapped = bytes(raw64[i] ^ wrap_key[i % len(wrap_key)] for i in range(len(raw64)))
        out = bytes.fromhex(LONG_PREFIX8_HEX) + wrapped
        return {
            "longframe_b64": base64.b64encode(out).decode("ascii"),
            "tick_ascii9": tick_ascii9.decode("ascii"),
            "out_hex": out.hex(),
        }


class KwaiAtlasSign64:
    def __init__(
        self,
        round_table_path: Union[str, Path] = "wb_round_tables.bin",
        final_table_path: Union[str, Path] = "wb_final_tables.bin",
        str2_hex: Optional[str] = None,
        counter: int = 1,
        counter_step: int = 1,
        key_byte: Optional[int] = None,
    ):
        self.encryptor = WhiteboxEncryptor(round_table_path, final_table_path)
        self.mw_hmac_key = MW_HMAC_KEY_ASCII.encode("ascii")
        self.str2_hex = (str2_hex or os.urandom(4).hex()).lower()
        self.counter = counter & 0xFFFFFFFF
        self.counter_step = int(counter_step) & 0xFFFFFFFF
        if self.counter_step == 0:
            self.counter_step = 1
        if key_byte is not None and (int(key_byte) < 0 or int(key_byte) > 0xFF):
            raise ValueError("key_byte must be in [0, 255]")
        self.key_byte = None if key_byte is None else int(key_byte)
        self._lock = threading.Lock()

    def _next_fields(self, timestamp: Optional[int]) -> Dict[str, int]:
        with self._lock:
            f2 = int.from_bytes(bytes.fromhex(self.str2_hex), "little")
            f3 = self.counter
            self.counter = (self.counter + self.counter_step) & 0xFFFFFFFF
        f5 = int(timestamp if timestamp is not None else time.time()) & 0xFFFFFFFF
        return {"f2": f2, "f3": f3, "f5": f5}

    def _calc_pre_f4(self, x: str) -> int:
        mw_in32 = hmac.new(self.mw_hmac_key, x.encode("utf-8"), hashlib.sha256).digest()
        mw_out48 = self.encryptor.encrypt_u(mw_in32)
        return zlib.crc32(mw_out48) & 0xFFFFFFFF

    @staticmethod
    def _derive_final_key_byte(
        pre_f1: int,
        pre_f2: int,
        pre_f3: int,
        pre_f4: int,
        pre_f5: int,
        pre_f6: int,
    ) -> int:
        stage23 = (
            _u32_le(pre_f1)
            + _u32_le(pre_f2)
            + _u32_le(pre_f3)
            + _u32_le(pre_f4)
            + _u32_le(pre_f5)
            + int(pre_f6 & 0xFFFFFF).to_bytes(3, "little")
        )
        checksum = sum(stage23) & 0xFFFFFFFF
        if checksum > 0xFF:
            checksum = (-checksum) & 0xFFFFFFFF
        stage_key = checksum & 0xFF
        return stage_key ^ FINAL_KEY_XOR_CONST

    def sign64(self, x: str, timestamp: Optional[int] = None, key_byte: Optional[int] = None) -> str:
        f = self._next_fields(timestamp)
        pre_f4 = self._calc_pre_f4(x)

        pre_f1 = PRE_F1_CONST
        pre_f2 = f["f2"]
        pre_f3 = f["f3"]
        pre_f5 = f["f5"]
        pre_f6 = PRE_F6_CONST

        final_f1 = pre_f1 ^ XOR_F1_F5
        final_f2 = pre_f2 ^ XOR_F2_F6
        final_f3 = pre_f3 ^ XOR_F3
        final_f4 = pre_f4 ^ XOR_F4
        final_f5 = pre_f5 ^ XOR_F1_F5
        final_f6 = pre_f6 ^ XOR_F2_F6

        raw23 = (
            _u32_le(final_f1)
            + _u32_le(final_f2)
            + _u32_le(final_f3)
            + _u32_le(final_f4)
            + _u32_le(final_f5)
            + final_f6.to_bytes(3, "little")
        )
        default_key = self._derive_final_key_byte(pre_f1, pre_f2, pre_f3, pre_f4, pre_f5, pre_f6)
        key = default_key if self.key_byte is None else self.key_byte
        if key_byte is not None:
            key = key_byte
        raw24 = _append_mix_key(raw23, key_byte=key)
        tail48 = _obfuscate_tail24(raw24).hex()
        return SIGN64_PREFIX_HEX + tail48


def _load_kaw_template() -> KawTemplate:
    fields = DEFAULT_KAW_BODY_TEXT.split("|")
    return KawTemplate(
        magic_le=0x00003D2D,
        seq_le=1,
        fields=fields,
    )


class KawKasService:
    def __init__(self, template: KawTemplate, seq_start: Optional[int] = None, seq_step: int = 1):
        self._lock = threading.Lock()
        self._template = template
        self._seq = template.seq_le if seq_start is None else (int(seq_start) & 0xFFFFFFFF)
        self._seq_step = int(seq_step) & 0xFFFFFFFF
        if self._seq_step == 0:
            self._seq_step = 1

    def _next_seq(self) -> int:
        with self._lock:
            curr_seq = self._seq
            self._seq = (self._seq + self._seq_step) & 0xFFFFFFFF
            return curr_seq

    @staticmethod
    def _to_int(value: str, default: int = 0) -> int:
        try:
            return int(str(value).strip())
        except Exception:
            return default

    @staticmethod
    def _to_float(value: str) -> Optional[float]:
        try:
            return float(str(value).strip())
        except Exception:
            return None

    def _build_runtime_overrides(self, template: KawTemplate) -> Dict[int, str]:
        fields = list(template.fields)
        overrides: Dict[int, str] = {}

        # field[4]: random +-5 around original numeric value
        if len(fields) > 4:
            f4 = self._to_float(fields[4])
            if f4 is not None:
                delta = random.uniform(-5.0, 5.0)
                new_f4 = max(0.0, f4 + delta)
                decimals = 0
                if "." in fields[4]:
                    decimals = len(fields[4].split(".", 1)[1])
                if decimals > 0:
                    overrides[4] = f"{new_f4:.{decimals}f}"
                else:
                    overrides[4] = str(int(round(new_f4)))

        # field[5]: random 50-150
        if len(fields) > 5:
            overrides[5] = str(random.randint(50, 150))

        # field[10]: +1 based on template value
        if len(fields) > 10:
            overrides[10] = str(self._to_int(fields[10], 0) + 1)

        # field[12]: random 1-10
        if len(fields) > 12:
            overrides[12] = str(random.randint(1, 10))

        # field[21]: battery random minus 1-3
        if len(fields) > 21:
            raw_battery = fields[21].strip()
            has_percent = raw_battery.endswith("%")
            num_part = raw_battery[:-1] if has_percent else raw_battery
            battery_val = self._to_int(num_part, -1)
            if battery_val >= 0:
                battery_new = max(0, battery_val - random.randint(1, 3))
                overrides[21] = f"{battery_new}%" if has_percent else str(battery_new)

        return overrides

    def make_kaw(
        self,
        timestamp: Optional[int] = None,
        template: Optional[KawTemplate] = None,
        extra_overrides: Optional[Dict[int, str]] = None,
    ) -> str:
        now_sec = int(timestamp if timestamp is not None else time.time())
        tpl = template or self._template
        seq = self._next_seq()
        overrides = self._build_runtime_overrides(tpl)
        if extra_overrides:
            overrides.update(extra_overrides)
        return tpl.generate_kaw(seq_le=seq, now_ts=now_sec, field_overrides=overrides)

    def make_kas(self, path: str, sig3: str, kaw: str) -> str:
        d = f"{path}{sig3}{kaw}"
        return kas_from_d(d)


sig3_service = Sig3Service()
long_service = AtlasLongFrameService(
    round_table_path=_ROOT / "wb_round_tables.bin",
    final_table_path=_ROOT / "wb_final_tables.bin",
)
_seed_state = _seed_state_from_seed_sign(os.environ.get("ATLAS64_COUNTER_SEED_SIGN", ""))
sign64_service = KwaiAtlasSign64(
    round_table_path=_ROOT / "wb_round_tables.bin",
    final_table_path=_ROOT / "wb_final_tables.bin",
    str2_hex=os.environ.get(
        "ATLAS64_STR2",
        (_seed_state.get("str2_hex") if _seed_state is not None else None) or "0808462d",
    ),
    counter=_get_env_int(
        "ATLAS64_COUNTER",
        int(_seed_state.get("counter_next")) if _seed_state is not None else 1,
    ),
    counter_step=_get_env_int("ATLAS64_COUNTER_STEP", 1),
    key_byte=_get_env_int("ATLAS64_KEY_BYTE", None),
)
kaw_kas_service = KawKasService(
    template=_load_kaw_template(),
    seq_start=_get_env_int("KAW_SEQ_START", None),
    seq_step=_get_env_int("KAW_SEQ_STEP", 1) or 1,
)


@app.get("/sign")
def sign(
    request: Request,
    data: str = Query(..., min_length=1),
    path: str = Query(..., min_length=1),
    salt: str = Query(..., min_length=1),
):
    try:
        sm_header = request.headers.get("SM")

        sig_result = SignatureUtil.main(data, salt)
        sig_value = sig_result.get("sig")
        nstokensig_value = sig_result.get("nstokensig")
        if not sig_value or not nstokensig_value:
            raise HTTPException(status_code=400, detail="sign failed: invalid data/salt")

        sig3_obj = sig3_service.make_sig3(path + sig_value)
        sig3_value = str(sig3_obj["sig3"])

        if sm_header:
            template_kaw = _decrypt_sm_header(sm_header)
            sm_template = KawTemplate.from_kaw(template_kaw)
            kaw_value = kaw_kas_service.make_kaw(
                timestamp=int(time.time()),
                template=sm_template,
            )
        else:
            extra: Dict[int, str] = {}
            model_name = _extract_mod_model_from_data(data)
            if model_name:
                extra[2] = model_name
            did_suffix = _extract_did_suffix_from_data(data)
            if did_suffix:
                extra[26] = did_suffix
            kaw_value = kaw_kas_service.make_kaw(timestamp=int(time.time()), extra_overrides=extra)
        kas_value = kaw_kas_service.make_kas(path=path, sig3=sig3_value, kaw=kaw_value)

        return {
            "sig": sig_value,
            "nstokensig": nstokensig_value,
            "sig3": sig3_value,
            "kaw": kaw_value,
            "kas": kas_value,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"sign failed: {exc}") from exc


@app.get("/encrypt")
def encrypt(data: str = Query(..., min_length=1), tick: Optional[int] = None):
    try:
        plain_bytes = _decode_b64(data)
        plain_text = plain_bytes.decode("utf-8")
        out = long_service.encrypt_long_frame(plain_bytes, tick=tick)
        sign = sign64_service.sign64(plain_text)
        return {
            "encrypt": out["longframe_b64"],
            "sign": sign,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"encrypt failed: {exc}") from exc

@app.get ("/ping")
def status():
    return 'pong'
