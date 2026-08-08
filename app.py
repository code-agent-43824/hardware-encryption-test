import base64
import ctypes
import getpass
import platform
import secrets
import sys
import textwrap
import time
from pathlib import Path


APP_VERSION = "v2.9"
CK_RV = ctypes.c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_ULONG = ctypes.c_ulong
CK_SLOT_ID = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_OBJECT_HANDLE = CK_ULONG
CK_FLAGS = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_MECHANISM_TYPE = CK_ULONG
CK_BBOOL = ctypes.c_ubyte
CK_BYTE = ctypes.c_ubyte
CK_BYTE_PTR = ctypes.POINTER(CK_BYTE)
CK_ATTRIBUTE_TYPE = CK_ULONG
PACK = 1 if platform.system() == "Windows" else 0


CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1

CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKO_SECRET_KEY = 0x00000004
CKK_RSA = 0x00000000
CKK_GOSTR3410 = 0x00000030
CKK_GOST28147 = 0x00000032
CK_VENDOR_PKCS11_RU_TEAM_TC26 = 0xD4321000
CKK_GOSTR3410_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x003
CKK_KUZNECHIK = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x004
CKK_MAGMA = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x005

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200
CKM_GOSTR3410 = 0x00001201
CKM_GOST28147_KEY_GEN = 0x00001220
CKM_GOST28147 = 0x00001222
CKM_GOSTR3410_512_KEY_PAIR_GEN = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x005
CKM_GOSTR3410_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x006
CKM_GOSTR3410_WITH_GOSTR3411_12_256 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x008
CKM_GOSTR3410_WITH_GOSTR3411_12_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x009
CKM_GOSTR3411_12_256 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x012
CKM_GOSTR3411_12_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x013
CKM_KUZNECHIK_KEY_GEN = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x030
CKM_KUZNECHIK_CTR_ACPKM = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x032
CKM_MAGMA_KEY_GEN = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x034
CKM_MAGMA_CTR_ACPKM = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x036

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_LABEL = 0x00000003
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_DERIVE = 0x0000010C
CKA_KEY_TYPE = 0x00000100
CKA_ID = 0x00000102
CKA_MODULUS_BITS = 0x00000121
CKA_GOSTR3410_PARAMS = 0x00000250
CKA_GOSTR3411_PARAMS = 0x00000251
CKA_GOST28147_PARAMS = 0x00000252

CKR_OK = 0
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKR_PIN_INCORRECT = 0x000000A0
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_USER_NOT_LOGGED_IN = 0x00000101

DEFAULT_PIN = "12345678"
DEFAULT_WARMUP_COUNT = 3
MAX_WARMUP_COUNT = 1000
MACOS_DEFAULT_LIBRARY_PATH = Path("/usr/local/lib/librtpkcs11ecp.dylib")
TEMP_KEY_LABEL_PREFIX = "hardware-encryption-test-temp-v1-"
RSA_MODULUS_BITS = 2048
FIND_OBJECTS_LIMIT = 128
FIND_OBJECTS_BATCH = 16
ATTR_UNAVAILABLE = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1
SAMPLE_FILE_NAMES = ["lorem-500kb.txt", str(Path("testdata") / "lorem-500kb.txt")]
GOST28147_89_BLOCK_SIZE = 8
KUZNECHIK_BLOCK_SIZE = 16
GOST28147_IV_SIZE = GOST28147_89_BLOCK_SIZE
MAGMA_CTR_ACPKM_IV_SIZE = GOST28147_89_BLOCK_SIZE // 2
KUZNECHIK_CTR_ACPKM_IV_SIZE = KUZNECHIK_BLOCK_SIZE // 2
CTR_ACPKM_PERIOD_FIELD_SIZE = 4
CTR_ACPKM_PERIOD_BITS = 4096 * 8
GOST_2012_256_PARAMS = bytes([0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01])
GOST_2012_512_PARAMS = bytes([0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01])
GOST_3411_2012_256_PARAMS = bytes([0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02])
GOST_3411_2012_512_PARAMS = bytes([0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03])
GOST_28147_PARAMS = bytes([0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01])


class PKCS11Error(Exception):
    def __init__(self, message, rv=None):
        self.rv = rv
        if rv is None:
            super().__init__(message)
        else:
            super().__init__(f"{message}: 0x{rv:08X}")


class CK_VERSION(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("major", ctypes.c_ubyte),
        ("minor", ctypes.c_ubyte),
    ]


class CK_INFO(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", ctypes.c_char * 32),
        ("flags", CK_ULONG),
        ("libraryDescription", ctypes.c_char * 32),
        ("libraryVersion", CK_VERSION),
    ]


class CK_TOKEN_INFO(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("label", ctypes.c_char * 32),
        ("manufacturerID", ctypes.c_char * 32),
        ("model", ctypes.c_char * 16),
        ("serialNumber", ctypes.c_char * 16),
        ("flags", CK_ULONG),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", ctypes.c_char * 16),
    ]


class CK_ATTRIBUTE(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("type", CK_ATTRIBUTE_TYPE),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]


class CK_MECHANISM(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("mechanism", CK_MECHANISM_TYPE),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_MECHANISM_INFO(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("ulMinKeySize", CK_ULONG),
        ("ulMaxKeySize", CK_ULONG),
        ("flags", CK_FLAGS),
    ]


def clean_text(value):
    return value.decode("utf-8", errors="ignore").strip().rstrip("\x00")


def yes_no(value):
    return CK_BBOOL(1 if value else 0)


def native_int(value):
    return int(value.value) if hasattr(value, "value") else int(value)


def rv_ok(rv, action):
    if rv != CKR_OK:
        raise PKCS11Error(action, rv)


def load_library(path):
    if platform.system() == "Windows":
        return ctypes.WinDLL(path)
    return ctypes.CDLL(path)


def app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_library_name():
    system = platform.system()
    if system == "Windows":
        return "rtpkcs11ecp.dll"
    if system == "Darwin":
        return "librtpkcs11ecp.dylib"
    return "librtpkcs11ecp.so"


def default_library_path():
    if platform.system() == "Darwin":
        return MACOS_DEFAULT_LIBRARY_PATH
    return app_dir() / default_library_name()


def resolve_library_path(raw_path):
    if raw_path:
        return Path(raw_path).expanduser()
    return default_library_path()


def resolve_sample_file_path(raw_path):
    if raw_path:
        return Path(raw_path).expanduser()
    base = app_dir()
    for name in SAMPLE_FILE_NAMES:
        candidate = base / name
        if candidate.exists():
            return candidate
    return base / SAMPLE_FILE_NAMES[0]


def bind_function(library, name, argtypes, restype=CK_RV):
    func = getattr(library, name)
    func.argtypes = argtypes
    func.restype = restype
    return func


def make_string_buffer_bytes(text):
    data = text.encode("utf-8")
    if not data:
        return None, 0
    buf = ctypes.create_string_buffer(data)
    return buf, len(data)


def make_ulong(value):
    data = CK_ULONG(value)
    return data, ctypes.sizeof(data)


def make_bool(value):
    data = yes_no(value)
    return data, ctypes.sizeof(data)


def make_bytes(value):
    data = bytes(value)
    if not data:
        return None, 0
    buf = ctypes.create_string_buffer(data)
    return buf, len(data)


def attribute_pointer(obj):
    if obj is None:
        return None
    if isinstance(obj, ctypes.Array):
        return ctypes.cast(obj, CK_VOID_PTR)
    return ctypes.cast(ctypes.byref(obj), CK_VOID_PTR)


def build_attribute(attr_type, raw_value):
    if isinstance(raw_value, tuple):
        obj, size = raw_value
    elif isinstance(raw_value, str):
        obj, size = make_string_buffer_bytes(raw_value)
    elif isinstance(raw_value, bool):
        obj, size = make_bool(raw_value)
    elif isinstance(raw_value, int):
        obj, size = make_ulong(raw_value)
    elif isinstance(raw_value, (bytes, bytearray)):
        obj, size = make_bytes(raw_value)
    elif raw_value is None:
        obj, size = None, 0
    else:
        raise TypeError(f"Unsupported attribute value type: {type(raw_value)!r}")

    attr = CK_ATTRIBUTE()
    attr.type = CK_ATTRIBUTE_TYPE(attr_type)
    attr.ulValueLen = CK_ULONG(size)
    attr._holder = obj
    attr.pValue = attribute_pointer(obj)
    return attr


def attributes_array(items):
    attrs = [build_attribute(attr_type, value) for attr_type, value in items]
    if not attrs:
        return None, 0
    array = (CK_ATTRIBUTE * len(attrs))(*attrs)
    array._holders = [attr._holder for attr in attrs]
    return array, len(attrs)


def attr_bytes(session, funcs, obj_handle, attr_type):
    template = (CK_ATTRIBUTE * 1)(CK_ATTRIBUTE(type=CK_ATTRIBUTE_TYPE(attr_type), pValue=None, ulValueLen=CK_ULONG(0)))
    rv = funcs["C_GetAttributeValue"](session, obj_handle, template, CK_ULONG(1))
    if rv == CKR_ATTRIBUTE_TYPE_INVALID:
        return None
    rv_ok(rv, "C_GetAttributeValue(size)")
    size = int(template[0].ulValueLen)
    if size == ATTR_UNAVAILABLE:
        return None
    if size == 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    template[0].pValue = ctypes.cast(buffer, CK_VOID_PTR)
    template[0].ulValueLen = CK_ULONG(size)
    rv = funcs["C_GetAttributeValue"](session, obj_handle, template, CK_ULONG(1))
    rv_ok(rv, "C_GetAttributeValue(data)")
    return bytes(buffer.raw[:size])


def attr_text(session, funcs, obj_handle, attr_type):
    value = attr_bytes(session, funcs, obj_handle, attr_type)
    if value is None:
        return ""
    return value.decode("utf-8", errors="ignore").strip().rstrip("\x00")


def attr_ulong(session, funcs, obj_handle, attr_type):
    value = attr_bytes(session, funcs, obj_handle, attr_type)
    if value is None:
        return None
    if len(value) < ctypes.sizeof(CK_ULONG):
        return None
    return int(CK_ULONG.from_buffer_copy(value[: ctypes.sizeof(CK_ULONG)]).value)


def display_id(value):
    if value is None:
        return "недоступен"
    if not value:
        return ""
    try:
        text = value.decode("utf-8").strip().rstrip("\x00")
        if text and all(ch.isprintable() for ch in text):
            return text
    except UnicodeDecodeError:
        pass
    return value.hex().upper()


KEY_TYPES = {
    CKK_RSA: {
        "constant": "CKK_RSA",
        "name": "RSA-2048",
        "sign_mechanism": CKM_SHA256_RSA_PKCS,
        "hash_mode": "SHA-256",
        "verify_mechanism": CKM_SHA256_RSA_PKCS,
        "signature_size": RSA_MODULUS_BITS // 8,
    },
    CKK_GOSTR3410: {
        "constant": "CKK_GOSTR3410",
        "name": "ГОСТ Р 34.10-2012(256)",
        "sign_mechanism": CKM_GOSTR3410_WITH_GOSTR3411_12_256,
        "sign_params": GOST_3411_2012_256_PARAMS,
        "hash_mode": "ГОСТ Р 34.11-2012(256), совместный механизм хеширования и подписи",
        "verify_mechanism": CKM_GOSTR3410,
        "digest_mechanism": CKM_GOSTR3411_12_256,
        "digest_size": 32,
        "signature_size": 64,
    },
    CKK_GOSTR3410_512: {
        "constant": "CKK_GOSTR3410_512",
        "name": "ГОСТ Р 34.10-2012(512)",
        "sign_mechanism": CKM_GOSTR3410_WITH_GOSTR3411_12_512,
        "sign_params": GOST_3411_2012_512_PARAMS,
        "hash_mode": "ГОСТ Р 34.11-2012(512), совместный механизм хеширования и подписи",
        "verify_mechanism": CKM_GOSTR3410_512,
        "digest_mechanism": CKM_GOSTR3411_12_512,
        "digest_size": 64,
        "signature_size": 128,
    },
    CKK_GOST28147: {"constant": "CKK_GOST28147", "name": "ГОСТ 28147-89"},
    CKK_KUZNECHIK: {"constant": "CKK_KUZNECHIK", "name": "Кузнечик"},
    CKK_MAGMA: {"constant": "CKK_MAGMA", "name": "Магма"},
}


def key_type_constant_name(algorithm):
    if algorithm is None:
        return "CKK_UNKNOWN"
    info = KEY_TYPES.get(algorithm)
    return info["constant"] if info else f"CKK_UNKNOWN(0x{algorithm:08X})"


def pair_algorithm_name(algorithm):
    info = KEY_TYPES.get(algorithm)
    if info:
        return info["name"]
    return f"0x{algorithm:08X}" if algorithm is not None else "неизвестно"


def prompt_non_empty(label):
    while True:
        value = input(label).strip()
        if value:
            return value
        print("Значение не должно быть пустым")


def prompt_operation_count(action):
    while True:
        raw = input(f"Сколько раз {action}? [1-10000]: ").strip()
        try:
            count = int(raw)
        except ValueError:
            print("Введите целое число")
            continue
        if 1 <= count <= 10000:
            return count
        print("Допустим диапазон от 1 до 10000")


def prompt_warmup_count():
    while True:
        raw = input(f"Сколько операций прогрева? [по умолчанию {DEFAULT_WARMUP_COUNT}, 0-{MAX_WARMUP_COUNT}]: ").strip()
        if raw == "":
            return DEFAULT_WARMUP_COUNT
        try:
            count = int(raw)
        except ValueError:
            print("Введите целое число")
            continue
        if 0 <= count <= MAX_WARMUP_COUNT:
            return count
        print(f"Допустим диапазон от 0 до {MAX_WARMUP_COUNT}")


CRYPTO_MODES = (
    {
        "choice": "0",
        "menu_label": "программно, ключ в памяти библиотеки",
        "mode": "software",
        "name": "программное",
        "cka_token": False,
    },
    {
        "choice": "1",
        "menu_label": "аппаратно, ключ на токене",
        "mode": "hardware",
        "name": "аппаратное",
        "cka_token": True,
    },
)

ENCRYPTION_ALGORITHMS = (
    {
        "choice": "0",
        "menu_label": "Магма",
        "name": "Магма",
        "key_type": CKK_MAGMA,
        "key_gen_mechanism": CKM_MAGMA_KEY_GEN,
        "encrypt_mechanism": CKM_MAGMA_CTR_ACPKM,
        "ctr_acpkm_iv_size": MAGMA_CTR_ACPKM_IV_SIZE,
        "acpkm_period": CTR_ACPKM_PERIOD_BITS,
    },
    {
        "choice": "1",
        "menu_label": "Кузнечик",
        "name": "Кузнечик",
        "key_type": CKK_KUZNECHIK,
        "key_gen_mechanism": CKM_KUZNECHIK_KEY_GEN,
        "encrypt_mechanism": CKM_KUZNECHIK_CTR_ACPKM,
        "ctr_acpkm_iv_size": KUZNECHIK_CTR_ACPKM_IV_SIZE,
        "acpkm_period": CTR_ACPKM_PERIOD_BITS,
    },
    {
        "choice": "2",
        "menu_label": "ГОСТ 28147-89 (режим гаммирования)",
        "name": "ГОСТ 28147-89",
        "key_type": CKK_GOST28147,
        "key_gen_mechanism": CKM_GOST28147_KEY_GEN,
        "encrypt_mechanism": CKM_GOST28147,
        "iv_size": GOST28147_IV_SIZE,
        "gost28147_params": GOST_28147_PARAMS,
    },
)

KEY_PAIR_ALGORITHMS = (
    {
        "choice": "0",
        "menu_label": "ГОСТ Р 34.10-2012(256)",
        "name": "ГОСТ Р 34.10-2012(256)",
        "key_type": CKK_GOSTR3410,
        "mechanism": CKM_GOSTR3410_KEY_PAIR_GEN,
        "required_mechanisms": (CKM_GOSTR3410_KEY_PAIR_GEN, CKM_GOSTR3411_12_256),
        "public_attributes": (
            (CKA_GOSTR3410_PARAMS, GOST_2012_256_PARAMS),
            (CKA_GOSTR3411_PARAMS, GOST_3411_2012_256_PARAMS),
        ),
        "private_attributes": (
            (CKA_DERIVE, True),
            (CKA_GOSTR3410_PARAMS, GOST_2012_256_PARAMS),
            (CKA_GOSTR3411_PARAMS, GOST_3411_2012_256_PARAMS),
        ),
    },
    {
        "choice": "1",
        "menu_label": "ГОСТ Р 34.10-2012(512)",
        "name": "ГОСТ Р 34.10-2012(512)",
        "key_type": CKK_GOSTR3410_512,
        "mechanism": CKM_GOSTR3410_512_KEY_PAIR_GEN,
        "required_mechanisms": (CKM_GOSTR3410_512_KEY_PAIR_GEN, CKM_GOSTR3411_12_512),
        "public_attributes": (
            (CKA_GOSTR3410_PARAMS, GOST_2012_512_PARAMS),
            (CKA_GOSTR3411_PARAMS, GOST_3411_2012_512_PARAMS),
        ),
        "private_attributes": (
            (CKA_DERIVE, True),
            (CKA_GOSTR3410_PARAMS, GOST_2012_512_PARAMS),
            (CKA_GOSTR3411_PARAMS, GOST_3411_2012_512_PARAMS),
        ),
    },
    {
        "choice": "2",
        "menu_label": "RSA-2048",
        "name": "RSA-2048",
        "key_type": CKK_RSA,
        "mechanism": CKM_RSA_PKCS_KEY_PAIR_GEN,
        "required_mechanisms": (CKM_RSA_PKCS_KEY_PAIR_GEN,),
        "modulus_bits": RSA_MODULUS_BITS,
        "public_attributes": ((CKA_ENCRYPT, True), (CKA_MODULUS_BITS, RSA_MODULUS_BITS)),
        "private_attributes": ((CKA_DECRYPT, True),),
    },
)


def choose_menu_option(title, options, prompt, invalid_message):
    print(title)
    for option in options:
        print(f"{option['choice']}) {option['menu_label']}")
    by_choice = {option["choice"]: option for option in options}
    while True:
        raw = input(prompt).strip() or "0"
        if raw in by_choice:
            return by_choice[raw]
        print(invalid_message)


def choose_crypto_mode():
    return choose_menu_option("Как шифровать?", CRYPTO_MODES, "Выберите режим [0]: ", "Введите 0 или 1")


def choose_encryption_algorithm():
    return choose_menu_option(
        "Какой алгоритм шифрования использовать?",
        ENCRYPTION_ALGORITHMS,
        "Выберите алгоритм [0]: ",
        "Введите 0, 1 или 2",
    )


def random_bytes(session, funcs, size):
    buffer = (CK_BYTE * size)()
    rv = funcs["C_GenerateRandom"](session, ctypes.cast(buffer, CK_BYTE_PTR), CK_ULONG(size))
    rv_ok(rv, "C_GenerateRandom")
    return bytes(buffer)


def mechanism_with_optional_param(mechanism_type, param_bytes=None):
    if param_bytes:
        param_buffer = ctypes.create_string_buffer(param_bytes)
        mechanism = CK_MECHANISM(mechanism_type, ctypes.cast(param_buffer, CK_VOID_PTR), CK_ULONG(len(param_bytes)))
        return mechanism, param_buffer
    return CK_MECHANISM(mechanism_type, None, CK_ULONG(0)), None


def build_ctr_acpkm_params(iv_size, period=0, iv=None):
    if iv is None:
        iv = secrets.token_bytes(iv_size)
    if len(iv) != iv_size:
        raise PKCS11Error(f"Неверная длина синхропосылки CTR-ACPKM: ожидалось {iv_size}, получено {len(iv)}")
    if period < 0 or period >= 1 << (CTR_ACPKM_PERIOD_FIELD_SIZE * 8):
        raise PKCS11Error(f"Недопустимый период смены ключа CTR-ACPKM: {period}")
    return int(period).to_bytes(CTR_ACPKM_PERIOD_FIELD_SIZE, "big") + iv


def print_pair(prefix, pair):
    algorithm = pair.get("algorithm")
    duplicate = ""
    if pair.get("duplicate_count", 1) > 1:
        duplicate = f" | duplicate={pair['duplicate_index']}/{pair['duplicate_count']}"
    print(
        f"{prefix}: cka_id={pair['id']} | cka_label={pair['label']} | "
        f"algorithm={key_type_constant_name(algorithm)} ({pair_algorithm_name(algorithm)}){duplicate}"
    )


def find_objects(session, funcs, template_items, limit=32):
    template, template_len = attributes_array(template_items)
    rv = funcs["C_FindObjectsInit"](session, template, CK_ULONG(template_len))
    rv_ok(rv, "C_FindObjectsInit")
    try:
        objects = []
        while len(objects) < limit:
            batch_size = min(FIND_OBJECTS_BATCH, limit - len(objects))
            batch = (CK_OBJECT_HANDLE * batch_size)()
            found = CK_ULONG(0)
            rv = funcs["C_FindObjects"](session, batch, CK_ULONG(len(batch)), ctypes.byref(found))
            rv_ok(rv, "C_FindObjects")
            count = int(found.value)
            if count == 0:
                break
            objects.extend(batch[:count])
        return objects
    finally:
        operation_failed = sys.exc_info()[0] is not None
        rv = funcs["C_FindObjectsFinal"](session)
        if rv != CKR_OK:
            cleanup_error = PKCS11Error("C_FindObjectsFinal", rv)
            if operation_failed:
                print(f"Предупреждение при очистке после исходной ошибки: {cleanup_error}", file=sys.stderr)
            else:
                raise cleanup_error


def pair_key_records(records):
    """Pair key objects by the original CKA_ID bytes and CKA_KEY_TYPE.

    Duplicate IDs are retained as separate selectable rows instead of silently
    overwriting an earlier object handle.
    """
    groups = {}
    for record in records:
        group_key = (record["id_raw"], record["algorithm"])
        groups.setdefault(group_key, {"public": [], "private": []})[record["kind"]].append(record)

    result = []
    sorted_groups = sorted(
        groups.items(),
        key=lambda item: (
            b"" if item[0][0] is None else item[0][0],
            -1 if item[0][1] is None else item[0][1],
            item[0][0] is None,
        ),
    )
    for (raw_id, algorithm), sides in sorted_groups:
        public = sorted(sides["public"], key=lambda item: (item["label"], native_int(item["handle"])))
        private = sorted(sides["private"], key=lambda item: (item["label"], native_int(item["handle"])))
        paired = []

        # Labels are only a tie-breaker inside an already matched raw CKA_ID.
        # This keeps similarly named duplicates together without ever using the
        # display string as key identity.
        remaining_private = list(private)
        remaining_public = []
        for public_record in public:
            match_index = next(
                (
                    index
                    for index, private_record in enumerate(remaining_private)
                    if public_record["label"] and public_record["label"] == private_record["label"]
                ),
                None,
            )
            if match_index is None:
                remaining_public.append(public_record)
            else:
                paired.append((public_record, remaining_private.pop(match_index)))

        while remaining_public or remaining_private:
            paired.append(
                (
                    remaining_public.pop(0) if remaining_public else None,
                    remaining_private.pop(0) if remaining_private else None,
                )
            )

        duplicate_count = len(paired)
        for duplicate_index, (public_record, private_record) in enumerate(paired, start=1):
            labels = [record["label"] for record in (public_record, private_record) if record and record["label"]]
            label = "" if not labels else labels[0] if len(set(labels)) == 1 else " / ".join(labels)
            result.append(
                {
                    "id_raw": raw_id,
                    "id": display_id(raw_id),
                    "label": label,
                    "algorithm": algorithm,
                    "public": public_record["handle"] if public_record else None,
                    "private": private_record["handle"] if private_record else None,
                    "duplicate_index": duplicate_index,
                    "duplicate_count": duplicate_count,
                }
            )
    return result


def find_pairs(session, funcs, cka_id=None, cka_label=None):
    common = []
    if cka_id:
        common.append((CKA_ID, bytes.fromhex(cka_id) if is_hex(cka_id) else cka_id.encode("utf-8")))
    if cka_label:
        common.append((CKA_LABEL, cka_label))

    public_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PUBLIC_KEY), *common], limit=FIND_OBJECTS_LIMIT)
    private_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PRIVATE_KEY), *common], limit=FIND_OBJECTS_LIMIT)

    records = []
    for key_name, handles in (("public", public_objects), ("private", private_objects)):
        for handle in handles:
            records.append(
                {
                    "kind": key_name,
                    "handle": handle,
                    "id_raw": attr_bytes(session, funcs, handle, CKA_ID),
                    "label": attr_text(session, funcs, handle, CKA_LABEL),
                    "algorithm": attr_ulong(session, funcs, handle, CKA_KEY_TYPE),
                }
            )
    return pair_key_records(records)


def is_hex(value):
    if len(value) % 2 != 0 or not value:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def open_session(funcs, slot_id, rw=False):
    session = CK_SESSION_HANDLE()
    flags = CK_FLAGS(CKF_SERIAL_SESSION | (CKF_RW_SESSION if rw else 0))
    rv = funcs["C_OpenSession"](slot_id, flags, None, None, ctypes.byref(session))
    rv_ok(rv, "C_OpenSession")
    return session


def close_session(funcs, session):
    rv = funcs["C_CloseSession"](session)
    if rv not in (CKR_OK, CKR_SESSION_HANDLE_INVALID):
        raise PKCS11Error("C_CloseSession", rv)


def login(funcs, session):
    pin = getpass.getpass(f"PIN токена [Enter: {DEFAULT_PIN}]: ")
    used_default_pin = False
    if pin == "":
        pin = DEFAULT_PIN
        used_default_pin = True
    pin_bytes = pin.encode("utf-8")
    rv = funcs["C_Login"](session, CK_USER_TYPE(CKU_USER), pin_bytes, CK_ULONG(len(pin_bytes)))
    if rv == CKR_OK:
        return True
    if rv == CKR_USER_ALREADY_LOGGED_IN:
        return False
    if rv == CKR_PIN_INCORRECT:
        if used_default_pin:
            raise PKCS11Error(
                f"PIN не введён, PIN по умолчанию {DEFAULT_PIN} не подошёл. Введите правильный PIN",
                rv,
            )
        raise PKCS11Error("Неверный PIN", rv)
    raise PKCS11Error("C_Login", rv)


def logout(funcs, session):
    rv = funcs["C_Logout"](session)
    if rv not in (CKR_OK, CKR_USER_NOT_LOGGED_IN):
        raise PKCS11Error("C_Logout", rv)


def choose_pair(pairs, prompt="Выберите номер пары [0]: ", default_index=0):
    if not pairs:
        print("Пары не найдены")
        return None
    for index, pair in enumerate(pairs):
        print_pair(str(index), pair)
    while True:
        raw = input(prompt).strip()
        if not raw:
            return pairs[default_index]
        try:
            index = int(raw)
        except ValueError:
            print("Введите номер")
            continue
        if 0 <= index < len(pairs):
            return pairs[index]
        print("Нет такого номера")


def choose_generation_type():
    return choose_menu_option(
        "Какой тип ключевой пары создать?",
        KEY_PAIR_ALGORITHMS,
        "Выберите тип [0]: ",
        "Введите 0, 1 или 2",
    )


def build_key_pair_templates(algorithm, cka_label, pair_id_value):
    public_items = [
        (CKA_CLASS, CKO_PUBLIC_KEY),
        (CKA_LABEL, cka_label),
        (CKA_ID, pair_id_value),
        (CKA_KEY_TYPE, algorithm["key_type"]),
        (CKA_TOKEN, True),
        (CKA_PRIVATE, False),
        *algorithm["public_attributes"],
    ]
    private_items = [
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_LABEL, cka_label),
        (CKA_ID, pair_id_value),
        (CKA_KEY_TYPE, algorithm["key_type"]),
        (CKA_TOKEN, True),
        (CKA_PRIVATE, True),
        *algorithm["private_attributes"],
    ]
    public_template, public_len = attributes_array(public_items)
    private_template, private_len = attributes_array(private_items)
    return public_template, public_len, private_template, private_len


def generate_pair(session, funcs, slot_id):
    algorithm = choose_generation_type()
    cka_id = prompt_non_empty("Введите cka_id: ")
    cka_label = prompt_non_empty("Введите cka_label: ")
    pair_id_value = bytes.fromhex(cka_id) if is_hex(cka_id) else cka_id.encode("utf-8")

    mechanisms = get_mechanism_list(funcs, slot_id)
    for mechanism_type in algorithm["required_mechanisms"]:
        if mechanism_type not in mechanisms:
            raise PKCS11Error(f"Токен не поддерживает механизм 0x{mechanism_type:08X} для {algorithm['name']}")

    modulus_bits = algorithm.get("modulus_bits")
    if modulus_bits:
        mechanism_info = get_mechanism_info(funcs, slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        if not (int(mechanism_info.ulMinKeySize) <= modulus_bits <= int(mechanism_info.ulMaxKeySize)):
            raise PKCS11Error(
                f"Токен не поддерживает RSA-{modulus_bits} (доступно {int(mechanism_info.ulMinKeySize)}..{int(mechanism_info.ulMaxKeySize)})"
            )

    public_template, public_len, private_template, private_len = build_key_pair_templates(
        algorithm,
        cka_label,
        pair_id_value,
    )

    mechanism = CK_MECHANISM(algorithm["mechanism"], None, CK_ULONG(0))
    public_key = CK_OBJECT_HANDLE()
    private_key = CK_OBJECT_HANDLE()
    rv = funcs["C_GenerateKeyPair"](
        session,
        ctypes.byref(mechanism),
        public_template,
        CK_ULONG(public_len),
        private_template,
        CK_ULONG(private_len),
        ctypes.byref(public_key),
        ctypes.byref(private_key),
    )
    rv_ok(rv, "C_GenerateKeyPair")
    print(f"Пара создана: cka_id={cka_id} | cka_label={cka_label} | type={algorithm['name']}")


def signing_mechanism_for_pair(pair):
    algorithm = pair.get("algorithm")
    info = KEY_TYPES.get(algorithm)
    if not info or "sign_mechanism" not in info:
        raise PKCS11Error(f"Неподдерживаемый тип ключа для подписи: {pair_algorithm_name(algorithm)}")
    mechanism, keepalive = mechanism_with_optional_param(info["sign_mechanism"], info.get("sign_params"))
    return mechanism, keepalive, info["hash_mode"]


def generate_secret_key(session, funcs, algorithm, mode_info):
    template_items = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_LABEL, f"{TEMP_KEY_LABEL_PREFIX}{secrets.token_hex(8)}"),
        (CKA_ID, random_bytes(session, funcs, 16)),
        (CKA_KEY_TYPE, algorithm["key_type"]),
        (CKA_TOKEN, mode_info["cka_token"]),
        (CKA_PRIVATE, True),
        (CKA_ENCRYPT, True),
        (CKA_DECRYPT, True),
    ]
    if algorithm.get("gost28147_params"):
        template_items.append((CKA_GOST28147_PARAMS, algorithm["gost28147_params"]))

    template, template_len = attributes_array(template_items)
    mechanism = CK_MECHANISM(algorithm["key_gen_mechanism"], None, CK_ULONG(0))
    key_handle = CK_OBJECT_HANDLE()
    rv = funcs["C_GenerateKey"](session, ctypes.byref(mechanism), template, CK_ULONG(template_len), ctypes.byref(key_handle))
    rv_ok(rv, f"C_GenerateKey({algorithm['name']})")
    return key_handle


def cleanup_stale_temp_keys(session, funcs):
    handles = find_objects(
        session,
        funcs,
        [(CKA_CLASS, CKO_SECRET_KEY), (CKA_TOKEN, True)],
        limit=FIND_OBJECTS_LIMIT,
    )
    stale = [
        handle
        for handle in handles
        if attr_text(session, funcs, handle, CKA_LABEL).startswith(TEMP_KEY_LABEL_PREFIX)
    ]
    for handle in stale:
        rv = funcs["C_DestroyObject"](session, handle)
        rv_ok(rv, "C_DestroyObject(stale temporary encryption key)")
    if stale:
        print(f"Удалены временные ключи после предыдущего аварийного запуска: {len(stale)}")
    return len(stale)


def build_encryption_params(algorithm):
    mechanism_type = algorithm["encrypt_mechanism"]
    if mechanism_type in {CKM_KUZNECHIK_CTR_ACPKM, CKM_MAGMA_CTR_ACPKM}:
        return build_ctr_acpkm_params(
            algorithm["ctr_acpkm_iv_size"],
            algorithm.get("acpkm_period", 0),
        )
    iv_size = algorithm.get("iv_size", 0)
    return secrets.token_bytes(iv_size) if iv_size else b""


def prepare_encryption_operation(algorithm, params, output_capacity):
    mechanism, mechanism_keepalive = mechanism_with_optional_param(algorithm["encrypt_mechanism"], params)
    return {
        "params": params,
        "mechanism": mechanism,
        "mechanism_keepalive": mechanism_keepalive,
        "output_length": CK_ULONG(output_capacity),
    }


def encrypt_with_generated_key(
    session,
    funcs,
    key_handle,
    algorithm,
    data_pointer,
    data_size,
    encrypted_pointer,
    prepared_operation,
):
    started = time.perf_counter()
    rv = funcs["C_EncryptInit"](session, ctypes.byref(prepared_operation["mechanism"]), key_handle)
    rv_ok(rv, f"C_EncryptInit({algorithm['name']})")

    rv = funcs["C_Encrypt"](
        session,
        data_pointer,
        data_size,
        encrypted_pointer,
        ctypes.byref(prepared_operation["output_length"]),
    )
    rv_ok(rv, f"C_Encrypt(data, {algorithm['name']})")
    elapsed = time.perf_counter() - started
    return int(prepared_operation["output_length"].value), elapsed


def sign_once(session, funcs, private_key, mechanism, data_pointer, data_size, signature_pointer, output_length):
    started = time.perf_counter()
    rv = funcs["C_SignInit"](session, ctypes.byref(mechanism), private_key)
    rv_ok(rv, "C_SignInit")

    rv = funcs["C_Sign"](
        session,
        data_pointer,
        data_size,
        signature_pointer,
        ctypes.byref(output_length),
    )
    rv_ok(rv, "C_Sign(data)")
    return time.perf_counter() - started


def calculate_benchmark_metrics(data_size, count, operation_times, total_elapsed):
    operation_elapsed = sum(operation_times)
    processed_mib = (data_size * count) / (1024 * 1024)
    return {
        "operation_elapsed": operation_elapsed,
        "total_elapsed": total_elapsed,
        "average_operation": operation_elapsed / count,
        "minimum_operation": min(operation_times),
        "maximum_operation": max(operation_times),
        "operation_throughput_mib_s": processed_mib / operation_elapsed if operation_elapsed else 0.0,
        "total_throughput_mib_s": processed_mib / total_elapsed if total_elapsed else 0.0,
    }


def print_benchmark_metrics(metrics, warmup_count, warmup_elapsed, setup_elapsed, setup_description):
    print(f"Прогрев: {warmup_count} операций за {warmup_elapsed:.6f} сек (не входит в измерение)")
    print(f"Setup: {setup_elapsed:.6f} сек ({setup_description}; не входит в измерение)")
    print(f"PKCS#11 operation: {metrics['operation_elapsed']:.6f} сек")
    print(f"Total измеряемого цикла: {metrics['total_elapsed']:.6f} сек")
    print(f"Среднее время PKCS#11 operation: {metrics['average_operation']:.6f} сек")
    print(
        f"Минимум: {metrics['minimum_operation']:.6f} сек | "
        f"Максимум: {metrics['maximum_operation']:.6f} сек"
    )
    print(f"Throughput PKCS#11 operation: {metrics['operation_throughput_mib_s']:.2f} MiB/s")
    print(f"Throughput total: {metrics['total_throughput_mib_s']:.2f} MiB/s")


def decrypt_and_check(session, funcs, key_handle, algorithm, ciphertext, params, expected_plaintext):
    mechanism, mechanism_keepalive = mechanism_with_optional_param(algorithm["encrypt_mechanism"], params)
    rv = funcs["C_DecryptInit"](session, ctypes.byref(mechanism), key_handle)
    rv_ok(rv, f"C_DecryptInit({algorithm['name']})")

    ciphertext_buffer = (CK_BYTE * len(ciphertext)).from_buffer_copy(ciphertext)
    plaintext = (CK_BYTE * len(ciphertext))()
    plaintext_len = CK_ULONG(len(plaintext))
    rv = funcs["C_Decrypt"](
        session,
        ciphertext_buffer,
        CK_ULONG(len(ciphertext)),
        ctypes.cast(plaintext, CK_BYTE_PTR),
        ctypes.byref(plaintext_len),
    )
    rv_ok(rv, f"C_Decrypt(data, {algorithm['name']})")
    decrypted = bytes(plaintext[: int(plaintext_len.value)])
    if decrypted != expected_plaintext:
        raise PKCS11Error(f"Самопроверка расшифрования {algorithm['name']} не пройдена")
    return mechanism_keepalive


def signature_buffer_length(session, funcs, pair):
    algorithm = pair.get("algorithm")
    info = KEY_TYPES.get(algorithm)
    if not info or "signature_size" not in info:
        raise PKCS11Error(f"Неподдерживаемый тип ключа для подписи: {pair_algorithm_name(algorithm)}")
    if algorithm == CKK_RSA:
        for handle in (pair.get("public"), pair.get("private")):
            if not handle:
                continue
            modulus_bits = attr_ulong(session, funcs, handle, CKA_MODULUS_BITS)
            if modulus_bits:
                return int(modulus_bits) // 8
    return info["signature_size"]


def verify_signature(session, funcs, pair, data_buffer, data_size, signature_bytes):
    public_key = pair.get("public")
    if not public_key:
        raise PKCS11Error("Самопроверка подписи невозможна: у пары нет открытого ключа")

    algorithm = pair.get("algorithm")
    info = KEY_TYPES.get(algorithm)
    if not info or "verify_mechanism" not in info:
        raise PKCS11Error(f"Неподдерживаемый тип ключа для проверки подписи: {pair_algorithm_name(algorithm)}")
    verify_data = data_buffer
    verify_data_size = data_size
    digest_mechanism_type = info.get("digest_mechanism")
    if digest_mechanism_type is not None:
        digest_mechanism = CK_MECHANISM(digest_mechanism_type, None, CK_ULONG(0))
        rv = funcs["C_DigestInit"](session, ctypes.byref(digest_mechanism))
        rv_ok(rv, "C_DigestInit(self-check)")
        digest = (CK_BYTE * info["digest_size"])()
        digest_len = CK_ULONG(info["digest_size"])
        rv = funcs["C_Digest"](
            session,
            data_buffer,
            CK_ULONG(data_size),
            ctypes.cast(digest, CK_BYTE_PTR),
            ctypes.byref(digest_len),
        )
        rv_ok(rv, "C_Digest(self-check)")
        verify_data = digest
        verify_data_size = int(digest_len.value)
    verify_mechanism = CK_MECHANISM(info["verify_mechanism"], None, CK_ULONG(0))

    signature = (CK_BYTE * len(signature_bytes)).from_buffer_copy(signature_bytes)
    rv = funcs["C_VerifyInit"](session, ctypes.byref(verify_mechanism), public_key)
    rv_ok(rv, "C_VerifyInit(self-check)")
    rv = funcs["C_Verify"](
        session,
        verify_data,
        CK_ULONG(verify_data_size),
        signature,
        CK_ULONG(len(signature_bytes)),
    )
    rv_ok(rv, "C_Verify(self-check)")


def encrypt_file(session, funcs, slot_id):
    raw_path = input("Что зашифровать? ").strip().strip('"')
    file_path = resolve_sample_file_path(raw_path)
    if not file_path.exists():
        print(f"Файл не найден: {file_path}")
        return

    count = prompt_operation_count("зашифровать")
    warmup_count = prompt_warmup_count()
    mode_info = choose_crypto_mode()
    algorithm = choose_encryption_algorithm()

    if mode_info["cka_token"]:
        cleanup_stale_temp_keys(session, funcs)

    mechanisms = get_mechanism_list(funcs, slot_id)
    required = [algorithm["key_gen_mechanism"], algorithm["encrypt_mechanism"]]
    for mechanism_type in required:
        if mechanism_type not in mechanisms:
            raise PKCS11Error(f"Токен не поддерживает механизм 0x{mechanism_type:08X} для {algorithm['name']}")

    plaintext = file_path.read_bytes()
    key_handle = None
    last_params = b""
    last_ciphertext = b""
    self_check_passed = False

    try:
        setup_started = time.perf_counter()
        data_buffer = (CK_BYTE * len(plaintext)).from_buffer_copy(plaintext)
        data_pointer = ctypes.cast(data_buffer, CK_BYTE_PTR)
        data_size = CK_ULONG(len(plaintext))
        encrypted_buffer = (CK_BYTE * len(plaintext))()
        encrypted_pointer = ctypes.cast(encrypted_buffer, CK_BYTE_PTR)
        key_handle = generate_secret_key(session, funcs, algorithm, mode_info)
        encryption_operations = [
            prepare_encryption_operation(algorithm, build_encryption_params(algorithm), len(plaintext))
            for _ in range(warmup_count + count)
        ]
        setup_elapsed = time.perf_counter() - setup_started

        warmup_started = time.perf_counter()
        for operation in encryption_operations[:warmup_count]:
            encrypt_with_generated_key(
                session,
                funcs,
                key_handle,
                algorithm,
                data_pointer,
                data_size,
                encrypted_pointer,
                operation,
            )
        warmup_elapsed = time.perf_counter() - warmup_started

        operation_times = []
        total_started = time.perf_counter()
        measured_operations = encryption_operations[warmup_count:]
        for operation in measured_operations:
            encrypted_len, operation_elapsed = encrypt_with_generated_key(
                session,
                funcs,
                key_handle,
                algorithm,
                data_pointer,
                data_size,
                encrypted_pointer,
                operation,
            )
            operation_times.append(operation_elapsed)
        total_elapsed = time.perf_counter() - total_started
        last_params = measured_operations[-1]["params"]
        last_ciphertext = bytes(encrypted_buffer[:encrypted_len])
        decrypt_and_check(session, funcs, key_handle, algorithm, last_ciphertext, last_params, plaintext)
        self_check_passed = True
    finally:
        if key_handle:
            rv = funcs["C_DestroyObject"](session, key_handle)
            if rv != CKR_OK:
                cleanup_error = PKCS11Error("C_DestroyObject(secret encryption key)", rv)
                if sys.exc_info()[0] is not None:
                    print(f"Предупреждение при очистке после исходной ошибки: {cleanup_error}", file=sys.stderr)
                else:
                    raise cleanup_error

    metrics = calculate_benchmark_metrics(len(plaintext), count, operation_times, total_elapsed)
    print(f"Режим шифрования: {mode_info['name']}")
    print(f"Алгоритм шифрования: {algorithm['name']}")
    print(f"Секретный ключ создан через C_GenerateKey: CKA_TOKEN={'TRUE' if mode_info['cka_token'] else 'FALSE'}")
    print(f"Механизм генерации ключа: 0x{algorithm['key_gen_mechanism']:08X}")
    print(f"Механизм шифрования: 0x{algorithm['encrypt_mechanism']:08X}")
    print(f"Самопроверка расшифрованием: {'успешно' if self_check_passed else 'не пройдена'}")
    if last_params:
        print(f"Параметры последнего шифрования: {last_params.hex().upper()}")
    else:
        print("Параметры последнего шифрования: не используются")
    print(f"Файл: {file_path}")
    print(f"Размер исходных данных: {file_path.stat().st_size} байт")
    print(f"Количество шифрований: {count}")
    print_benchmark_metrics(
        metrics,
        warmup_count,
        warmup_elapsed,
        setup_elapsed,
        "ключ, параметры механизмов и буферы",
    )
    print(f"Размер последнего шифротекста: {len(last_ciphertext)} байт")
    print("Последний шифротекст (Base64, первые 256 символов):")
    print(base64.b64encode(last_ciphertext).decode("ascii")[:256])


def delete_pair(session, funcs):
    pairs = find_pairs(session, funcs)
    if not pairs:
        print("Пары не найдены")
        return
    pair = choose_pair(pairs, prompt="Какую пару удалить? [0]: ")
    if not pair:
        return
    print_pair("Удаляем пару", pair)
    confirm = input("Подтвердить удаление? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes", "д", "да"}:
        print("Удаление отменено")
        return
    for key in ("public", "private"):
        handle = pair.get(key)
        if handle:
            rv = funcs["C_DestroyObject"](session, handle)
            rv_ok(rv, "C_DestroyObject")
    print_pair("Пара удалена", pair)


def find_pair_menu(session, funcs):
    pairs = find_pairs(session, funcs)
    if not pairs:
        print("Пары не найдены")
        return
    for index, pair in enumerate(pairs):
        print_pair(str(index), pair)


def sign_file(session, funcs):
    raw_path = input("Что подписать? ").strip().strip('"')
    file_path = resolve_sample_file_path(raw_path)
    if not file_path.exists():
        print(f"Файл не найден: {file_path}")
        return
    count = prompt_operation_count("подписать")
    warmup_count = prompt_warmup_count()
    pairs = find_pairs(session, funcs)
    if not pairs:
        print("Пары не найдены")
        return
    pair = choose_pair(pairs, prompt="Какой парой подписать? [0]: ")
    if not pair:
        return
    private_key = pair.get("private")
    if not private_key:
        print("У найденной пары нет приватного ключа")
        return
    if not pair.get("public"):
        print("У найденной пары нет открытого ключа, обязательная самопроверка подписи невозможна")
        return

    data = file_path.read_bytes()
    setup_started = time.perf_counter()
    data_buffer = (CK_BYTE * len(data)).from_buffer_copy(data)
    data_pointer = ctypes.cast(data_buffer, CK_BYTE_PTR)
    data_size = CK_ULONG(len(data))
    mechanism, mechanism_keepalive, hash_mode_name = signing_mechanism_for_pair(pair)
    signature_capacity = signature_buffer_length(session, funcs, pair)
    signature = (CK_BYTE * signature_capacity)()
    signature_pointer = ctypes.cast(signature, CK_BYTE_PTR)
    output_lengths = [CK_ULONG(signature_capacity) for _ in range(warmup_count + count)]
    setup_elapsed = time.perf_counter() - setup_started

    warmup_started = time.perf_counter()
    for output_length in output_lengths[:warmup_count]:
        sign_once(
            session,
            funcs,
            private_key,
            mechanism,
            data_pointer,
            data_size,
            signature_pointer,
            output_length,
        )
    warmup_elapsed = time.perf_counter() - warmup_started

    operation_times = []
    measured_output_lengths = output_lengths[warmup_count:]
    total_started = time.perf_counter()
    for output_length in measured_output_lengths:
        operation_elapsed = sign_once(
            session,
            funcs,
            private_key,
            mechanism,
            data_pointer,
            data_size,
            signature_pointer,
            output_length,
        )
        operation_times.append(operation_elapsed)

    total_elapsed = time.perf_counter() - total_started
    last_signature_length = int(measured_output_lengths[-1].value)
    last_signature_bytes = bytes(signature[:last_signature_length])
    metrics = calculate_benchmark_metrics(len(data), count, operation_times, total_elapsed)
    signature_base64 = base64.b64encode(last_signature_bytes).decode("ascii") if last_signature_bytes else ""
    verify_signature(session, funcs, pair, data_buffer, len(data), last_signature_bytes)

    print_pair("Подпись выполнена ключом", pair)
    print(f"Алгоритм подписи: {pair_algorithm_name(pair.get('algorithm'))}")
    print(f"Режим хеширования: {hash_mode_name}")
    print(f"Файл: {file_path}")
    print(f"Размер данных: {len(data)} байт")
    print(f"Количество подписаний: {count}")
    print(f"Размер последней подписи: {last_signature_length} байт")
    print("Самопроверка подписи: успешно")
    print_benchmark_metrics(metrics, warmup_count, warmup_elapsed, setup_elapsed, "механизм и буферы")
    print("Подпись (Base64):")
    for line in textwrap.wrap(signature_base64, 64):
        print(line)


def show_menu():
    print()
    print("Выберите действие:")
    print("1) найти ключевую пару")
    print("2) сгенерировать ключевую пару")
    print("3) удалить ключевую пару")
    print("4) подписать 500 килобайт данных")
    print("5) шифровать 500 килобайт данных")
    print("0) выйти")
    return input("> ").strip()


def prepare_functions(library):
    signatures = {
        "C_Initialize": [CK_VOID_PTR],
        "C_Finalize": [CK_VOID_PTR],
        "C_GetInfo": [ctypes.POINTER(CK_INFO)],
        "C_GetSlotList": [CK_BBOOL, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG)],
        "C_GetTokenInfo": [CK_SLOT_ID, ctypes.POINTER(CK_TOKEN_INFO)],
        "C_GetMechanismList": [CK_SLOT_ID, ctypes.POINTER(CK_MECHANISM_TYPE), ctypes.POINTER(CK_ULONG)],
        "C_GetMechanismInfo": [CK_SLOT_ID, CK_MECHANISM_TYPE, ctypes.POINTER(CK_MECHANISM_INFO)],
        "C_OpenSession": [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, ctypes.POINTER(CK_SESSION_HANDLE)],
        "C_CloseSession": [CK_SESSION_HANDLE],
        "C_Login": [CK_SESSION_HANDLE, CK_USER_TYPE, ctypes.c_char_p, CK_ULONG],
        "C_Logout": [CK_SESSION_HANDLE],
        "C_FindObjectsInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG],
        "C_FindObjects": [CK_SESSION_HANDLE, ctypes.POINTER(CK_OBJECT_HANDLE), CK_ULONG, ctypes.POINTER(CK_ULONG)],
        "C_FindObjectsFinal": [CK_SESSION_HANDLE],
        "C_GetAttributeValue": [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG],
        "C_GenerateKeyPair": [
            CK_SESSION_HANDLE,
            ctypes.POINTER(CK_MECHANISM),
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_OBJECT_HANDLE),
            ctypes.POINTER(CK_OBJECT_HANDLE),
        ],
        "C_GenerateKey": [
            CK_SESSION_HANDLE,
            ctypes.POINTER(CK_MECHANISM),
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_OBJECT_HANDLE),
        ],
        "C_GenerateRandom": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG],
        "C_DestroyObject": [CK_SESSION_HANDLE, CK_OBJECT_HANDLE],
        "C_SignInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
        "C_Sign": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)],
        "C_VerifyInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
        "C_Verify": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG],
        "C_DigestInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM)],
        "C_Digest": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)],
        "C_EncryptInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
        "C_Encrypt": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)],
        "C_DecryptInit": [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
        "C_Decrypt": [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)],
    }
    return {name: bind_function(library, name, argtypes) for name, argtypes in signatures.items()}


def get_token_slots(funcs):
    count = CK_ULONG(0)
    rv = funcs["C_GetSlotList"](CK_BBOOL(1), None, ctypes.byref(count))
    rv_ok(rv, "C_GetSlotList(count)")
    if count.value == 0:
        raise PKCS11Error("Токен не найден")
    slots = (CK_SLOT_ID * count.value)()
    rv = funcs["C_GetSlotList"](CK_BBOOL(1), slots, ctypes.byref(count))
    rv_ok(rv, "C_GetSlotList(data)")
    return [native_int(slots[index]) for index in range(int(count.value))]


def get_token_info(funcs, slot_id):
    token_info = CK_TOKEN_INFO()
    rv = funcs["C_GetTokenInfo"](slot_id, ctypes.byref(token_info))
    rv_ok(rv, "C_GetTokenInfo")
    return token_info


def choose_token_slot(funcs, slots):
    if len(slots) == 1:
        return slots[0]
    print("Найдено несколько токенов:")
    for index, slot_id in enumerate(slots):
        token_info = get_token_info(funcs, slot_id)
        print(
            f"{index}) slot={int(slot_id)} | label={clean_text(token_info.label)} | "
            f"model={clean_text(token_info.model)} | serial={clean_text(token_info.serialNumber)}"
        )
    while True:
        raw = input("Выберите номер токена [0]: ").strip()
        if raw == "":
            return slots[0]
        try:
            index = int(raw)
        except ValueError:
            print("Введите номер")
            continue
        if 0 <= index < len(slots):
            return slots[index]
        print("Нет такого номера")


def print_library_info(funcs):
    info = CK_INFO()
    rv = funcs["C_GetInfo"](ctypes.byref(info))
    rv_ok(rv, "C_GetInfo")
    print("Library loaded successfully")
    print(f"Cryptoki version: {info.cryptokiVersion.major}.{info.cryptokiVersion.minor}")
    print(f"Manufacturer: {clean_text(info.manufacturerID)}")
    print(f"Description: {clean_text(info.libraryDescription)}")
    print(f"Library version: {info.libraryVersion.major}.{info.libraryVersion.minor}")


def print_token_info(funcs, slot_id):
    token_info = get_token_info(funcs, slot_id)
    print(f"Token slot: {int(slot_id)}")
    print(f"Token label: {clean_text(token_info.label)}")
    print(f"Token manufacturer: {clean_text(token_info.manufacturerID)}")
    print(f"Token model: {clean_text(token_info.model)}")
    print(f"Token serial: {clean_text(token_info.serialNumber)}")


def get_mechanism_list(funcs, slot_id):
    count = CK_ULONG(0)
    rv = funcs["C_GetMechanismList"](slot_id, None, ctypes.byref(count))
    rv_ok(rv, "C_GetMechanismList(count)")
    if count.value == 0:
        return []
    mechanisms = (CK_MECHANISM_TYPE * count.value)()
    rv = funcs["C_GetMechanismList"](slot_id, mechanisms, ctypes.byref(count))
    rv_ok(rv, "C_GetMechanismList(data)")
    return [int(mechanisms[index]) for index in range(int(count.value))]


def get_mechanism_info(funcs, slot_id, mechanism_type):
    info = CK_MECHANISM_INFO()
    rv = funcs["C_GetMechanismInfo"](slot_id, CK_MECHANISM_TYPE(mechanism_type), ctypes.byref(info))
    rv_ok(rv, "C_GetMechanismInfo")
    return info


def run_with_session(funcs, slot_id, action, *, rw=False, login_required=False):
    session = open_session(funcs, slot_id, rw=rw)
    login_owned = False
    try:
        if login_required:
            login_owned = login(funcs, session)
        action(session, funcs)
    finally:
        operation_failed = sys.exc_info()[0] is not None
        cleanup_errors = []
        if login_owned:
            try:
                logout(funcs, session)
            except PKCS11Error as error:
                cleanup_errors.append(error)
        try:
            close_session(funcs, session)
        except PKCS11Error as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            if operation_failed:
                for error in cleanup_errors:
                    print(f"Предупреждение при очистке после исходной ошибки: {error}", file=sys.stderr)
            else:
                for error in cleanup_errors[1:]:
                    print(f"Дополнительная ошибка очистки: {error}", file=sys.stderr)
                raise cleanup_errors[0]


def run_menu(funcs, slot_id):
    actions = {
        "1": lambda: run_with_session(funcs, slot_id, find_pair_menu),
        "2": lambda: run_with_session(funcs, slot_id, lambda session, api: generate_pair(session, api, slot_id), rw=True, login_required=True),
        "3": lambda: run_with_session(funcs, slot_id, delete_pair, rw=True, login_required=True),
        "4": lambda: run_with_session(funcs, slot_id, sign_file, rw=True, login_required=True),
        "5": lambda: run_with_session(funcs, slot_id, lambda session, api: encrypt_file(session, api, slot_id), rw=True, login_required=True),
    }

    while True:
        choice = show_menu()
        if choice == "0":
            return
        action = actions.get(choice)
        if action is None:
            print("Неизвестный пункт меню")
            continue
        try:
            action()
        except PKCS11Error as error:
            print(f"Ошибка: {error}")
        except Exception as error:
            print(f"Неожиданная ошибка: {error}")


def library_load_error_message(library_path, error):
    message = f"Не удалось загрузить PKCS#11-библиотеку {library_path}: {error}"
    if platform.system() == "Darwin":
        message += (
            "\nУстановите официальный RutokenInstaller.pkg и используйте установленную "
            f"библиотеку по пути {MACOS_DEFAULT_LIBRARY_PATH}; не извлекайте и не переименовывайте dylib вручную."
        )
    return message


def initialize_pkcs11(funcs):
    rv = funcs["C_Initialize"](None)
    if rv == CKR_OK:
        return True
    if rv == CKR_CRYPTOKI_ALREADY_INITIALIZED:
        return False
    rv_ok(rv, "C_Initialize")


def main():
    print(f"hardware-encryption-test {APP_VERSION}")
    default_path = default_library_path()
    raw_library_path = input(f"Путь к PKCS#11 библиотеке [Enter: {default_path}]: ").strip().strip('"')
    library_path = resolve_library_path(raw_library_path)
    if not library_path.exists():
        print(f"Библиотека не найдена: {library_path}")
        return 1

    try:
        library = load_library(str(library_path))
    except OSError as error:
        print(library_load_error_message(library_path, error))
        return 1

    funcs = None
    initialized_here = False
    try:
        funcs = prepare_functions(library)
        initialized_here = initialize_pkcs11(funcs)
        print_library_info(funcs)
        slot_id = choose_token_slot(funcs, get_token_slots(funcs))
        print_token_info(funcs, slot_id)
        run_menu(funcs, slot_id)
    except (AttributeError, OSError) as error:
        print(library_load_error_message(library_path, error))
        return 1
    except PKCS11Error as error:
        print(f"Ошибка: {error}")
        return 1
    finally:
        if initialized_here:
            rv = funcs["C_Finalize"](None)
            if rv != CKR_OK:
                print(f"C_Finalize failed: 0x{rv:08X}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
