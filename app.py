import base64
import ctypes
import getpass
import platform
import sys
import textwrap
import time
from pathlib import Path


APP_VERSION = "v2.1"
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

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200
CKM_GOST28147_KEY_GEN = 0x00001220
CKM_GOST28147_ECB = 0x00001221
CKM_GOST28147 = 0x00001222
CKM_GOST28147_KEY_WRAP = 0x00001224
CKM_GOSTR3410_512_KEY_PAIR_GEN = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x005
CKM_GOSTR3410_12_DERIVE = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x007
CKM_GOSTR3410_WITH_GOSTR3411_12_256 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x008
CKM_GOSTR3410_WITH_GOSTR3411_12_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x009
CKM_GOSTR3411_12_256 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x012
CKM_GOSTR3411_12_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x013
CKM_KDF_GOSTR3411_2012_256 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x026
CKM_KDF_GOSTR3411_2012_512 = CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x027

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_LABEL = 0x00000003
CKA_VALUE = 0x00000011
CKA_MODIFIABLE = 0x00000170
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_WRAP = 0x00000106
CKA_UNWRAP = 0x00000107
CKA_DERIVE = 0x0000010C
CKA_SENSITIVE = 0x00000103
CKA_KEY_TYPE = 0x00000100
CKA_ID = 0x00000102
CKA_MODULUS_BITS = 0x00000121
CKA_START_DATE = 0x00000110
CKA_END_DATE = 0x00000111
CKA_EXTRACTABLE = 0x00000162
CKA_GOSTR3410_PARAMS = 0x00000250
CKA_GOSTR3411_PARAMS = 0x00000251
CKA_GOST28147_PARAMS = 0x00000252

CKR_OK = 0
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKR_MECHANISM_INVALID = 0x00000070
CKR_PIN_INCORRECT = 0x000000A0
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_USER_NOT_LOGGED_IN = 0x00000101

DEFAULT_PIN = "12345678"
RSA_MODULUS_BITS = 2048
FIND_OBJECTS_LIMIT = 128
FIND_OBJECTS_BATCH = 16
ATTR_UNAVAILABLE = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1
SAMPLE_FILE_NAMES = ["lorem-500kb.txt", str(Path("testdata") / "lorem-500kb.txt")]
GOST_28147_KEY_SIZE = 32
GOST28147_89_BLOCK_SIZE = 8
UKM_LENGTH = 8
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


class CK_DATE(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("year", ctypes.c_char * 4),
        ("month", ctypes.c_char * 2),
        ("day", ctypes.c_char * 2),
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


class CK_GOSTR3410_256_DERIVE_PARAMS(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("kdf", CK_ULONG),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE * 64),
        ("ulUKMLen", CK_ULONG),
        ("pUKM", CK_BYTE * UKM_LENGTH),
    ]


class CK_GOSTR3410_512_DERIVE_PARAMS(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    _fields_ = [
        ("kdf", CK_ULONG),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE * 128),
        ("ulUKMLen", CK_ULONG),
        ("pUKM", CK_BYTE * UKM_LENGTH),
    ]


class CK_FUNCTION_LIST(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    pass


CK_FUNCTION_LIST_PTR = ctypes.POINTER(CK_FUNCTION_LIST)


def clean_text(value):
    return value.decode("utf-8", errors="ignore").strip().rstrip("\x00")


def yes_no(value):
    return CK_BBOOL(1 if value else 0)


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


def resolve_library_path(raw_path):
    if raw_path:
        return Path(raw_path).expanduser()
    return app_dir() / default_library_name()


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
    if not value:
        return ""
    try:
        text = value.decode("utf-8").strip().rstrip("\x00")
        if text and all(ch.isprintable() for ch in text):
            return text
    except UnicodeDecodeError:
        pass
    return value.hex().upper()


def attr_id(session, funcs, obj_handle):
    return display_id(attr_bytes(session, funcs, obj_handle, CKA_ID))


def prompt_non_empty(label):
    while True:
        value = input(label).strip()
        if value:
            return value
        print("Значение не должно быть пустым")


def prompt_count():
    while True:
        raw = input("Сколько раз подписать? [1-10000]: ").strip()
        try:
            count = int(raw)
        except ValueError:
            print("Введите целое число")
            continue
        if 1 <= count <= 10000:
            return count
        print("Допустим диапазон от 1 до 10000")


def prompt_encrypt_count():
    while True:
        raw = input("Сколько раз зашифровать? [1-10000]: ").strip()
        try:
            count = int(raw)
        except ValueError:
            print("Введите целое число")
            continue
        if 1 <= count <= 10000:
            return count
        print("Допустим диапазон от 1 до 10000")


def choose_crypto_mode():
    while True:
        print("Как шифровать?")
        print("0) программно, ключ в памяти библиотеки")
        print("1) аппаратно, ключ на токене")
        raw = input("Выберите режим [0]: ").strip()
        if raw == "":
            raw = "0"
        if raw == "0":
            return {"mode": "software", "name": "программное", "cka_token": False}
        if raw == "1":
            return {"mode": "hardware", "name": "аппаратное", "cka_token": True}
        print("Введите 0 или 1")


def make_random_label(prefix):
    return f"{prefix}-{int(time.time() * 1000)}"


def pad_gost_data(data):
    padding_size = GOST28147_89_BLOCK_SIZE - (len(data) % GOST28147_89_BLOCK_SIZE)
    if padding_size == 0:
        padding_size = GOST28147_89_BLOCK_SIZE
    return data + bytes([padding_size]) * padding_size


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


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


def print_pair(prefix, pair):
    algorithm = pair.get("algorithm")
    if algorithm is None:
        print(f"{prefix}: cka_id={pair['id']} | cka_label={pair['label']}")
        return
    print(f"{prefix}: cka_id={pair['id']} | cka_label={pair['label']} | algorithm=0x{algorithm:08X}")


def pair_algorithm_name(algorithm):
    if algorithm == CKK_RSA:
        return "RSA-2048"
    if algorithm == CKK_GOSTR3410:
        return "ГОСТ Р 34.10-2012(256)"
    if algorithm == CKK_GOSTR3410_512:
        return "ГОСТ Р 34.10-2012(512)"
    return f"0x{algorithm:08X}" if algorithm is not None else "неизвестно"


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
        rv = funcs["C_FindObjectsFinal"](session)
        rv_ok(rv, "C_FindObjectsFinal")


def find_pairs(session, funcs, cka_id=None, cka_label=None):
    common = []
    if cka_id:
        common.append((CKA_ID, bytes.fromhex(cka_id) if is_hex(cka_id) else cka_id.encode("utf-8")))
    if cka_label:
        common.append((CKA_LABEL, cka_label))

    public_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PUBLIC_KEY), *common], limit=FIND_OBJECTS_LIMIT)
    private_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PRIVATE_KEY), *common], limit=FIND_OBJECTS_LIMIT)

    pairs = {}
    for key_name, handles in (("public", public_objects), ("private", private_objects)):
        for handle in handles:
            pair_id = attr_id(session, funcs, handle)
            algorithm = attr_ulong(session, funcs, handle, CKA_KEY_TYPE)
            pair_key = (pair_id, algorithm)
            pair = pairs.setdefault(
                pair_key,
                {"id": pair_id, "label": "", "algorithm": algorithm, "public": None, "private": None},
            )
            pair_label = attr_text(session, funcs, handle, CKA_LABEL)
            if pair_label and not pair["label"]:
                pair["label"] = pair_label
            pair[key_name] = handle

    return [pairs[key] for key in sorted(pairs, key=lambda item: (item[0], -1 if item[1] is None else item[1]))]


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
    pin = getpass.getpass("PIN токена: ")
    used_default_pin = False
    if pin == "":
        pin = DEFAULT_PIN
        used_default_pin = True
    pin_bytes = pin.encode("utf-8")
    rv = funcs["C_Login"](session, CK_USER_TYPE(CKU_USER), pin_bytes, CK_ULONG(len(pin_bytes)))
    if rv in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
        return
    if rv == CKR_PIN_INCORRECT:
        if used_default_pin:
            raise PKCS11Error(f"PIN не передан, автоматическая проверка {DEFAULT_PIN} не подошла. Введите правильный PIN", rv)
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
    print("Какой тип ключевой пары создать?")
    print("0) ГОСТ Р 34.10-2012(256)")
    print("1) ГОСТ Р 34.10-2012(512)")
    print("2) RSA-2048")
    while True:
        raw = input("Выберите тип [0]: ").strip()
        if raw == "":
            raw = "0"
        if raw == "0":
            return {
                "name": "ГОСТ Р 34.10-2012(256)",
                "key_type": CKK_GOSTR3410,
                "mechanism": CKM_GOSTR3410_KEY_PAIR_GEN,
                "public_params": GOST_2012_256_PARAMS,
                "private_hash_params": GOST_3411_2012_256_PARAMS,
                "required_mechanisms": [CKM_GOSTR3410_KEY_PAIR_GEN, CKM_GOSTR3411_12_256],
            }
        if raw == "1":
            return {
                "name": "ГОСТ Р 34.10-2012(512)",
                "key_type": CKK_GOSTR3410_512,
                "mechanism": CKM_GOSTR3410_512_KEY_PAIR_GEN,
                "public_params": GOST_2012_512_PARAMS,
                "private_hash_params": GOST_3411_2012_512_PARAMS,
                "required_mechanisms": [CKM_GOSTR3410_512_KEY_PAIR_GEN, CKM_GOSTR3411_12_512],
            }
        if raw == "2":
            return {"name": "RSA-2048", "key_type": CKK_RSA, "mechanism": CKM_RSA_PKCS_KEY_PAIR_GEN}
        print("Введите 0, 1 или 2")


def build_gost_key_templates(algorithm, cka_label, pair_id_value):
    start_date = CK_DATE(b"2020", b"12", b"25")
    end_date = CK_DATE(b"2030", b"12", b"25")
    public_items = [
        (CKA_CLASS, CKO_PUBLIC_KEY),
        (CKA_LABEL, cka_label),
        (CKA_ID, pair_id_value),
        (CKA_KEY_TYPE, algorithm["key_type"]),
        (CKA_TOKEN, True),
        (CKA_PRIVATE, False),
        (CKA_GOSTR3410_PARAMS, algorithm["public_params"]),
    ]
    if algorithm["key_type"] == CKK_GOSTR3410:
        public_items.append((CKA_GOSTR3411_PARAMS, algorithm["private_hash_params"]))
    public_template, public_len = attributes_array(public_items)
    private_template, private_len = attributes_array(
        [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_LABEL, cka_label),
            (CKA_ID, pair_id_value),
            (CKA_KEY_TYPE, algorithm["key_type"]),
            (CKA_TOKEN, True),
            (CKA_PRIVATE, True),
            (CKA_DERIVE, True),
            (CKA_GOSTR3410_PARAMS, algorithm["public_params"]),
            (CKA_GOSTR3411_PARAMS, algorithm["private_hash_params"]),
            (CKA_START_DATE, (start_date, ctypes.sizeof(start_date))),
            (CKA_END_DATE, (end_date, ctypes.sizeof(end_date))),
        ]
    )
    return public_template, public_len, private_template, private_len


def generate_pair(session, funcs, slot_id):
    algorithm = choose_generation_type()
    cka_id = prompt_non_empty("Введите cka_id: ")
    cka_label = prompt_non_empty("Введите cka_label: ")
    pair_id_value = bytes.fromhex(cka_id) if is_hex(cka_id) else cka_id.encode("utf-8")

    mechanisms = get_mechanism_list(funcs, slot_id)
    for mechanism_type in algorithm.get("required_mechanisms", [algorithm["mechanism"]]):
        if mechanism_type not in mechanisms:
            raise PKCS11Error(f"Токен не поддерживает механизм 0x{mechanism_type:08X} для {algorithm['name']}")

    if algorithm["key_type"] == CKK_RSA:
        mechanism_info = get_mechanism_info(funcs, slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        modulus_bits = RSA_MODULUS_BITS
        if not (int(mechanism_info.ulMinKeySize) <= modulus_bits <= int(mechanism_info.ulMaxKeySize)):
            raise PKCS11Error(
                f"Токен не поддерживает RSA-{modulus_bits} (доступно {int(mechanism_info.ulMinKeySize)}..{int(mechanism_info.ulMaxKeySize)})"
            )
        public_template, public_len = attributes_array(
            [
                (CKA_CLASS, CKO_PUBLIC_KEY),
                (CKA_LABEL, cka_label),
                (CKA_ID, pair_id_value),
                (CKA_KEY_TYPE, CKK_RSA),
                (CKA_TOKEN, True),
                (CKA_ENCRYPT, True),
                (CKA_PRIVATE, False),
                (CKA_MODULUS_BITS, modulus_bits),
            ]
        )
        private_template, private_len = attributes_array(
            [
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_LABEL, cka_label),
                (CKA_ID, pair_id_value),
                (CKA_KEY_TYPE, CKK_RSA),
                (CKA_DECRYPT, True),
                (CKA_TOKEN, True),
                (CKA_PRIVATE, True),
            ]
        )
    else:
        public_template, public_len, private_template, private_len = build_gost_key_templates(algorithm, cka_label, pair_id_value)

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
    if algorithm == CKK_RSA:
        return CK_MECHANISM(CKM_SHA256_RSA_PKCS, None, CK_ULONG(0)), None, "SHA-256"
    if algorithm in {CKK_GOSTR3410, CKK_GOSTR3410_512}:
        while True:
            print("Как хешировать для подписи?")
            print("0) программно библиотекой Rutoken")
            print("1) аппаратно внутри токена")
            raw = input("Выберите режим [0]: ").strip()
            if raw == "":
                raw = "0"
            if raw not in {"0", "1"}:
                print("Введите 0 или 1")
                continue
            software_hash = raw == "0"
            break
    if algorithm == CKK_GOSTR3410:
        mechanism_type = CKM_GOSTR3410_WITH_GOSTR3411_12_256
        params = GOST_3411_2012_256_PARAMS
        hash_name = "ГОСТ Р 34.11-2012(256)"
    if algorithm == CKK_GOSTR3410_512:
        mechanism_type = CKM_GOSTR3410_WITH_GOSTR3411_12_512
        params = GOST_3411_2012_512_PARAMS
        hash_name = "ГОСТ Р 34.11-2012(512)"
    if algorithm in {CKK_GOSTR3410, CKK_GOSTR3410_512}:
        if software_hash:
            param_buffer = ctypes.create_string_buffer(params)
            mechanism = CK_MECHANISM(
                mechanism_type,
                ctypes.cast(param_buffer, CK_VOID_PTR),
                CK_ULONG(len(params)),
            )
            return mechanism, param_buffer, f"{hash_name}, программное хеширование"
        return CK_MECHANISM(mechanism_type, None, CK_ULONG(0)), None, f"{hash_name}, аппаратное хеширование"
    raise PKCS11Error(f"Неподдерживаемый тип ключа для подписи: {pair_algorithm_name(algorithm)}")


def build_vko_mechanism(pair, public_value, ukm):
    algorithm = pair.get("algorithm")
    if algorithm == CKK_GOSTR3410:
        params_struct = CK_GOSTR3410_256_DERIVE_PARAMS()
        expected_len = 64
        kdf = CKM_KDF_GOSTR3411_2012_256
    elif algorithm == CKK_GOSTR3410_512:
        params_struct = CK_GOSTR3410_512_DERIVE_PARAMS()
        expected_len = 128
        kdf = CKM_KDF_GOSTR3411_2012_512
    else:
        raise PKCS11Error(f"VKO поддерживается только для ГОСТ-пар, получено: {pair_algorithm_name(algorithm)}")

    if len(public_value) != expected_len:
        raise PKCS11Error(f"Неверная длина открытого ключа для VKO: ожидалось {expected_len}, получено {len(public_value)}")

    params_struct.kdf = CK_ULONG(kdf)
    params_struct.ulPublicDataLen = CK_ULONG(len(public_value))
    params_struct.pPublicData[: len(public_value)] = public_value
    params_struct.ulUKMLen = CK_ULONG(len(ukm))
    params_struct.pUKM[: len(ukm)] = ukm

    mechanism = CK_MECHANISM(
        CKM_GOSTR3410_12_DERIVE,
        ctypes.cast(ctypes.byref(params_struct), CK_VOID_PTR),
        CK_ULONG(ctypes.sizeof(params_struct)),
    )
    return mechanism, params_struct, kdf


def derive_kek(session, funcs, pair):
    public_key = pair.get("public")
    private_key = pair.get("private")
    if not public_key or not private_key:
        raise PKCS11Error("Для VKO нужна полная ГОСТ-пара: открытый и закрытый ключ")

    public_value = attr_bytes(session, funcs, public_key, CKA_VALUE)
    if not public_value:
        raise PKCS11Error("Не удалось прочитать CKA_VALUE открытого ГОСТ-ключа")

    ukm = random_bytes(session, funcs, UKM_LENGTH)
    mechanism, mechanism_params, kdf = build_vko_mechanism(pair, public_value, ukm)
    kek_template, kek_template_len = attributes_array(
        [
            (CKA_LABEL, make_random_label("vko-kek")),
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GOST28147),
            (CKA_TOKEN, False),
            (CKA_MODIFIABLE, True),
            (CKA_PRIVATE, True),
            (CKA_WRAP, True),
            (CKA_UNWRAP, True),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_GOST28147_PARAMS, GOST_28147_PARAMS),
            (CKA_EXTRACTABLE, False),
            (CKA_SENSITIVE, True),
        ]
    )
    kek_handle = CK_OBJECT_HANDLE()
    rv = funcs["C_DeriveKey"](
        session,
        ctypes.byref(mechanism),
        private_key,
        kek_template,
        CK_ULONG(kek_template_len),
        ctypes.byref(kek_handle),
    )
    rv_ok(rv, "C_DeriveKey")
    return {
        "handle": kek_handle,
        "ukm": ukm,
        "kdf": kdf,
        "public_data_len": len(public_value),
        "mechanism_keepalive": mechanism_params,
    }


def create_source_cek(session, funcs, mode_info):
    label = make_random_label("gost28147-cek-src")
    key_value = random_bytes(session, funcs, GOST_28147_KEY_SIZE)
    template, template_len = attributes_array(
        [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_LABEL, label),
            (CKA_KEY_TYPE, CKK_GOST28147),
            (CKA_TOKEN, False),
            (CKA_PRIVATE, True),
            (CKA_MODIFIABLE, True),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_GOST28147_PARAMS, GOST_28147_PARAMS),
            (CKA_VALUE, key_value),
            (CKA_EXTRACTABLE, True),
            (CKA_SENSITIVE, False),
        ]
    )
    key_handle = CK_OBJECT_HANDLE()
    rv = funcs["C_CreateObject"](session, template, CK_ULONG(template_len), ctypes.byref(key_handle))
    rv_ok(rv, f"C_CreateObject(source CEK for {mode_info['mode']})")
    return key_handle, label


def wrap_cek(session, funcs, kek_handle, cek_handle, ukm):
    last_error = None
    for mechanism_type in (CKM_GOST28147_KEY_WRAP, CKM_GOST28147):
        mechanism, keepalive = mechanism_with_optional_param(mechanism_type, ukm)
        wrapped_len = CK_ULONG(0)
        rv = funcs["C_WrapKey"](session, ctypes.byref(mechanism), kek_handle, cek_handle, None, ctypes.byref(wrapped_len))
        if rv == CKR_MECHANISM_INVALID:
            last_error = PKCS11Error(f"C_WrapKey(size, mechanism=0x{mechanism_type:08X})", rv)
            continue
        rv_ok(rv, f"C_WrapKey(size, mechanism=0x{mechanism_type:08X})")

        wrapped = (CK_BYTE * int(wrapped_len.value))()
        rv = funcs["C_WrapKey"](
            session,
            ctypes.byref(mechanism),
            kek_handle,
            cek_handle,
            ctypes.cast(wrapped, CK_BYTE_PTR),
            ctypes.byref(wrapped_len),
        )
        rv_ok(rv, f"C_WrapKey(data, mechanism=0x{mechanism_type:08X})")
        return bytes(wrapped[: int(wrapped_len.value)]), keepalive, mechanism_type

    raise last_error or PKCS11Error("C_WrapKey")


def unwrap_cek(session, funcs, kek_handle, wrapped_key, ukm, mode_info):
    label = make_random_label("gost28147-cek")
    template_items = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_LABEL, label),
        (CKA_KEY_TYPE, CKK_GOST28147),
        (CKA_TOKEN, mode_info["cka_token"]),
        (CKA_PRIVATE, True),
        (CKA_MODIFIABLE, True),
        (CKA_ENCRYPT, True),
        (CKA_DECRYPT, True),
        (CKA_GOST28147_PARAMS, GOST_28147_PARAMS),
    ]
    if mode_info["mode"] == "software":
        template_items.extend([(CKA_EXTRACTABLE, True), (CKA_SENSITIVE, False)])
    else:
        template_items.extend([(CKA_EXTRACTABLE, False), (CKA_SENSITIVE, True)])
    template, template_len = attributes_array(template_items)
    wrapped_buffer = (CK_BYTE * len(wrapped_key)).from_buffer_copy(wrapped_key)
    last_error = None
    for mechanism_type in (CKM_GOST28147_KEY_WRAP, CKM_GOST28147):
        mechanism, keepalive = mechanism_with_optional_param(mechanism_type, ukm)
        key_handle = CK_OBJECT_HANDLE()
        rv = funcs["C_UnwrapKey"](
            session,
            ctypes.byref(mechanism),
            kek_handle,
            ctypes.cast(wrapped_buffer, CK_BYTE_PTR),
            CK_ULONG(len(wrapped_key)),
            template,
            CK_ULONG(template_len),
            ctypes.byref(key_handle),
        )
        if rv == CKR_MECHANISM_INVALID:
            last_error = PKCS11Error(f"C_UnwrapKey(mechanism=0x{mechanism_type:08X})", rv)
            continue
        rv_ok(rv, f"C_UnwrapKey(mechanism=0x{mechanism_type:08X})")
        return key_handle, label, keepalive, mechanism_type

    raise last_error or PKCS11Error("C_UnwrapKey")


def encrypt_with_cek(session, funcs, cek_handle, plaintext):
    iv = random_bytes(session, funcs, GOST28147_89_BLOCK_SIZE)
    mechanism = CK_MECHANISM(CKM_GOST28147_ECB, None, CK_ULONG(0))
    previous_block = iv
    encrypted_blocks = []

    for offset in range(0, len(plaintext), GOST28147_89_BLOCK_SIZE):
        block = plaintext[offset : offset + GOST28147_89_BLOCK_SIZE]
        mixed_block = xor_bytes(previous_block, block)
        input_buffer = (CK_BYTE * len(mixed_block)).from_buffer_copy(mixed_block)

        rv = funcs["C_EncryptInit"](session, ctypes.byref(mechanism), cek_handle)
        rv_ok(rv, "C_EncryptInit")

        out_len = CK_ULONG(GOST28147_89_BLOCK_SIZE)
        out_block = (CK_BYTE * GOST28147_89_BLOCK_SIZE)()
        rv = funcs["C_Encrypt"](
            session,
            ctypes.cast(input_buffer, CK_BYTE_PTR),
            CK_ULONG(len(mixed_block)),
            ctypes.cast(out_block, CK_BYTE_PTR),
            ctypes.byref(out_len),
        )
        rv_ok(rv, "C_Encrypt(data)")

        encrypted_block = bytes(out_block[: int(out_len.value)])
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return iv, b"".join(encrypted_blocks)


def encrypt_file(session, funcs, slot_id):
    raw_path = input("Что зашифровать? ").strip().strip('"')
    file_path = resolve_sample_file_path(raw_path)
    if not file_path.exists():
        print(f"Файл не найден: {file_path}")
        return

    count = prompt_encrypt_count()
    mode_info = choose_crypto_mode()
    pairs = [pair for pair in find_pairs(session, funcs) if pair.get("algorithm") in {CKK_GOSTR3410, CKK_GOSTR3410_512}]
    if not pairs:
        print("ГОСТ-пары не найдены")
        return
    pair = choose_pair(pairs, prompt="Какой ГОСТ-парой шифровать? [0]: ")
    if not pair:
        return

    plaintext = pad_gost_data(file_path.read_bytes())
    setup_started = time.perf_counter()
    kek_info = derive_kek(session, funcs, pair)
    source_cek = None
    final_cek = None
    wrapped = b""
    wrap_mechanism_type = None

    try:
        source_cek, _ = create_source_cek(session, funcs, mode_info)
        wrapped, _, wrap_mechanism_type = wrap_cek(session, funcs, kek_info["handle"], source_cek, kek_info["ukm"])
        rv = funcs["C_DestroyObject"](session, source_cek)
        rv_ok(rv, "C_DestroyObject(source CEK)")
        source_cek = None
        final_cek, _, _, wrap_mechanism_type = unwrap_cek(session, funcs, kek_info["handle"], wrapped, kek_info["ukm"], mode_info)
        setup_elapsed = time.perf_counter() - setup_started

        operation_times = []
        last_iv = b""
        last_ciphertext = b""
        total_started = time.perf_counter()
        for _ in range(count):
            started = time.perf_counter()
            last_iv, last_ciphertext = encrypt_with_cek(session, funcs, final_cek, plaintext)
            operation_times.append(time.perf_counter() - started)
        total_elapsed = time.perf_counter() - total_started
    finally:
        if source_cek:
            rv = funcs["C_DestroyObject"](session, source_cek)
            rv_ok(rv, "C_DestroyObject(source CEK cleanup)")
        if final_cek:
            rv = funcs["C_DestroyObject"](session, final_cek)
            rv_ok(rv, "C_DestroyObject(final CEK)")
        if kek_info.get("handle"):
            rv = funcs["C_DestroyObject"](session, kek_info["handle"])
            rv_ok(rv, "C_DestroyObject(KEK)")

    avg_elapsed = total_elapsed / count if count else 0.0
    print_pair("Шифрование выполнено ключом", pair)
    print(f"Режим шифрования: {mode_info['name']}")
    print("Исходный CEK для wrap создаётся как session object: CKA_TOKEN=FALSE")
    print(f"Финальный CEK после unwrap: CKA_TOKEN={'TRUE' if mode_info['cka_token'] else 'FALSE'}")
    print(f"Алгоритм KEK: VKO / CKM_GOSTR3410_12_DERIVE, KDF=0x{kek_info['kdf']:08X}")
    print(f"Размер publicData для VKO: {kek_info['public_data_len']} байт | UKM: {kek_info['ukm'].hex().upper()}")
    print(f"CEK получен через wrap/unwrap, механизм=0x{(wrap_mechanism_type or 0):08X}, размер wrapped CEK: {len(wrapped)} байт")
    print(f"Файл: {file_path}")
    print(f"Размер исходных данных: {file_path.stat().st_size} байт")
    print(f"Размер данных после padding: {len(plaintext)} байт")
    print(f"Количество шифрований: {count}")
    print(f"Подготовка ключей: {setup_elapsed:.6f} сек")
    print(f"Общее время шифрования: {total_elapsed:.6f} сек")
    print(f"Среднее время одного шифрования: {avg_elapsed:.6f} сек")
    print(f"Минимум: {min(operation_times):.6f} сек | Максимум: {max(operation_times):.6f} сек")
    print(f"IV последнего шифрования: {last_iv.hex().upper()}")
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
    count = prompt_count()
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

    data = file_path.read_bytes()
    data_buffer = (CK_BYTE * len(data)).from_buffer_copy(data)
    mechanism, mechanism_keepalive, hash_mode_name = signing_mechanism_for_pair(pair)
    signature_lengths = []
    last_signature_bytes = b""
    operation_times = []
    total_started = time.perf_counter()

    for _ in range(count):
        started = time.perf_counter()

        rv = funcs["C_SignInit"](session, ctypes.byref(mechanism), private_key)
        rv_ok(rv, "C_SignInit")

        out_len = CK_ULONG(0)
        rv = funcs["C_Sign"](session, data_buffer, CK_ULONG(len(data)), None, ctypes.byref(out_len))
        rv_ok(rv, "C_Sign(size)")

        signature = (CK_BYTE * int(out_len.value))()
        rv = funcs["C_Sign"](
            session,
            data_buffer,
            CK_ULONG(len(data)),
            ctypes.cast(signature, CK_BYTE_PTR),
            ctypes.byref(out_len),
        )
        rv_ok(rv, "C_Sign(data)")

        operation_times.append(time.perf_counter() - started)
        signature_lengths.append(int(out_len.value))
        last_signature_bytes = bytes(signature[: int(out_len.value)])

    total_elapsed = time.perf_counter() - total_started
    avg_elapsed = total_elapsed / count if count else 0.0
    signature_base64 = base64.b64encode(last_signature_bytes).decode("ascii") if last_signature_bytes else ""

    print_pair("Подпись выполнена ключом", pair)
    print(f"Алгоритм подписи: {pair_algorithm_name(pair.get('algorithm'))}")
    print(f"Режим хеширования: {hash_mode_name}")
    print(f"Файл: {file_path}")
    print(f"Размер данных: {len(data)} байт")
    print(f"Количество подписаний: {count}")
    print(f"Размер последней подписи: {signature_lengths[-1]} байт")
    print(f"Общее время: {total_elapsed:.6f} сек")
    print(f"Среднее время одной подписи: {avg_elapsed:.6f} сек")
    print(f"Минимум: {min(operation_times):.6f} сек | Максимум: {max(operation_times):.6f} сек")
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
    print("5) шифровать 500 кб данных")
    print("0) выйти")
    return input("> ").strip()


def prepare_functions(library):
    get_function_list = bind_function(library, "C_GetFunctionList", [ctypes.POINTER(CK_FUNCTION_LIST_PTR)])
    function_list = CK_FUNCTION_LIST_PTR()
    rv = get_function_list(ctypes.byref(function_list))
    rv_ok(rv, "C_GetFunctionList")

    return {
        "C_Initialize": bind_function(library, "C_Initialize", [CK_VOID_PTR]),
        "C_Finalize": bind_function(library, "C_Finalize", [CK_VOID_PTR]),
        "C_GetInfo": bind_function(library, "C_GetInfo", [ctypes.POINTER(CK_INFO)]),
        "C_GetSlotList": bind_function(library, "C_GetSlotList", [CK_BBOOL, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG)]),
        "C_GetTokenInfo": bind_function(library, "C_GetTokenInfo", [CK_SLOT_ID, ctypes.POINTER(CK_TOKEN_INFO)]),
        "C_GetMechanismList": bind_function(library, "C_GetMechanismList", [CK_SLOT_ID, ctypes.POINTER(CK_MECHANISM_TYPE), ctypes.POINTER(CK_ULONG)]),
        "C_GetMechanismInfo": bind_function(library, "C_GetMechanismInfo", [CK_SLOT_ID, CK_MECHANISM_TYPE, ctypes.POINTER(CK_MECHANISM_INFO)]),
        "C_OpenSession": bind_function(library, "C_OpenSession", [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, ctypes.POINTER(CK_SESSION_HANDLE)]),
        "C_CloseSession": bind_function(library, "C_CloseSession", [CK_SESSION_HANDLE]),
        "C_Login": bind_function(library, "C_Login", [CK_SESSION_HANDLE, CK_USER_TYPE, ctypes.c_char_p, CK_ULONG]),
        "C_Logout": bind_function(library, "C_Logout", [CK_SESSION_HANDLE]),
        "C_FindObjectsInit": bind_function(library, "C_FindObjectsInit", [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]),
        "C_FindObjects": bind_function(library, "C_FindObjects", [CK_SESSION_HANDLE, ctypes.POINTER(CK_OBJECT_HANDLE), CK_ULONG, ctypes.POINTER(CK_ULONG)]),
        "C_FindObjectsFinal": bind_function(library, "C_FindObjectsFinal", [CK_SESSION_HANDLE]),
        "C_GetAttributeValue": bind_function(library, "C_GetAttributeValue", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]),
        "C_CreateObject": bind_function(library, "C_CreateObject", [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_GenerateKeyPair": bind_function(library, "C_GenerateKeyPair", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE), ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_GenerateKey": bind_function(library, "C_GenerateKey", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_DeriveKey": bind_function(library, "C_DeriveKey", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_WrapKey": bind_function(library, "C_WrapKey", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)]),
        "C_UnwrapKey": bind_function(library, "C_UnwrapKey", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_GenerateRandom": bind_function(library, "C_GenerateRandom", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]),
        "C_DestroyObject": bind_function(library, "C_DestroyObject", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]),
        "C_SignInit": bind_function(library, "C_SignInit", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]),
        "C_Sign": bind_function(library, "C_Sign", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)]),
        "C_EncryptInit": bind_function(library, "C_EncryptInit", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]),
        "C_Encrypt": bind_function(library, "C_Encrypt", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)]),
    }


def get_first_token_slot(funcs):
    count = CK_ULONG(0)
    rv = funcs["C_GetSlotList"](CK_BBOOL(1), None, ctypes.byref(count))
    rv_ok(rv, "C_GetSlotList(count)")
    if count.value == 0:
        raise PKCS11Error("Токен не найден")
    slots = (CK_SLOT_ID * count.value)()
    rv = funcs["C_GetSlotList"](CK_BBOOL(1), slots, ctypes.byref(count))
    rv_ok(rv, "C_GetSlotList(data)")
    return slots[0]


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
    token_info = CK_TOKEN_INFO()
    rv = funcs["C_GetTokenInfo"](slot_id, ctypes.byref(token_info))
    rv_ok(rv, "C_GetTokenInfo")
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
    try:
        if login_required:
            login(funcs, session)
        try:
            action(session, funcs)
        finally:
            if login_required:
                logout(funcs, session)
    finally:
        close_session(funcs, session)


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


def main():
    print(f"Hello from hardware-encryption-test {APP_VERSION}")
    raw_library_path = input("Путь к PKCS#11 библиотеке [Enter для файла рядом с приложением]: ").strip().strip('"')
    library_path = resolve_library_path(raw_library_path)
    if not library_path.exists():
        print(f"Библиотека не найдена: {library_path}")
        sys.exit(1)

    library = load_library(str(library_path))
    funcs = None
    try:
        funcs = prepare_functions(library)
        rv = funcs["C_Initialize"](None)
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            rv_ok(rv, "C_Initialize")
        print_library_info(funcs)
        slot_id = get_first_token_slot(funcs)
        print_token_info(funcs, slot_id)
        run_menu(funcs, slot_id)
    except PKCS11Error as error:
        print(f"Error: {error}")
    finally:
        if funcs is not None:
            rv = funcs["C_Finalize"](None)
            if rv != CKR_OK:
                print(f"C_Finalize failed: 0x{rv:08X}", file=sys.stderr)


if __name__ == "__main__":
    main()
