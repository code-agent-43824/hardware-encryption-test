import ctypes
import getpass
import platform
import sys
from pathlib import Path


APP_VERSION = "v0.3"
CK_RV = ctypes.c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_ULONG = ctypes.c_ulong
CK_SLOT_ID = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_OBJECT_HANDLE = CK_ULONG
CK_FLAGS = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_OBJECT_CLASS = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_MECHANISM_TYPE = CK_ULONG
CK_BBOOL = ctypes.c_ubyte
CK_UTF8CHAR = ctypes.c_ubyte
CK_UTF8CHAR_PTR = ctypes.POINTER(CK_UTF8CHAR)
CK_BYTE = ctypes.c_ubyte
CK_BYTE_PTR = ctypes.POINTER(CK_BYTE)
CK_ATTRIBUTE_TYPE = CK_ULONG
PACK = 1 if platform.system() == "Windows" else 0
FUNCTYPE = ctypes.CFUNCTYPE


CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1

CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKK_RSA = 0x00000000

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_SHA256_RSA_PKCS = 0x00000040

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ID = 0x00000102
CKA_KEY_TYPE = 0x00000100
CKA_PRIVATE = 0x00000002
CKA_MODULUS_BITS = 0x00000121
CKA_PUBLIC_EXPONENT = 0x00000122
CKA_ENCRYPT = 0x00000104
CKA_VERIFY = 0x0000010A
CKA_WRAP = 0x00000110
CKA_SENSITIVE = 0x00000103
CKA_DECRYPT = 0x00000105
CKA_SIGN = 0x00000108
CKA_UNWRAP = 0x00000112
CKA_EXTRACTABLE = 0x00000162

CKR_OK = 0
CKR_CANCEL = 0x00000001
CKR_ARGUMENTS_BAD = 0x00000007
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKR_GENERAL_ERROR = 0x00000005
CKR_OBJECT_HANDLE_INVALID = 0x00000082
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
CKR_PIN_INCORRECT = 0x000000A0
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_SLOT_ID_INVALID = 0x00000003
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_USER_NOT_LOGGED_IN = 0x00000101

ATTR_UNAVAILABLE = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1


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


class CK_FUNCTION_LIST(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    pass


CK_FUNCTION_LIST_PTR = ctypes.POINTER(CK_FUNCTION_LIST)
C_GetFunctionList_Type = FUNCTYPE(CK_RV, ctypes.POINTER(CK_FUNCTION_LIST_PTR))


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


def print_pair(prefix, pair):
    print(f"{prefix}: cka_id={pair['id']} | cka_label={pair['label']}")


def find_objects(session, funcs, template_items, limit=32):
    template, template_len = attributes_array(template_items)
    rv = funcs["C_FindObjectsInit"](session, template, CK_ULONG(template_len))
    rv_ok(rv, "C_FindObjectsInit")
    try:
        objects = []
        while len(objects) < limit:
            batch = (CK_OBJECT_HANDLE * min(16, limit - len(objects)))()
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

    public_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA), *common], limit=128)
    private_objects = find_objects(session, funcs, [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA), *common], limit=128)

    public_map = {}
    for handle in public_objects:
        pair_id = attr_id(session, funcs, handle)
        pair_label = attr_text(session, funcs, handle, CKA_LABEL)
        public_map[(pair_id, pair_label)] = handle

    private_map = {}
    for handle in private_objects:
        pair_id = attr_id(session, funcs, handle)
        pair_label = attr_text(session, funcs, handle, CKA_LABEL)
        private_map[(pair_id, pair_label)] = handle

    keys = sorted(set(public_map) | set(private_map))
    return [
        {
            "id": pair_id,
            "label": pair_label,
            "public": public_map.get((pair_id, pair_label)),
            "private": private_map.get((pair_id, pair_label)),
        }
        for pair_id, pair_label in keys
    ]


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
    pin_bytes = pin.encode("utf-8")
    rv = funcs["C_Login"](session, CK_USER_TYPE(CKU_USER), pin_bytes, CK_ULONG(len(pin_bytes)))
    if rv in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
        return
    if rv == CKR_PIN_INCORRECT:
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


def generate_pair(session, funcs):
    cka_id = prompt_non_empty("Введите cka_id: ")
    cka_label = prompt_non_empty("Введите cka_label: ")
    pair_id_value = bytes.fromhex(cka_id) if is_hex(cka_id) else cka_id.encode("utf-8")

    public_template, public_len = attributes_array(
        [
            (CKA_TOKEN, True),
            (CKA_LABEL, cka_label),
            (CKA_ID, pair_id_value),
            (CKA_MODULUS_BITS, 2048),
            (CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
            (CKA_ENCRYPT, True),
            (CKA_VERIFY, True),
            (CKA_WRAP, True),
        ]
    )
    private_template, private_len = attributes_array(
        [
            (CKA_TOKEN, True),
            (CKA_PRIVATE, True),
            (CKA_LABEL, cka_label),
            (CKA_ID, pair_id_value),
            (CKA_SENSITIVE, True),
            (CKA_DECRYPT, True),
            (CKA_SIGN, True),
            (CKA_UNWRAP, True),
            (CKA_EXTRACTABLE, False),
        ]
    )
    mechanism = CK_MECHANISM(CKM_RSA_PKCS_KEY_PAIR_GEN, None, CK_ULONG(0))
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
    print(f"Пара создана: cka_id={cka_id} | cka_label={cka_label}")


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
    if not raw_path:
        print("Нужно указать путь к файлу")
        return
    file_path = Path(raw_path).expanduser()
    if not file_path.exists():
        print("Файл не найден")
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
    mechanism = CK_MECHANISM(CKM_SHA256_RSA_PKCS, None, CK_ULONG(0))
    signature_lengths = []
    for _ in range(count):
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
        signature_lengths.append(int(out_len.value))

    print_pair("Подпись выполнена ключом", pair)
    print(f"Файл: {file_path}")
    print(f"Размер данных: {len(data)} байт")
    print(f"Количество подписаний: {count}")
    print(f"Размер последней подписи: {signature_lengths[-1]} байт")


def show_menu():
    print()
    print("Выберите действие:")
    print("1) найти ключевую пару")
    print("2) сгенерировать ключевую пару")
    print("3) удалить ключевую пару")
    print("4) подписать 500 килобайт данных")
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
        "C_OpenSession": bind_function(library, "C_OpenSession", [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, ctypes.POINTER(CK_SESSION_HANDLE)]),
        "C_CloseSession": bind_function(library, "C_CloseSession", [CK_SESSION_HANDLE]),
        "C_Login": bind_function(library, "C_Login", [CK_SESSION_HANDLE, CK_USER_TYPE, ctypes.c_char_p, CK_ULONG]),
        "C_Logout": bind_function(library, "C_Logout", [CK_SESSION_HANDLE]),
        "C_FindObjectsInit": bind_function(library, "C_FindObjectsInit", [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]),
        "C_FindObjects": bind_function(library, "C_FindObjects", [CK_SESSION_HANDLE, ctypes.POINTER(CK_OBJECT_HANDLE), CK_ULONG, ctypes.POINTER(CK_ULONG)]),
        "C_FindObjectsFinal": bind_function(library, "C_FindObjectsFinal", [CK_SESSION_HANDLE]),
        "C_GetAttributeValue": bind_function(library, "C_GetAttributeValue", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]),
        "C_GenerateKeyPair": bind_function(library, "C_GenerateKeyPair", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG, ctypes.POINTER(CK_OBJECT_HANDLE), ctypes.POINTER(CK_OBJECT_HANDLE)]),
        "C_DestroyObject": bind_function(library, "C_DestroyObject", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]),
        "C_SignInit": bind_function(library, "C_SignInit", [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]),
        "C_Sign": bind_function(library, "C_Sign", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, ctypes.POINTER(CK_ULONG)]),
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


def run_menu(funcs, slot_id):
    while True:
        choice = show_menu()
        if choice == "0":
            return
        if choice == "1":
            session = open_session(funcs, slot_id, rw=False)
            try:
                find_pair_menu(session, funcs)
            finally:
                close_session(funcs, session)
        elif choice == "2":
            session = open_session(funcs, slot_id, rw=True)
            try:
                login(funcs, session)
                try:
                    generate_pair(session, funcs)
                finally:
                    logout(funcs, session)
            finally:
                close_session(funcs, session)
        elif choice == "3":
            session = open_session(funcs, slot_id, rw=True)
            try:
                login(funcs, session)
                try:
                    delete_pair(session, funcs)
                finally:
                    logout(funcs, session)
            finally:
                close_session(funcs, session)
        elif choice == "4":
            session = open_session(funcs, slot_id, rw=True)
            try:
                login(funcs, session)
                try:
                    sign_file(session, funcs)
                finally:
                    logout(funcs, session)
            finally:
                close_session(funcs, session)
        else:
            print("Неизвестный пункт меню")


def main():
    print(f"Hello from hardware-encryption-test {APP_VERSION}")

    funcs = None
    try:
        raw_path = input("Enter path to PKCS#11 library: ").strip().strip('"')
        library_path = resolve_library_path(raw_path)

        if not library_path.exists():
            print(f"Library not found: {library_path}")
            return

        library = load_library(str(library_path))
        funcs = prepare_functions(library)
        rv = funcs["C_Initialize"](None)
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise PKCS11Error("C_Initialize", rv)

        print_library_info(funcs)
        slot_id = get_first_token_slot(funcs)
        print_token_info(funcs, slot_id)
        run_menu(funcs, slot_id)
    except EOFError:
        print("Input cancelled")
    except Exception as error:
        print(f"Error: {error}")
    finally:
        if funcs is not None:
            rv = funcs["C_Finalize"](None)
            if rv != CKR_OK:
                print(f"C_Finalize failed: 0x{rv:08X}", file=sys.stderr)


if __name__ == "__main__":
    main()
