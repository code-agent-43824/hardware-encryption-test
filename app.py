import ctypes
import os
import platform


APP_VERSION = "v0.1"
CK_RV = ctypes.c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_ULONG = ctypes.c_ulong
CK_SLOT_ID = CK_ULONG
PACK = 1 if platform.system() == "Windows" else 0
FUNCTYPE = ctypes.CFUNCTYPE


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


class CK_FUNCTION_LIST(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    pass


CK_FUNCTION_LIST_PTR = ctypes.POINTER(CK_FUNCTION_LIST)
C_Initialize_Type = FUNCTYPE(CK_RV, CK_VOID_PTR)
C_Finalize_Type = FUNCTYPE(CK_RV, CK_VOID_PTR)
C_GetInfo_Type = FUNCTYPE(CK_RV, ctypes.POINTER(CK_INFO))
C_GetFunctionList_Type = FUNCTYPE(CK_RV, ctypes.POINTER(CK_FUNCTION_LIST_PTR))
C_GetSlotList_Type = FUNCTYPE(CK_RV, ctypes.c_ubyte, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG))
C_GetSlotInfo_Type = FUNCTYPE(CK_RV, CK_SLOT_ID, CK_VOID_PTR)
C_GetTokenInfo_Type = FUNCTYPE(CK_RV, CK_SLOT_ID, ctypes.POINTER(CK_TOKEN_INFO))


CK_FUNCTION_LIST._fields_ = [
    ("version", CK_VERSION),
    ("C_Initialize", C_Initialize_Type),
    ("C_Finalize", C_Finalize_Type),
    ("C_GetInfo", C_GetInfo_Type),
    ("C_GetFunctionList", C_GetFunctionList_Type),
    ("C_GetSlotList", C_GetSlotList_Type),
    ("C_GetSlotInfo", C_GetSlotInfo_Type),
    ("C_GetTokenInfo", C_GetTokenInfo_Type),
]


CKR_OK = 0
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_SLOT_ID_INVALID = 0x00000003


def clean_text(value):
    return value.decode("utf-8", errors="ignore").strip().rstrip("\x00")


def load_library(path):
    if platform.system() == "Windows":
        return ctypes.WinDLL(path)
    return ctypes.CDLL(path)


def main():
    print(f"Hello from hardware-encryption-test {APP_VERSION}")
    path = input("Enter path to PKCS#11 library: ").strip().strip('"')

    if not path:
        print("No path provided")
        return

    if not os.path.exists(path):
        print("Library not found")
        return

    try:
        library = load_library(path)
        get_function_list = library.C_GetFunctionList
        get_function_list.argtypes = [ctypes.POINTER(CK_FUNCTION_LIST_PTR)]
        get_function_list.restype = CK_RV

        function_list = CK_FUNCTION_LIST_PTR()
        rv = get_function_list(ctypes.byref(function_list))
        if rv != CKR_OK:
            print(f"C_GetFunctionList failed: 0x{rv:08X}")
            return

        rv = function_list.contents.C_Initialize(None)
        if rv != CKR_OK:
            print(f"C_Initialize failed: 0x{rv:08X}")
            return

        info = CK_INFO()
        rv = function_list.contents.C_GetInfo(ctypes.byref(info))
        if rv != CKR_OK:
            print(f"C_GetInfo failed: 0x{rv:08X}")
            function_list.contents.C_Finalize(None)
            return

        print("Library loaded successfully")
        print(
            f"Cryptoki version: {info.cryptokiVersion.major}.{info.cryptokiVersion.minor}"
        )
        print(f"Manufacturer: {clean_text(info.manufacturerID)}")
        print(f"Description: {clean_text(info.libraryDescription)}")
        print(f"Library version: {info.libraryVersion.major}.{info.libraryVersion.minor}")

        token_info = CK_TOKEN_INFO()
        rv = function_list.contents.C_GetTokenInfo(CK_SLOT_ID(0), ctypes.byref(token_info))
        if rv == CKR_OK:
            print(f"Token label: {clean_text(token_info.label)}")
            print(f"Token manufacturer: {clean_text(token_info.manufacturerID)}")
            print(f"Token model: {clean_text(token_info.model)}")
            print(f"Token serial: {clean_text(token_info.serialNumber)}")
        elif rv in (CKR_TOKEN_NOT_PRESENT, CKR_SLOT_ID_INVALID):
            print("подключите токен")
        else:
            print(f"C_GetTokenInfo failed: 0x{rv:08X}")

        function_list.contents.C_Finalize(None)
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
