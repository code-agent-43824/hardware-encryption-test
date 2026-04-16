import ctypes
import os
import platform


CK_RV = ctypes.c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_ULONG = ctypes.c_ulong
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


class CK_FUNCTION_LIST(ctypes.Structure):
    if PACK:
        _pack_ = PACK
    pass


CK_FUNCTION_LIST_PTR = ctypes.POINTER(CK_FUNCTION_LIST)
C_Initialize_Type = FUNCTYPE(CK_RV, CK_VOID_PTR)
C_Finalize_Type = FUNCTYPE(CK_RV, CK_VOID_PTR)
C_GetInfo_Type = FUNCTYPE(CK_RV, ctypes.POINTER(CK_INFO))


CK_FUNCTION_LIST._fields_ = [
    ("version", CK_VERSION),
    ("C_Initialize", C_Initialize_Type),
    ("C_Finalize", C_Finalize_Type),
    ("C_GetInfo", C_GetInfo_Type),
]


CKR_OK = 0


def clean_text(value):
    return value.decode("utf-8", errors="ignore").strip().rstrip("\x00")


def load_library(path):
    if platform.system() == "Windows":
        return ctypes.WinDLL(path)
    return ctypes.CDLL(path)


def main():
    print("Hello from hardware-encryption-test")
    path = input("Enter path to PKCS#11 library: ").strip().strip('"')

    if not path:
        print("No path provided")
        return

    if not os.path.exists(path):
        print("Library not found")
        return

    try:
        print(f"[diag] path accepted: {path}")
        print("[diag] loading library")
        library = load_library(path)
        print("[diag] library loaded")

        print("[diag] resolving C_GetFunctionList")
        get_function_list = library.C_GetFunctionList
        get_function_list.argtypes = [ctypes.POINTER(CK_FUNCTION_LIST_PTR)]
        get_function_list.restype = CK_RV
        print("[diag] C_GetFunctionList resolved")

        function_list = CK_FUNCTION_LIST_PTR()
        print("[diag] calling C_GetFunctionList")
        rv = get_function_list(ctypes.byref(function_list))
        print(f"[diag] C_GetFunctionList returned: 0x{rv:08X}")
        if rv != CKR_OK:
            print(f"C_GetFunctionList failed: 0x{rv:08X}")
            return

        print("[diag] calling C_Initialize(NULL)")
        rv = function_list.contents.C_Initialize(None)
        print(f"[diag] C_Initialize returned: 0x{rv:08X}")
        if rv != CKR_OK:
            print(f"C_Initialize failed: 0x{rv:08X}")
            return

        info = CK_INFO()
        print("[diag] calling C_GetInfo")
        rv = function_list.contents.C_GetInfo(ctypes.byref(info))
        print(f"[diag] C_GetInfo returned: 0x{rv:08X}")
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

        print("[diag] calling C_Finalize")
        function_list.contents.C_Finalize(None)
        print("[diag] C_Finalize completed")
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
