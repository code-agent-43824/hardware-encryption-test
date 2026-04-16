import ctypes
import os
import platform


CK_RV = ctypes.c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_ULONG = ctypes.c_ulong


class CK_VERSION(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_ubyte),
        ("minor", ctypes.c_ubyte),
    ]


class CK_INFO(ctypes.Structure):
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", ctypes.c_char * 32),
        ("flags", CK_ULONG),
        ("libraryDescription", ctypes.c_char * 32),
        ("libraryVersion", CK_VERSION),
    ]


C_Initialize_Type = ctypes.CFUNCTYPE(CK_RV, CK_VOID_PTR)
C_Finalize_Type = ctypes.CFUNCTYPE(CK_RV, CK_VOID_PTR)
C_GetInfo_Type = ctypes.CFUNCTYPE(CK_RV, ctypes.POINTER(CK_INFO))


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [
        ("version", CK_VERSION),
        ("C_Initialize", C_Initialize_Type),
        ("C_Finalize", C_Finalize_Type),
        ("C_GetInfo", C_GetInfo_Type),
    ]


CK_FUNCTION_LIST_PTR = ctypes.POINTER(CK_FUNCTION_LIST)
C_GetFunctionList_Type = ctypes.CFUNCTYPE(CK_RV, ctypes.POINTER(CK_FUNCTION_LIST_PTR))


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
        library = load_library(path)
        get_function_list = C_GetFunctionList_Type(("C_GetFunctionList", library))

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

        function_list.contents.C_Finalize(None)
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
