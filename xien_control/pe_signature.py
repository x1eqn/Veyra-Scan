from __future__ import annotations

import ctypes
import json
import subprocess
from pathlib import Path
from uuid import UUID

from .exe_models import SignatureInfo


def check_signature(path: Path, include_details: bool = False) -> SignatureInfo:
    status = _authenticode_status(path)
    info = SignatureInfo(status=status)
    if include_details and status in {"SIGNED_VALID", "SIGNED_INVALID"}:
        details = _powershell_signature(path)
        if details:
            info.status = details.get("status") or info.status
            info.signer_subject = details.get("signer_subject", "")
            info.signer_issuer = details.get("signer_issuer", "")
    return info


def _authenticode_status(path: Path) -> str:
    if not hasattr(ctypes, "windll"):
        return "UNKNOWN"
    try:
        result = _win_verify_trust(path)
    except (AttributeError, OSError, ValueError):
        return "UNKNOWN"
    code = int(result) & 0xFFFFFFFF
    if code == 0:
        return "SIGNED_VALID"
    if code in {0x800B0100, 0x800B0001, 0x800B0003}:
        return "UNSIGNED"
    if code in {0x800B0101, 0x800B0109, 0x80096010, 0x80096019}:
        return "SIGNED_INVALID"
    return "UNKNOWN"


def _powershell_signature(path: Path) -> dict[str, str]:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "[pscustomobject]@{"
            "status=$s.Status.ToString();"
            "signer_subject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''};"
            "signer_issuer=if($s.SignerCertificate){$s.SignerCertificate.Issuer}else{''}"
            "} | ConvertTo-Json -Compress"
        ),
        str(path),
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}
    status_map = {
        "Valid": "SIGNED_VALID",
        "NotSigned": "UNSIGNED",
        "HashMismatch": "SIGNED_INVALID",
        "NotTrusted": "SIGNED_INVALID",
        "UnknownError": "UNKNOWN",
    }
    return {
        "status": status_map.get(str(raw.get("status", "")), "UNKNOWN"),
        "signer_subject": str(raw.get("signer_subject") or ""),
        "signer_issuer": str(raw.get("signer_issuer") or ""),
    }


def _win_verify_trust(path: Path) -> int:
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
        ]

    action = _guid_from_uuid(UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"), GUID)
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
    data = WINTRUST_DATA(
        ctypes.sizeof(WINTRUST_DATA),
        None,
        None,
        2,
        0,
        1,
        ctypes.pointer(file_info),
        0,
        None,
        None,
        0x00001000,
        0,
    )
    wintrust = ctypes.windll.wintrust
    wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    return wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _guid_from_uuid(value: UUID, guid_type):
    data4 = (ctypes.c_ubyte * 8).from_buffer_copy(value.bytes[8:])
    return guid_type(value.time_low, value.time_mid, value.time_hi_version, data4)
