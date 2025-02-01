#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

#define Winlogon() _YA("Winlogon")
#define SourceName() _YA("1234567")
#define szPin() _YW(L"*")
#define FMT_PCR() _YW(L"%ws%c%ws%c%ws%c%ws%c" MS_KEY_STORAGE_PROVIDER)
#define FMT_R_C() _YW(L"\\\\.\\%s\\%s")
#define NTDLL() _YW(L"ntdll")
#define READER() _YW(L"Reader")
#define CONTAINER() _YW(L"Container")
#define CAPTION_1() _YW(L"CerificateLogon")
#define CAPTION_2() _YW(L"PFX Logon")

template <typename T>
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);
	IO_STATUS_BLOCK iosb;

	if (0 <= status)
	{
		HANDLE hFile;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			FILE_STANDARD_INFORMATION fsi;

			if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
			{
				if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
				{
					if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
					{
						LocalFree(pb);
					}
					else
					{
						pdb->pbData = pb;
						pdb->cbData = (ULONG)iosb.Information;
					}
				}
				else
				{
					status = STATUS_NO_MEMORY;
				}
			}

			NtClose(hFile);
		}
	}

	return status;
}

HRESULT OpenKspKey(
	_Out_ NCRYPT_KEY_HANDLE* phKey,
	_In_ PCWSTR pszProviderName,
	_In_ PWSTR pszKeyName,
	_In_ ULONG dwLegacyKeySpec)
{
	NCRYPT_PROV_HANDLE hProvider;

	NTSTATUS hr = NCryptOpenStorageProvider(&hProvider, pszProviderName, 0);

	if (NOERROR == hr)
	{
		hr = NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG);

		NCryptFreeObject(hProvider);
	}

	return (hr);
}

NTSTATUS DoLogon(_Out_ PHANDLE Token,
	_In_ PVOID AuthenticationInformation,
	_In_ ULONG AuthenticationInformationLength)
{
	NTSTATUS status;
	ULONG AuthenticationPackage;
	LSA_STRING PackageName;

	HANDLE LsaHandle;
	if (0 <= (status = LsaConnectUntrusted(&LsaHandle)))
	{
		RtlInitString(&PackageName, _YA(MICROSOFT_KERBEROS_NAME_A));

		if (0 <= (status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthenticationPackage)))
		{
			RtlInitString(&PackageName, Winlogon());
			TOKEN_SOURCE ts = { {}, {0xFEDCBA90, 0x12345678} };
			strcpy(ts.SourceName, SourceName());

			void* ProfileBuffer;
			ULONG ProfileBufferLength;
			LUID LogonId;
			QUOTA_LIMITS ql;
			NTSTATUS subStatus;

			if (0 > (status = LsaLogonUser(LsaHandle, &PackageName, Interactive, AuthenticationPackage,
				AuthenticationInformation, AuthenticationInformationLength, 0, &ts,
				&ProfileBuffer, &ProfileBufferLength, &LogonId, Token, &ql, &subStatus)))
			{
				if (0 > subStatus)
				{
					status = subStatus;
				}
			}
			else
			{
				LsaFreeReturnBuffer(ProfileBuffer);
			}
		}

		LsaDeregisterLogonProcess(LsaHandle);
	}

	return status;
}

typedef struct KERB_SMARTCARD_CSP_INFO
{
	ULONG dwCspInfoLen;				// size of this structure w/ payload
	ULONG MessageType;				// info type, currently CertHashInfo
	// payload starts, marshaled structure of MessageType
	union {
		PVOID ContextInformation;	// Reserved
		ULONG64 SpaceHolderForWow64;
	};
	ULONG flags;					// Reserved
	ULONG KeySpec;					// AT_SIGNATURE xor AT_KEYEXCHANGE
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR Buffer[];
} *PKERB_SMARTCARD_CSP_INFO;

NTSTATUS CerificateLogon(_Out_ PHANDLE Token,
	_In_ PCWSTR pcszReaderName,
	_In_ PCWSTR pwszContainerName,
	_In_ PCWSTR pcszPin = szPin(),
	_In_ PCWSTR pcszCardName = szPin())
{
	int len = 0;
	PWSTR psz = 0;
	PKERB_CERTIFICATE_LOGON pkcl = 0;

	ULONG cb = 0, Offset = (ULONG)wcslen(pcszPin), * pu = 0;

	while (0 < (len = _snwprintf(psz, len, FMT_PCR(),
		pcszPin, 0, pcszCardName, 0, pcszReaderName, 0, pwszContainerName, 0)))
	{
		if (psz)
		{
			ULONG n = 4;
			do
			{
				*pu++ = ++Offset;
				Offset += (ULONG)wcslen(psz + Offset);
			} while (--n);

			return DoLogon(Token, pkcl, cb);
		}

		ULONG dwCspInfoLen = sizeof(KERB_SMARTCARD_CSP_INFO) + ++len * sizeof(WCHAR);
		cb = sizeof(KERB_CERTIFICATE_LOGON) + dwCspInfoLen;
		RtlZeroMemory(pkcl = (PKERB_CERTIFICATE_LOGON)alloca(cb), cb);
		KERB_SMARTCARD_CSP_INFO* p = (KERB_SMARTCARD_CSP_INFO*)(pkcl + 1);
		psz = p->Buffer;

		pkcl->CspDataLength = dwCspInfoLen;
		pkcl->CspData = (PUCHAR)sizeof(KERB_CERTIFICATE_LOGON);
		pkcl->MessageType = KerbCertificateLogon;
		pkcl->Pin.Buffer = (PWSTR)(ULONG_PTR)RtlPointerToOffset(pkcl, psz);
		pkcl->Pin.MaximumLength = pkcl->Pin.Length = (USHORT)Offset * sizeof(WCHAR);
		p->dwCspInfoLen = dwCspInfoLen;
		p->MessageType = 1;
		pu = &p->nCardNameOffset;
	}

	return STATUS_INTERNAL_ERROR;
}

struct CRYPT_PKCS12_PBE_PARAMS_WITH_SALT : CRYPT_PKCS12_PBE_PARAMS
{
	ULONG64 Salt = 0;

	CRYPT_PKCS12_PBE_PARAMS_WITH_SALT()
	{
		iIterations = 1;
		cbSalt = sizeof(Salt);
	}
};

HRESULT WritePfxToKey(_In_ PCWSTR lpFileName,
	_In_ PCWSTR szPassword,
	_In_ PCWSTR pcszReaderName,
	_In_ PCWSTR ContainerName)
{
	HRESULT hr;
	CRYPT_DATA_BLOB PFX;
	if (0 <= (hr = ReadFromFile(lpFileName, &PFX)))
	{
		if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword,
			NCRYPT_ALLOW_EXPORT_FLAG | PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY)))
		{
			PCCERT_CONTEXT pCertContext = 0;
			while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
			{
				CERT_KEY_CONTEXT ckc;
				ULONG cb = sizeof(ckc);
				if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &cb))
				{
					hr = STATUS_INTERNAL_DB_ERROR;

					if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
					{
						PWSTR psz = 0;
						int len = 0;

						while (0 < (len = _snwprintf(psz, len, FMT_R_C(), pcszReaderName, ContainerName)))
						{
							if (psz)
							{
								CRYPT_PKCS12_PBE_PARAMS_WITH_SALT params;
								BCryptBuffer buf[] = {
									{ (1 + len) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_KEY_NAME, psz },
									{ sizeof(params), NCRYPTBUFFER_PKCS_ALG_PARAM, &params },
									{
										sizeof(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES),
											NCRYPTBUFFER_PKCS_ALG_OID,
										const_cast<PSTR>(_YA(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES))
									},
								};

								NCryptBufferDesc ParameterList{ NCRYPTBUFFER_VERSION, _countof(buf), buf };

								PBYTE pb = 0;
								cb = 0;
								while (NOERROR == (hr = NCryptExportKey(ckc.hNCryptKey, 0,
									_YW(NCRYPT_PKCS8_PRIVATE_KEY_BLOB), &ParameterList, pb, cb, &cb, 0)))
								{
									if (pb)
									{
										NCRYPT_PROV_HANDLE hProvider;

										if (NOERROR == (hr = NCryptOpenStorageProvider(&hProvider, _YW(MS_KEY_STORAGE_PROVIDER), 0)))
										{
											NCRYPT_KEY_HANDLE hKey;

											hr = NCryptImportKey(hProvider, 0, _YW(NCRYPT_PKCS8_PRIVATE_KEY_BLOB),
												&ParameterList, &hKey, pb, cb, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG);

											NCryptFreeObject(hProvider);

											if (NOERROR == hr)
											{
												if (NOERROR == (hr = NCryptSetProperty(hKey,
													_YW(NCRYPT_CERTIFICATE_PROPERTY),
													pCertContext->pbCertEncoded,
													pCertContext->cbCertEncoded, 0)))
												{
													hr = NCryptFinalizeKey(hKey, 0);
												}

												NCryptFreeObject(hKey);
											}
										}

										break;
									}

									pb = (PBYTE)alloca(cb);
								}

								break;
							}

							psz = (PWSTR)alloca(++len * sizeof(WCHAR));
						}
					}

					CertFreeCertificateContext(pCertContext);
					break;
				}
			}

			CertCloseStore(hStore, 0);
		}

		LocalFree(PFX.pbData);
	}

	return hr;
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PBYTE pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG |
		CRYPT_DECODE_NOCOPY_FLAG |
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG |
		CRYPT_DECODE_SHARE_OID_STRING_FLAG,
		0, ppv, pcb ? pcb : &cb) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

HRESULT GetPublickKey(_In_ NCRYPT_KEY_HANDLE hKey, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	HRESULT hr;
	while (NOERROR == (hr = NCryptGetProperty(hKey, _YW(NCRYPT_CERTIFICATE_PROPERTY), pb, cb, &cb, 0)))
	{
		if (pb)
		{
			PCERT_INFO pCertInfo;

			if (NOERROR == (hr = Decode(X509_CERT_TO_BE_SIGNED, pb, cb, &pCertInfo)))
			{
				HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
					&pCertInfo->SubjectPublicKeyInfo, 0, 0, phKey));

				LocalFree(pCertInfo);
			}
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT TestKey(_In_ BOOL bDelete, _In_ PCWSTR pcszReaderName, _In_ PCWSTR ContainerName)
{
	HRESULT hr = STATUS_INTERNAL_ERROR;
	PWSTR psz = 0;
	int len = 0;

	while (0 < (len = _snwprintf(psz, len, FMT_R_C(), pcszReaderName, ContainerName)))
	{
		if (psz)
		{
			NCRYPT_KEY_HANDLE hKey;

			if (NOERROR == (hr = OpenKspKey(&hKey, MS_KEY_STORAGE_PROVIDER, psz, 0)))
			{
				UCHAR hash[0x20];
				BCryptGenRandom(0, hash, sizeof(hash), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
				BCRYPT_PKCS1_PADDING_INFO pi = { _YW(BCRYPT_SHA256_ALGORITHM) };
				PBYTE pbSig = 0;
				ULONG cbSig = 0;
				BCRYPT_KEY_HANDLE hBKey;
				while (NOERROR == (hr = NCryptSignHash(hKey, &pi, hash, sizeof(hash), pbSig, cbSig, &cbSig, BCRYPT_PAD_PKCS1)))
				{
					if (pbSig)
					{
						if (NOERROR == (hr = GetPublickKey(hKey, &hBKey)))
						{
							hr = BCryptVerifySignature(hBKey, &pi, hash, sizeof(hash), pbSig, cbSig, BCRYPT_PAD_PKCS1);
							BCryptDestroyKey(hBKey);
						}
						break;
					}

					pbSig = (PBYTE)alloca(cbSig);
				}

				if (bDelete)
				{
					if (NOERROR == NCryptDeleteKey(hKey, 0))
					{
						break;
					}
				}

				NCryptFreeObject(hKey);
			}

			break;
		}

		psz = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return hr;
}

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR lpCaption)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
	__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		lpSource = GetModuleHandle(NTDLL());
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBox(hwnd, lpText, lpCaption, dwError ? MB_ICONERROR : MB_ICONINFORMATION);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

void WINAPI ep()
{
	CPP_FUNCTION;

	HRESULT hr = STATUS_INVALID_PARAMETER_MIX;

	if (PWSTR pszPfx = wcschr(GetCommandLineW(), '*'))
	{
		if (PWSTR pszPassword = wcschr(++pszPfx, '*'))
		{
			*pszPassword++ = 0;
			MessageBoxW(0, pszPfx, pszPassword, MB_ICONINFORMATION);

			PCWSTR ReaderName = READER(), ContainerName = CONTAINER();

			if (NOERROR == (hr = WritePfxToKey(pszPfx, pszPassword, ReaderName, ContainerName)))
			{
				HANDLE hToken;
				if (0 <= (hr = CerificateLogon(&hToken, ReaderName, ContainerName)))
				{
					HR(hr, ImpersonateLoggedOnUser(hToken));
					NtClose(hToken);

					ShowErrorBox(0, hr, CAPTION_1());

					NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &(hToken = 0), sizeof(hToken));
				}

				TestKey(TRUE, ReaderName, ContainerName);
			}
		}
	}

	ExitProcess(ShowErrorBox(0, hr, CAPTION_2()));
}