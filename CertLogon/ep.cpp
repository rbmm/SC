#include "stdafx.h"
#include <WinCred.h>

inline HANDLE fixH(HANDLE hFile)
{
	return INVALID_HANDLE_VALUE == hFile ? 0 : hFile;
}

template <typename T>
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
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
		hr = NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, NCRYPT_SILENT_FLAG);

		NCryptFreeObject(hProvider);
	}

	return (hr);
}

HRESULT AddToMyStore(_In_ PCCERT_CONTEXT pCertContext)
{
	HRESULT hr;

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY")))
	{
		HR(hr, CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));

		CertCloseStore(hCertStore, 0);
	}

	return hr;
}

HRESULT NameFromCert(_In_ PCCERT_CONTEXT pCertContext, _Out_ PWSTR* ppwszUserName)
{
	HRESULT hr;

	CERT_CREDENTIAL_INFO cci = { sizeof(cci) };
	ULONG cb = sizeof(cci.rgbHashOfCert);

	HR(hr, CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0,
		pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, cci.rgbHashOfCert, &cb)) &&
		HR(hr, CredMarshalCredentialW(CertCredential, &cci, ppwszUserName));

	return hr;
}

HRESULT NameFromCert(
	_In_ PCCERT_CONTEXT pCertContext,
	_Out_ PWSTR* ppwszUserName,
	_Out_ NCRYPT_KEY_HANDLE* phKey)
{
	HRESULT hr;
	ULONG cb = 0;
	PCRYPT_KEY_PROV_INFO kpi = 0;
	while (HR(hr, CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, kpi, &cb)))
	{
		if (kpi)
		{
			if (S_OK == (hr = NameFromCert(pCertContext, ppwszUserName)))
			{
				if (S_OK != (hr = AddToMyStore(pCertContext)))
				{
					CredFree(*ppwszUserName);
					*ppwszUserName = 0;
				}
				else
				{
					OpenKspKey(phKey, kpi->pwszProvName, kpi->pwszContainerName, kpi->dwKeySpec);
				}

			}
			break;
		}

		kpi = (PCRYPT_KEY_PROV_INFO)alloca(cb);
	}

	return hr;
}

HRESULT PFXImport(
	_In_ DATA_BLOB* pPFX,
	_In_ PCWSTR szPassword,
	_Out_ PWSTR* ppwszUserName,
	_Out_ NCRYPT_KEY_HANDLE* phKey)
{
	HRESULT hr;

	if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(pPFX, szPassword, PKCS12_ALWAYS_CNG_KSP)))
	{
		PCCERT_CONTEXT pCertContext = 0;
		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
		{
			if (S_OK == (hr = NameFromCert(pCertContext, ppwszUserName, phKey)))
			{
				CertFreeCertificateContext(pCertContext);
				break;
			}
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb)
{
	HRESULT hr;

	if (HANDLE hFile = HR(hr, fixH(CreateFileW(lpFileName, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0))))
	{
		FILE_STANDARD_INFORMATION fsi;
		IO_STATUS_BLOCK iosb;

		if (0 <= (hr = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
		{
			if (fsi.EndOfFile.QuadPart > 0x10000)
			{
				hr = STATUS_FILE_TOO_LARGE;
			}
			else
			{
				if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
				{
					if (0 > (hr = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
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
					hr = E_OUTOFMEMORY;
				}
			}
		}

		NtClose(hFile);
	}

	return hr;
}

HRESULT PFXImport(
	_In_ PCWSTR lpFileName,
	_In_ PCWSTR szPassword,
	_Out_ PWSTR* ppwszUserName,
	_Out_ NCRYPT_KEY_HANDLE* phKey)
{
	DATA_BLOB db;
	HRESULT hr = ReadFromFile(lpFileName, &db);

	if (0 <= hr)
	{
		hr = PFXImport(&db, szPassword, ppwszUserName, phKey);
		LocalFree(db.pbData);
	}
	return hr;
}

HRESULT DemoLogon(PWSTR pszPfx, PWSTR pszPassword)
{
	PWSTR pszUserName;
	NCRYPT_KEY_HANDLE hKey = 0;

	HRESULT hr;

	if (S_OK == (hr = PFXImport(pszPfx, pszPassword, &pszUserName, &hKey)))
	{
		HANDLE hToken;

		HR(hr, LogonUserW(pszUserName, 0, 0, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_WINNT50, &hToken));
		
		CredFree(pszUserName);

		if (hKey)
		{
			if (NCryptDeleteKey(hKey, 0))
			{
				NCryptFreeObject(hKey);
			}
		}

		if (S_OK == hr)
		{
			HR(hr, ImpersonateLoggedOnUser(hToken));
			NtClose(hToken);
		}
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

		lpSource = GetModuleHandle(L"ntdll");
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

void WINAPI ep(PEB* )
{
	HRESULT hr = STATUS_INVALID_PARAMETER_MIX;

	if (PWSTR pszPfx = wcschr(GetCommandLineW(), '*'))
	{
		if (PWSTR pszPassword = wcschr(++pszPfx, '*'))
		{
			*pszPassword++ = 0;
			MessageBoxW(0, pszPfx, pszPassword, MB_ICONINFORMATION);
			hr = DemoLogon(pszPfx, pszPassword);
		}
	}

	ExitProcess(ShowErrorBox(0, hr, L"PFX Logon"));
}
