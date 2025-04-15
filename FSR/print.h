#pragma once

struct PrintInfo : TEB_ACTIVE_FRAME, TEB_ACTIVE_FRAME_CONTEXT
{
	HANDLE _G_hFile;
	UINT _G_CodePage;
	BOOLEAN _G_bConsole;

	PrintInfo()
	{
		Context = this;
		TEB_ACTIVE_FRAME_CONTEXT::Flags = 0;
		FrameName = name();
		RtlPushFrame(this);
	}

	~PrintInfo()
	{
		RtlPopFrame(this);
	}

	static PrintInfo* get()
	{
		if (TEB_ACTIVE_FRAME* prf = RtlGetFrame())
		{
			do 
			{
				if (name() == prf->Context->FrameName) return static_cast<PrintInfo*>(prf);
			} while (prf = prf->Previous);
		}

		return 0;
	}

	static PCSTR name()
	{
		return __FUNCDNAME__;
	}
};

void PutChars(PCWSTR pwz, ULONG cch);

inline void PutChars(PCWSTR pwz)
{
	PutChars(pwz, (ULONG)wcslen(pwz));
}

void PrintWA_v(PCWSTR format, ...);

#define DbgPrint(fmt, ...) PrintWA_v(_YW(_CRT_WIDE(fmt)), __VA_ARGS__ )

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

HRESULT PrintError(HRESULT dwError);

void InitPrintf();



