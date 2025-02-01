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

#define DbgPrint(fmt, ...) PrintWA_v(_CRT_WIDE(fmt), __VA_ARGS__ )

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

HRESULT PrintError(HRESULT dwError);

void InitPrintf();

#define echo(x) x
#define label(x) echo(x)##__LINE__

#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }
#define LAA_D(se) {{se} }

#define END_PRIVILEGES }};};

