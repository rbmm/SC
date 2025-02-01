#include "stdafx.h"

#include "print.h"

NTSTATUS
WINAPI
NtSetProcessValidCallTargets(
							 _In_ HANDLE hProcess,
							 _In_ PVOID VirtualAddress,
							 _In_ SIZE_T RegionSize,
							 _In_ ULONG NumberOfOffsets,
							 _Inout_updates_(NumberOfOffsets) PCFG_CALL_TARGET_INFO OffsetInformation
							 )
{
	MEMORY_RANGE_ENTRY va = { VirtualAddress, RegionSize };
	CFG_CALL_TARGET_LIST_INFORMATION mi = { NumberOfOffsets, 0, &NumberOfOffsets, OffsetInformation };
	NTSTATUS status = NtSetInformationVirtualMemory(hProcess, VmCfgCallTargetInformation, 1, &va, &mi, sizeof(mi));
	if (0 <= status && NumberOfOffsets)
	{
		do 
		{
			OffsetInformation++->Flags |= CFG_CALL_TARGET_PROCESSED;
		} while (--NumberOfOffsets);
	}
	return status;
}

NTSTATUS
GetProcessMitigationPolicy(
						   _In_ HANDLE hProcess,
						   _In_ PROCESS_MITIGATION_POLICY MitigationPolicy,
						   _Out_writes_bytes_(ULONG) PVOID lpBuffer
						   )
{
	struct PROCESS_MITIGATION {
		PROCESS_MITIGATION_POLICY Policy;
		ULONG Flags;
	};

	PROCESS_MITIGATION m = { MitigationPolicy };
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &m, sizeof(m), 0);
	if (0 <= status)
	{
		*(PULONG)lpBuffer = m.Flags;
		return STATUS_SUCCESS;
	}

	return status;
}

BOOLEAN IsExportSuppressionEnabled(HANDLE hProcess)
{
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg;

	return 0 <= GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg) &&
		cfg.EnableControlFlowGuard && cfg.EnableExportSuppression;
}

NTSTATUS SetExportValid(HANDLE hProcess, LPCVOID pv)
{
	MEMORY_BASIC_INFORMATION mbi;

	NTSTATUS status = NtQueryVirtualMemory(hProcess, (void*)pv, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

	if (0 <= status)
	{
		if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE)
		{
			return STATUS_INVALID_ADDRESS;
		}

		CFG_CALL_TARGET_INFO OffsetInformation = {
			(ULONG_PTR)pv - (ULONG_PTR)mbi.BaseAddress,
			CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID | CFG_CALL_TARGET_VALID
		};

		return NtSetProcessValidCallTargets(hProcess, mbi.BaseAddress, mbi.RegionSize, 1, &OffsetInformation) &&
			(OffsetInformation.Flags & CFG_CALL_TARGET_PROCESSED) ? STATUS_SUCCESS : STATUS_STRICT_CFG_VIOLATION;
	}

	return status;
}

NTSTATUS SetExportValid(HANDLE hProcess, LPCVOID pv1, LPCVOID pv2)
{
	if (pv1 > pv2)
	{
		LPCVOID pv = pv2;
		pv2 = pv1, pv1 = pv;
	}

	MEMORY_BASIC_INFORMATION mbi;

	NTSTATUS status;

	if (0 <= (status = NtQueryVirtualMemory(hProcess, (void*)pv2, MemoryBasicInformation, &mbi, sizeof(mbi), 0)))
	{
		if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE)
		{
			return STATUS_INVALID_ADDRESS;
		}

		CFG_CALL_TARGET_INFO OffsetInformation[] = {
			{ ((ULONG_PTR)pv1 - (ULONG_PTR)mbi.AllocationBase) & ~15, CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID | CFG_CALL_TARGET_VALID },
			{ ((ULONG_PTR)pv2 - (ULONG_PTR)mbi.AllocationBase) & ~15, CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID | CFG_CALL_TARGET_VALID },
		};

		mbi.RegionSize += (ULONG_PTR)mbi.BaseAddress - (ULONG_PTR)mbi.AllocationBase;

		if (mbi.AllocationBase <= pv1)
		{
			return NtSetProcessValidCallTargets(hProcess, mbi.AllocationBase, 
				mbi.RegionSize, _countof(OffsetInformation), OffsetInformation) &&
				(OffsetInformation[0].Flags & CFG_CALL_TARGET_PROCESSED) &&
				(OffsetInformation[1].Flags & CFG_CALL_TARGET_PROCESSED) ? STATUS_SUCCESS : STATUS_STRICT_CFG_VIOLATION;
		}

		if (!NtSetProcessValidCallTargets(hProcess, mbi.AllocationBase, mbi.RegionSize, 1, OffsetInformation + 1) ||
			!(OffsetInformation[1].Flags & CFG_CALL_TARGET_PROCESSED))
		{
			return STATUS_STRICT_CFG_VIOLATION;
		}

		return SetExportValid(hProcess, pv1);
	}

	return status;
}