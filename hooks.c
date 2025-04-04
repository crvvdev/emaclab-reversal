void __fastcall EmacInfinityHookHandler(void *stackCurrent, void *a2, void *OriginalAddress, void *NewAddress)
{
  _QWORD *i; // rax
  void **SystemCallFunction; // rcx

  if ( !byte_FFFFF801BCFACDA0 && OriginalAddress && NewAddress )
  {
    for ( i = (char *)stackCurrent + 16; i < a2; ++i )
    {
      if ( *i >= 0xEAADDEEAADDEADDEui64 && *i < 0xAEADDEEADAEAADDEui64 )
      {
        SystemCallFunction = (void **)(i + 9);
        if ( i + 9 >= a2 )
          return;
        if ( *SystemCallFunction == OriginalAddress )
        {
          *SystemCallFunction = NewAddress;
          return;
        }
      }
    }
  }
}

// write access to const memory has been detected, the output may be wrong!
char EmacInfinityHookSetup()
{
  int NtKiSystemCall64Offset; // edx
  void **v1; // rbx
  unsigned __int64 i; // rax
  int v3; // r9d
  int v4; // ecx
  __int64 v5; // rsi
  __int64 v6; // rdi
  unsigned __int64 *j; // rbx
  void *retaddr; // [rsp+28h] [rbp+0h] BYREF
  unsigned __int64 v10; // [rsp+30h] [rbp+8h] BYREF
  __int64 v11; // [rsp+38h] [rbp+10h] BYREF

  dword_FFFFF801BD006AFC = 1;
  NtKiSystemCall64Offset = FindNtKiSystemCall64Offset();
  dword_FFFFF801BD006AF8 = NtKiSystemCall64Offset;
  v1 = &retaddr;
  LOBYTE(i) = -(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38);
  v11 = 0i64;
  v10 = 0i64;
  if ( !byte_FFFFF801BCFACDA0 && NtKiSystemCall64Offset != -1 )
  {
    v3 = *(_DWORD *)KeGetCurrentThread();
    for ( i = g_EmacInfinityHookList; i != g_EmacInfinityHookListEnd; i += 24i64 )
    {
      v4 = *(_DWORD *)(i + 4);
      if ( v4 != -1 && v4 == v3 )
      {
        v5 = *(_QWORD *)(i + 16);
        v6 = *(_QWORD *)(i + 8);
        if ( v5 )
        {
          LOBYTE(i) = ((__int64 (__fastcall *)(__int64 *, unsigned __int64 *))(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))(
                        &v11,
                        &v10);
          if ( (unsigned __int64)&retaddr < v10 )
          {
            while ( 1 )
            {
              i = (unsigned __int64)(v1 + 1);
              if ( *(_WORD *)v1 == 0xF33 && (*(_DWORD *)i == 0x501802 || *(_DWORD *)i == 0x601802) )
                break;
              ++v1;
              if ( i >= v10 )
                return i;
            }
            for ( j = (unsigned __int64 *)(v1 + 2); (unsigned __int64)j < v10; ++j )
            {
              i = *j;
              if ( *j >= 0xEAADDEEAADDEADDEui64 && i < 0xAEADDEEADAEAADDEui64 )
              {
                i = (unsigned __int64)(j + 9);
                if ( (unsigned __int64)(j + 9) >= v10 )
                  return i;
                if ( *(_QWORD *)i == v5 && v6 )
                {
                  *(_QWORD *)i = v6;
                  return i;
                }
              }
            }
          }
        }
        return i;
      }
    }
  }
  return i;
}

char __fastcall EmacInitializeInfinityHook(__int64 a1, __int64 a2)
{
  __int16 v4; // ax

  _InterlockedIncrement(&g_EmacReferenceCount);
  LOBYTE(v4) = MEMORY[0]();                     // HalpCollectPmcCounters
  if ( a1 && a2 && !byte_FFFFF801BCFACDA0 )
  {
    v4 = *(_WORD *)(a2 - 10);
    if ( v4 == 0x135 )
    {
      LOBYTE(v4) = sub_FFFFF801BCF4A3B0();
    }
    else if ( v4 == 0xF33 )
    {
      LOBYTE(v4) = EmacInfinityHookSetup();
    }
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return v4;
}


NTSTATUS __fastcall EmacNtAllocateVirtualMemoryHandler(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect)
{
  __int64 (__fastcall *v10)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _DWORD); // rax
  NTSTATUS status; // r12d MAPDST
  __int64 (*IoGetCurrentProcessFn)(void); // rbx
  __int64 PsGetCurrentProcessIdFn; // rdi
  PEPROCESS CurrentProcess; // rbx MAPDST
  unsigned __int64 v15; // r8
  __m128 v16; // xmm0
  __m128 v17; // xmm1
  __m128 v18; // xmm1
  __m128 v19; // xmm0
  char Irql; // di
  __int64 v21; // rdx
  unsigned __int64 v22; // r8
  __m128 si128; // xmm0
  __m128 v24; // xmm1
  __m128 v25; // xmm1
  __m128 v26; // xmm0
  PUNICODE_STRING v28; // [rsp+30h] [rbp-D0h] BYREF
  int (__fastcall *SeLocateProcessImageNameFn)(PEPROCESS, PUNICODE_STRING *); // [rsp+48h] [rbp-B8h]
  void (__fastcall *ExFreePoolWithTagFn)(PUNICODE_STRING, _QWORD); // [rsp+50h] [rbp-B0h]
  wchar_t SubStr[8]; // [rsp+60h] [rbp-A0h] BYREF
  __m128 v34; // [rsp+70h] [rbp-90h]
  wchar_t v35[8]; // [rsp+80h] [rbp-80h] BYREF
  __m128 v36; // [rsp+90h] [rbp-70h] BYREF
  wchar_t v37[8]; // [rsp+A0h] [rbp-60h] BYREF
  __m128 v38; // [rsp+B0h] [rbp-50h] BYREF
  wchar_t v39[8]; // [rsp+C0h] [rbp-40h] BYREF
  __m128 v40; // [rsp+D0h] [rbp-30h] BYREF
  __int64 (__fastcall *PsGetProcessIdFn)(PEPROCESS); // [rsp+E0h] [rbp-20h]
  __int64 (__fastcall *ExAcquireSpinLockExclusiveFn)(void *); // [rsp+E8h] [rbp-18h]
  void (__fastcall *ExReleaseSpinLockExclusiveFn)(void *, __int64); // [rsp+F0h] [rbp-10h]
  unsigned __int64 ObfDereferenceObjectFn; // [rsp+F8h] [rbp-8h]
  __m128 v45; // [rsp+100h] [rbp+0h]
  __m128i v46; // [rsp+110h] [rbp+10h] BYREF
  __m128i v47; // [rsp+120h] [rbp+20h] BYREF
  __m128 v48; // [rsp+130h] [rbp+30h]
  __m128 v49; // [rsp+140h] [rbp+40h]
  __m128 v50; // [rsp+150h] [rbp+50h]
  __m128 v51; // [rsp+160h] [rbp+60h]
  __m128 v52; // [rsp+170h] [rbp+70h]
  UCHAR Dest[632]; // [rsp+180h] [rbp+80h] BYREF

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFD3920 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFD3920 = v10) != 0i64) )
  {
    PsGetProcessIdFn = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ObfDereferenceObjectFn = ((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38);
    ExAcquireSpinLockExclusiveFn = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExReleaseSpinLockExclusiveFn = (void (__fastcall *)(void *, __int64))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExFreePoolWithTagFn = (void (__fastcall *)(PUNICODE_STRING, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    SeLocateProcessImageNameFn = (int (__fastcall *)(PEPROCESS, PUNICODE_STRING *))(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    memset(Dest, 0, sizeof(Dest));
    KeGetCurrentIrql();
    PsGetCurrentProcessIdFn = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
    v28 = 0i64;
    CurrentProcess = (PEPROCESS)IoGetCurrentProcessFn();
    status = qword_FFFFF801BCFD3920(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if ( g_GameProcessId && EmacIsExecutableMemoryProtection(Protect) )
    {
      if ( ProcessHandle != (HANDLE)-1i64 || PsGetCurrentProcessIdFn != g_GameProcessId )
        CurrentProcess = EmacReferenceProcessObjectByHandle(ProcessHandle);
      if ( CurrentProcess && PsGetProcessIdFn(CurrentProcess) == g_GameProcessId )
      {
        if ( status < 0 )
        {
          if ( status == 0xC0000022 )
          {
            *(_QWORD *)Dest = *BaseAddress;
            *(_QWORD *)&Dest[8] = *RegionSize;
            *(_DWORD *)&Dest[16] = PsGetCurrentProcessIdFn;
            *(_DWORD *)&Dest[20] = Protect;
            *(_DWORD *)&Dest[24] = 0x204D5641;
            if ( SeLocateProcessImageNameFn(CurrentProcess, &v28) >= 0 )
            {
              if ( (v28->Length & 0xFFFEu) >= 0x256 )
                v22 = 299i64;
              else
                v22 = (unsigned __int64)v28->Length >> 1;
              wcsncpy((wchar_t *)&Dest[28], v28->Buffer, v22);
              ExFreePoolWithTagFn(v28, 0i64);
            }
            if ( *(_WORD *)&Dest[28] )
            {
              *(_QWORD *)v37 = 0xFC7EDC8FA1722C1Dui64;
              v50.m128_u64[0] = 0x9DBBD747DFFF6BC7ui64;
              *(_QWORD *)&v37[4] = 0x3E18CF6E9FF47B07i64;
              si128 = (__m128)_mm_load_si128((const __m128i *)v37);
              v38.m128_u64[0] = 0x9D95D735DF9A6BAFui64;
              v38.m128_u64[1] = 0x826FBBDB781A1D0Dui64;
              v24 = (__m128)_mm_load_si128((const __m128i *)&v38);
              v50.m128_u64[1] = 0x826FBBBE78621D68ui64;
              v49.m128_u64[0] = 0xFC12DCB9A14A2C65ui64;
              v49.m128_u64[1] = 0x3E7BCF009F817B66i64;
              v38 = _mm_xor_ps(v24, v50);       // Decrypted UTF-16: her.exe
              *(__m128 *)v37 = _mm_xor_ps(si128, v49);
              if ( !wcsstr((const wchar_t *)&Dest[28], v37) )// x86launcher.exe
              {
                *(_QWORD *)&v39[4] = 0x3E18CF6E9FF47B07i64;
                v40.m128_u64[0] = 0x9D95D735DF9A6BAFui64;
                v40.m128_u64[1] = 0x826FBBDB781A1D0Dui64;
                v25 = (__m128)_mm_load_si128((const __m128i *)&v40);
                *(_QWORD *)v39 = 0xFC7EDC8DA17C2C1Dui64;
                v26 = (__m128)_mm_load_si128((const __m128i *)v39);
                v52.m128_u64[0] = 0x9DBBD747DFFF6BC7ui64;
                v52.m128_u64[1] = 0x826FBBBE78621D68ui64;
                v51.m128_u64[0] = 0xFC12DCB9A14A2C65ui64;
                v51.m128_u64[1] = 0x3E7BCF009F817B66i64;
                v40 = _mm_xor_ps(v25, v52);     // Decrypted UTF-8: 
                *(__m128 *)v39 = _mm_xor_ps(v26, v51);// Decrypted UTF-16: 
                if ( !wcsstr((const wchar_t *)&Dest[28], v39) )// x64launcher.exe
                  EmacReportNtAllocateVirtualMemory(
                    PsGetCurrentProcessIdFn,
                    (__int64)*BaseAddress,
                    *RegionSize,
                    AllocationType,
                    Protect,
                    (wchar_t *)&Dest[28]);
              }
            }
          }
        }
        else if ( PsGetCurrentProcessIdFn != g_GameProcessId && PsGetCurrentProcessIdFn != g_SteamProcessId )
        {
          *(_QWORD *)Dest = *BaseAddress;
          *(_QWORD *)&Dest[8] = *RegionSize;
          *(_DWORD *)&Dest[16] = PsGetCurrentProcessIdFn;
          *(_DWORD *)&Dest[20] = Protect;
          *(_DWORD *)&Dest[24] = ' MVA';
          if ( SeLocateProcessImageNameFn(CurrentProcess, &v28) >= 0 )
          {
            if ( (v28->Length & 0xFFFEu) >= 0x256 )
              v15 = 299i64;
            else
              v15 = (unsigned __int64)v28->Length >> 1;
            wcsncpy((wchar_t *)&Dest[28], v28->Buffer, v15);
            ExFreePoolWithTagFn(v28, 0i64);
          }
          if ( *(_WORD *)&Dest[28] )
          {
            *(_QWORD *)SubStr = 0xFC7EDC8FA1722C1Dui64;
            v46.m128i_i64[0] = 0x9DBBD747DFFF6BC7ui64;
            *(_QWORD *)&SubStr[4] = 0x3E18CF6E9FF47B07i64;
            v16 = (__m128)_mm_load_si128((const __m128i *)SubStr);
            v46.m128i_i64[1] = 0x826FBBBE78621D68ui64;
            v17 = (__m128)_mm_load_si128(&v46);
            v34.m128_u64[0] = 0x9D95D735DF9A6BAFui64;
            v34.m128_u64[1] = 0x826FBBDB781A1D0Dui64;
            v45.m128_u64[0] = 0xFC12DCB9A14A2C65ui64;
            v45.m128_u64[1] = 0x3E7BCF009F817B66i64;
            v34 = _mm_xor_ps(v17, v34);
            *(__m128 *)SubStr = _mm_xor_ps(v16, v45);
            if ( !wcsstr((const wchar_t *)&Dest[28], SubStr) )// L"x86launcher.exe"
            {
              v36.m128_u64[0] = 0x9D95D735DF9A6BAFui64;
              v36.m128_u64[1] = 0x826FBBDB781A1D0Dui64;
              v18 = (__m128)_mm_load_si128((const __m128i *)&v36);
              *(_QWORD *)v35 = 0xFC7EDC8DA17C2C1Dui64;
              v48.m128_u64[0] = 0x9DBBD747DFFF6BC7ui64;
              *(_QWORD *)&v35[4] = 0x3E18CF6E9FF47B07i64;
              v48.m128_u64[1] = 0x826FBBBE78621D68ui64;
              v47.m128i_i64[0] = 0xFC12DCB9A14A2C65ui64;
              v47.m128i_i64[1] = 0x3E7BCF009F817B66i64;
              v19 = _mm_xor_ps((__m128)_mm_load_si128(&v47), *(__m128 *)v35);
              v36 = _mm_xor_ps(v18, v48);
              *(__m128 *)v35 = v19;
              if ( !wcsstr((const wchar_t *)&Dest[28], v35) )// L"x64launcher.exe"
                EmacReportNtAllocateVirtualMemory(
                  PsGetCurrentProcessIdFn,
                  (__int64)*BaseAddress,
                  *RegionSize,
                  AllocationType,
                  Protect,
                  (wchar_t *)&Dest[28]);
            }
          }
          Irql = ExAcquireSpinLockExclusiveFn(&unk_FFFFF801BCFAC468);
          if ( qword_FFFFF801BCFAC458 == qword_FFFFF801BCFAC460 )
            stl_vector_alloc_2(&qword_FFFFF801BCFAC450, (_BYTE *)qword_FFFFF801BCFAC458, Dest);
          else
            sub_FFFFF801BCF43C20((__int64)&qword_FFFFF801BCFAC450, Dest);
          LOBYTE(v21) = Irql;
          ExReleaseSpinLockExclusiveFn(&unk_FFFFF801BCFAC468, v21);
        }
      }
    }
  }
  else
  {
    status = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return status;
}

__int64 __fastcall EmacNtCreateThreadExHandler(
        __int64 a1,
        unsigned int a2,
        __int64 a3,
        void *handle,
        unsigned __int64 baseAddress,
        __int64 a6,
        int a7,
        __int64 a8,
        __int64 a9,
        __int64 a10,
        __int64 a11)
{
  __int64 (__fastcall *v12)(__int64, _QWORD, __int64, void *, unsigned __int64, __int64, int, __int64, __int64, __int64, __int64); // r10
  __int64 v13; // rax
  __int64 result; // rax
  char scanResultType; // si
  void (__fastcall *KeStackAttachProcessFn)(PEPROCESS, __int64 *); // r13
  __int64 (__fastcall *PsGetProcessIdFn)(PEPROCESS); // r12
  __int64 (*IoGetCurrentProcessFn)(void); // r15
  PEPROCESS v19; // rax
  PEPROCESS v20; // rbx
  unsigned __int64 v21; // rax
  __int64 v22; // rdx
  __int64 v23; // rax
  int ProcessId; // ebx
  __int64 Process; // rax
  __int64 v26; // [rsp+60h] [rbp-79h] BYREF
  int (__fastcall *ZwQueryVirtualMemoryFn)(__int64, unsigned __int64, _QWORD, _MEMORY_BASIC_INFORMATION *, unsigned __int64, __int64 *); // [rsp+68h] [rbp-71h]
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+70h] [rbp-69h]
  void (__fastcall *ObfDereferenceObjectFn)(PEPROCESS); // [rsp+78h] [rbp-61h]
  _MEMORY_BASIC_INFORMATION v30; // [rsp+80h] [rbp-59h] BYREF
  __int64 v31; // [rsp+B0h] [rbp-29h] BYREF
  __int128 v32; // [rsp+B8h] [rbp-21h]
  __int128 v33; // [rsp+C8h] [rbp-11h]
  __int64 v34; // [rsp+D8h] [rbp-1h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  v12 = (__int64 (__fastcall *)(__int64, _QWORD, __int64, void *, unsigned __int64, __int64, int, __int64, __int64, __int64, __int64))qword_FFFFF801BCFE2360;
  if ( qword_FFFFF801BCFE2360
    || (sub_FFFFF801BCF4A358(),
        qword_FFFFF801BCFE2360 = v13,
        (v12 = (__int64 (__fastcall *)(__int64, _QWORD, __int64, void *, unsigned __int64, __int64, int, __int64, __int64, __int64, __int64))v13) != 0i64) )
  {
    v34 = 0i64;
    v31 = 0i64;
    v26 = 0i64;
    v32 = 0i64;
    scanResultType = 0;
    ObfDereferenceObjectFn = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v33 = 0i64;
    memset(&v30, 0, sizeof(v30));
    KeStackAttachProcessFn = (void (__fastcall *)(PEPROCESS, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessIdFn = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ZwQueryVirtualMemoryFn = (int (__fastcall *)(__int64, unsigned __int64, _QWORD, _MEMORY_BASIC_INFORMATION *, unsigned __int64, __int64 *))(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId && handle != (void *)-1i64 )
    {
      v19 = EmacReferenceProcessObjectByHandle(handle);
      v20 = v19;
      if ( v19 )
      {
        if ( PsGetProcessIdFn(v19) == g_GameProcessId )
        {
          KeStackAttachProcessFn(v20, &v31);
          if ( ZwQueryVirtualMemoryFn(-1i64, baseAddress, 0i64, &v30, sizeof(_MEMORY_BASIC_INFORMATION), &v26) >= 0 )
          {
            if ( v30.Type == 0x1000000 )
            {
              if ( (v30.State & 0x1000) != 0 )
              {
                v21 = v30.Protect - 16;
                if ( (unsigned int)v21 <= 48 && (v22 = 0x1000000010001i64, _bittest64(&v22, v21)) || v30.Protect == 0x80 )
                {
                  if ( baseAddress > (unsigned __int64)MmHighestUserAddress )
                  {
                    scanResultType = 7;
                  }
                  else if ( baseAddress >= g_NtdllBase
                         && baseAddress <= g_NtdllSize + g_NtdllBase
                         && (baseAddress == Ntdll_DbgBreakPoint
                          || baseAddress == Ntdll_DbgUiRemoteBreakin
                          || baseAddress == Ntdll_DbgUserBreakPoint) )
                  {
                    scanResultType = 4;
                  }
                }
                else
                {
                  scanResultType = 3;
                }
              }
              else
              {
                scanResultType = 2;
              }
            }
            else
            {
              scanResultType = 1;
            }
          }
          KeUnstackDetachProcessFn(&v31);
        }
        ObfDereferenceObjectFn(v20);
        if ( scanResultType )
        {
          v23 = IoGetCurrentProcessFn();
          ProcessId = PsGetProcessIdFn((PEPROCESS)v23);
          Process = IoGetCurrentProcessFn();
          EmacReportNtCreateThreadEx(Process, ProcessId, baseAddress, scanResultType);
          result = 3221225506i64;
          goto LABEL_30;
        }
      }
      v12 = (__int64 (__fastcall *)(__int64, _QWORD, __int64, void *, unsigned __int64, __int64, int, __int64, __int64, __int64, __int64))qword_FFFFF801BCFE2360;
    }
    result = v12(a1, a2, a3, handle, baseAddress, a6, a7, a8, a9, a10, a11);
    goto LABEL_30;
  }
  result = 0xC0000138i64;
LABEL_30:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

NTSTATUS __fastcall EmacNtCreateThreadHandler(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PCLIENT_ID ClientId,
        PCONTEXT ThreadContext,
        PVOID InitialTeb,
        BOOLEAN CreateSuspended)
{
  __int64 (__fastcall *v9)(PHANDLE, _QWORD, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN); // rbx
  __int64 v10; // rax
  NTSTATUS result; // eax
  char reportFlag; // si
  unsigned __int64 Rcx; // rdi
  __int64 (__fastcall *PsGetProcessIdFn)(PEPROCESS); // r13
  __int64 (*IoGetCurrentProcessFn)(void); // r15
  PEPROCESS Process; // rax MAPDST
  struct _KPROCESS *v18; // rax
  unsigned __int64 v19; // rax
  __int64 v20; // rdx
  __int64 v21; // rax
  int CurrentProcessId; // ebx
  __int64 CurrentProcess; // rax
  void (__fastcall *KeStackAttachProcessFn)(PEPROCESS, __int64 *); // [rsp+40h] [rbp-C0h]
  __int64 v25; // [rsp+48h] [rbp-B8h] BYREF
  int (__fastcall *ZwQueryVirtualMemoryFn)(__int64, unsigned __int64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *); // [rsp+50h] [rbp-B0h]
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+58h] [rbp-A8h]
  void (__fastcall *ObfDereferenceObjectFn)(PEPROCESS); // [rsp+60h] [rbp-A0h]
  MEMORY_BASIC_INFORMATION mbi; // [rsp+68h] [rbp-98h] BYREF
  __int64 ApcState; // [rsp+98h] [rbp-68h] BYREF
  __int128 v31; // [rsp+A0h] [rbp-60h]
  __int128 v32; // [rsp+B0h] [rbp-50h]
  __int64 v33; // [rsp+C0h] [rbp-40h]
  CONTEXT ctx; // [rsp+D0h] [rbp-30h] BYREF

  _InterlockedIncrement(&g_EmacReferenceCount);
  v9 = (__int64 (__fastcall *)(PHANDLE, _QWORD, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN))qword_FFFFF801BCFDAE40;
  if ( qword_FFFFF801BCFDAE40
    || (sub_FFFFF801BCF4A358(),
        qword_FFFFF801BCFDAE40 = v10,
        (v9 = (__int64 (__fastcall *)(PHANDLE, _QWORD, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN))v10) != 0i64) )
  {
    memset(&ctx, 0, sizeof(ctx));
    ApcState = 0i64;
    v25 = 0i64;
    reportFlag = 0;
    Rcx = 0i64;
    v33 = 0i64;
    v31 = 0i64;
    ObfDereferenceObjectFn = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v32 = 0i64;
    memset(&mbi, 0, sizeof(mbi));
    KeStackAttachProcessFn = (void (__fastcall *)(PEPROCESS, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessIdFn = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ZwQueryVirtualMemoryFn = (int (__fastcall *)(__int64, unsigned __int64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *))(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId && ThreadContext && ProcessHandle != (HANDLE)-1i64 )
    {
      Process = EmacReferenceProcessObjectByHandle(ProcessHandle);
      if ( Process )
      {
        if ( PsGetProcessIdFn(Process) == g_GameProcessId )
        {
          v18 = (struct _KPROCESS *)IoGetCurrentProcessFn();
          if ( (int)EmacCopyProcessMemory(v18, ThreadContext, &ctx, sizeof(_CONTEXT), 0i64) >= 0 )
          {
            Rcx = ctx.Rcx;                      // Check thread StartAddress
            KeStackAttachProcessFn(Process, &ApcState);
            if ( ZwQueryVirtualMemoryFn(-1i64, Rcx, 0i64, &mbi, 0x30i64, &v25) >= 0 )
            {
              if ( mbi.Type == 0x1000000 )
              {
                if ( (mbi.State & 0x1000) != 0 )
                {
                  v19 = mbi.Protect - 16;
                  if ( (unsigned int)v19 <= 0x30 && (v20 = 0x1000000010001i64, _bittest64(&v20, v19))
                    || mbi.Protect == 128 )
                  {
                    if ( Rcx > (unsigned __int64)MmHighestUserAddress )
                    {
                      reportFlag = 7;
                    }
                    else if ( Rcx >= g_NtdllBase
                           && Rcx <= g_NtdllSize + g_NtdllBase
                           && (Rcx == Ntdll_DbgBreakPoint
                            || Rcx == Ntdll_DbgUiRemoteBreakin
                            || Rcx == Ntdll_DbgUserBreakPoint) )
                    {
                      reportFlag = 4;
                    }
                  }
                  else
                  {
                    reportFlag = 3;
                  }
                }
                else
                {
                  reportFlag = 2;
                }
              }
              else
              {
                reportFlag = 1;
              }
            }
            KeUnstackDetachProcessFn(&ApcState);
          }
        }
        ObfDereferenceObjectFn(Process);
        if ( reportFlag )
        {
          v21 = IoGetCurrentProcessFn();
          CurrentProcessId = PsGetProcessIdFn((PEPROCESS)v21);
          CurrentProcess = IoGetCurrentProcessFn();
          EmacReportNtCreateThread(CurrentProcess, CurrentProcessId, Rcx, reportFlag);
          result = 0xC0000022;
          goto LABEL_32;
        }
      }
      v9 = (__int64 (__fastcall *)(PHANDLE, _QWORD, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN))qword_FFFFF801BCFDAE40;
    }
    result = v9(
               ThreadHandle,
               DesiredAccess,
               ObjectAttributes,
               ProcessHandle,
               ClientId,
               ThreadContext,
               InitialTeb,
               CreateSuspended);
    goto LABEL_32;
  }
  result = 0xC0000138;
LABEL_32:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

__int64 __fastcall EmacNtFreeVirtualMemoryHandler(void *a1, void *a2, __int64 a3, unsigned int a4)
{
  __int64 (__fastcall *v8)(_QWORD, _QWORD, _QWORD, _QWORD); // rax
  int v9; // ebp
  __int64 (__fastcall *v10)(PEPROCESS); // r12
  __int64 (*v11)(void); // rbx
  __int64 v12; // r13
  struct _KPROCESS *v13; // rsi
  PEPROCESS v14; // rbx
  char v15; // al
  unsigned __int64 v16; // rdx
  unsigned __int64 *v17; // rcx
  char v18; // di
  unsigned __int64 v20; // [rsp+30h] [rbp-48h] BYREF
  __int64 (__fastcall *v21)(void *); // [rsp+38h] [rbp-40h]
  void (__fastcall *v22)(void *, unsigned __int64); // [rsp+40h] [rbp-38h]
  void (__fastcall *v23)(PEPROCESS); // [rsp+48h] [rbp-30h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFE2368 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFE2368 = v8) != 0i64) )
  {
    v10 = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v11 = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v23 = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v21 = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v22 = (void (__fastcall *)(void *, unsigned __int64))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    KeGetCurrentIrql();
    v20 = 0i64;
    v12 = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
    v13 = (struct _KPROCESS *)v11();
    v9 = qword_FFFFF801BCFE2368(a1, a2, a3, a4);
    if ( v9 >= 0 && g_GameProcessId )
    {
      v14 = a1 == (void *)-1i64 && v12 == g_GameProcessId ? v13 : EmacReferenceProcessObjectByHandle(a1);
      if ( v14 )
      {
        if ( v10(v14) == g_GameProcessId && (int)EmacCopyProcessMemory(v13, a2, &v20, 8ui64, 0i64) >= 0 )
        {
          v15 = v21(&unk_FFFFF801BCFAC468);
          v17 = (unsigned __int64 *)qword_FFFFF801BCFAC450;
          v18 = v15;
          if ( qword_FFFFF801BCFAC450 != (void *)qword_FFFFF801BCFAC458 )
          {
            while ( 1 )
            {
              if ( *((_DWORD *)v17 + 6) == ' MVA' )
              {
                v16 = *v17;
                if ( v20 >= *v17 )
                {
                  v16 += v17[1];
                  if ( v20 <= v16 )
                    break;
                }
              }
              v17 += 79;
              if ( v17 == (unsigned __int64 *)qword_FFFFF801BCFAC458 )
                goto LABEL_20;
            }
            memmove_2(v17, v17 + 79, qword_FFFFF801BCFAC458 - (_QWORD)(v17 + 79));
            qword_FFFFF801BCFAC458 -= 632i64;
          }
LABEL_20:
          LOBYTE(v16) = v18;
          v22(&unk_FFFFF801BCFAC468, v16);
        }
        if ( v14 != v13 )
          v23(v14);
      }
    }
  }
  else
  {
    v9 = -1073741512;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return (unsigned int)v9;
}

__int64 __fastcall EmacNtMapViewOfSectionHandler(
        __int64 a1,
        void *a2,
        void *a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        void *a7,
        int a8,
        int a9,
        int a10)
{
  __int64 (__fastcall *v13)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _DWORD, _DWORD); // rax
  int v14; // r15d
  __int64 (*v15)(void); // rbx
  __int64 v16; // rsi
  struct _KPROCESS *v17; // rdi
  PEPROCESS v18; // rbx
  unsigned __int64 v19; // r8
  char v20; // si
  __int64 v21; // rdx
  PUNICODE_STRING v23; // [rsp+50h] [rbp-B0h] BYREF
  __int64 (__fastcall *v24)(PEPROCESS); // [rsp+58h] [rbp-A8h]
  int (__fastcall *v25)(struct _KPROCESS *, PUNICODE_STRING *); // [rsp+60h] [rbp-A0h]
  void (__fastcall *v26)(PUNICODE_STRING, _QWORD); // [rsp+68h] [rbp-98h]
  __int64 (__fastcall *v27)(void *); // [rsp+70h] [rbp-90h]
  void (__fastcall *v28)(void *, __int64); // [rsp+78h] [rbp-88h]
  void (__fastcall *v29)(PEPROCESS); // [rsp+80h] [rbp-80h]
  UCHAR Dest[632]; // [rsp+90h] [rbp-70h] BYREF

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFE2370 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFE2370 = v13) != 0i64) )
  {
    v24 = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v15 = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v29 = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v27 = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v28 = (void (__fastcall *)(void *, __int64))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v26 = (void (__fastcall *)(PUNICODE_STRING, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v25 = (int (__fastcall *)(struct _KPROCESS *, PUNICODE_STRING *))(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    memset(Dest, 0, sizeof(Dest));
    KeGetCurrentIrql();
    v16 = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
    v17 = (struct _KPROCESS *)v15();
    v23 = 0i64;
    v14 = qword_FFFFF801BCFE2370(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    if ( v14 >= 0 && g_GameProcessId && EmacIsExecutableMemoryProtection(a10) )
    {
      v18 = a2 == (void *)-1i64 && v16 == g_GameProcessId ? v17 : EmacReferenceProcessObjectByHandle(a2);
      if ( v18 )
      {
        if ( v24(v18) == g_GameProcessId )
        {
          *(_DWORD *)&Dest[16] = v16;
          *(_DWORD *)&Dest[20] = a10;
          *(_DWORD *)&Dest[24] = ' SVM';
          if ( (int)EmacCopyProcessMemory(v17, a7, &Dest[8], 8ui64, 0i64) >= 0
            && (int)EmacCopyProcessMemory(v17, a3, Dest, 8ui64, 0i64) >= 0 )
          {
            if ( v16 != g_GameProcessId && v25(v17, &v23) >= 0 )
            {
              if ( (v23->Length & 0xFFFEu) >= 0x256 )
                v19 = 299i64;
              else
                v19 = (unsigned __int64)v23->Length >> 1;
              wcsncpy((wchar_t *)&Dest[28], v23->Buffer, v19);
              v26(v23, 0i64);
            }
            v20 = v27(&unk_FFFFF801BCFAC468);
            if ( qword_FFFFF801BCFAC458 == qword_FFFFF801BCFAC460 )
              stl_vector_alloc_2(&qword_FFFFF801BCFAC450, (_BYTE *)qword_FFFFF801BCFAC458, Dest);
            else
              sub_FFFFF801BCF43C20((__int64)&qword_FFFFF801BCFAC450, Dest);
            LOBYTE(v21) = v20;
            v28(&unk_FFFFF801BCFAC468, v21);
          }
        }
        if ( v18 != v17 )
          v29(v18);
      }
    }
  }
  else
  {
    v14 = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return (unsigned int)v14;
}

__int64 __fastcall EmacNtProtectVirtualMemoryHandler(
        HANDLE ProcessHandle,
        void *a2,
        void *a3,
        unsigned int a4,
        void *a5)
{
  __int64 (__fastcall *v9)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD); // rax
  int status; // esi
  __int64 (*IoGetCurrentProcessFn)(void); // rdi MAPDST
  int v12; // r13d
  struct _KPROCESS *CurrentProcess; // rdi MAPDST
  PEPROCESS Process; // rbx
  unsigned __int64 v16; // r8
  char v17; // r14
  __int64 v18; // rdx
  int v20; // [rsp+30h] [rbp-D0h] BYREF
  unsigned __int16 *v21; // [rsp+38h] [rbp-C8h] BYREF
  __int64 (*PsGetCurrentProcessIdFn)(void); // [rsp+48h] [rbp-B8h]
  __int64 (__fastcall *PsGetProcessIdFn)(PEPROCESS); // [rsp+50h] [rbp-B0h]
  int (__fastcall *SeLocateProcessImageNameFn)(struct _KPROCESS *, unsigned __int16 **); // [rsp+58h] [rbp-A8h]
  void (__fastcall *ExFreePoolWithTagFn)(unsigned __int16 *, _QWORD); // [rsp+60h] [rbp-A0h]
  __int64 (__fastcall *ExAcquireSpinLockExclusiveFn)(void *); // [rsp+68h] [rbp-98h]
  void (__fastcall *ExReleaseSpinLockExclusiveFn)(void *, __int64); // [rsp+70h] [rbp-90h]
  void (__fastcall *ObfDereferenceObjectFn)(PEPROCESS); // [rsp+78h] [rbp-88h]
  UCHAR Dest[632]; // [rsp+80h] [rbp-80h] BYREF

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFE2378 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFE2378 = v9) != 0i64) )
  {
    PsGetCurrentProcessIdFn = (__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessIdFn = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ObfDereferenceObjectFn = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExAcquireSpinLockExclusiveFn = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExReleaseSpinLockExclusiveFn = (void (__fastcall *)(void *, __int64))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExFreePoolWithTagFn = (void (__fastcall *)(unsigned __int16 *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    SeLocateProcessImageNameFn = (int (__fastcall *)(struct _KPROCESS *, unsigned __int16 **))(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)SeLocateProcessImageName ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    memset(Dest, 0, sizeof(Dest));
    v12 = PsGetCurrentProcessIdFn();
    v20 = 0;
    CurrentProcess = (struct _KPROCESS *)IoGetCurrentProcessFn();
    v21 = 0i64;
    KeGetCurrentIrql();
    status = qword_FFFFF801BCFE2378(ProcessHandle, a2, a3, a4, a5);
    if ( g_GameProcessId )
    {
      if ( EmacIsExecutableMemoryProtection(a4) )
      {
        CurrentProcess = (struct _KPROCESS *)IoGetCurrentProcessFn();
        if ( (int)EmacCopyProcessMemory(CurrentProcess, a5, &v20, 4ui64, 0i64) >= 0
          && !EmacIsExecutableMemoryProtection(v20) )
        {
          Process = ProcessHandle == (HANDLE)-1i64 && PsGetCurrentProcessIdFn() == g_GameProcessId
                  ? CurrentProcess
                  : EmacReferenceProcessObjectByHandle(ProcessHandle);
          if ( Process )
          {
            if ( status >= 0 && PsGetProcessIdFn(Process) == g_GameProcessId )
            {
              *(_DWORD *)&Dest[20] = a4;
              *(_DWORD *)&Dest[16] = v12;
              *(_DWORD *)&Dest[24] = ' MVP';
              if ( (int)EmacCopyProcessMemory(CurrentProcess, a2, Dest, 8ui64, 0i64) >= 0
                && (int)EmacCopyProcessMemory(CurrentProcess, a3, &Dest[8], 8ui64, 0i64) >= 0 )
              {
                if ( SeLocateProcessImageNameFn(CurrentProcess, &v21) >= 0 )
                {
                  if ( (*v21 & 0xFFFEu) >= 0x256 )
                    v16 = 299i64;
                  else
                    v16 = (unsigned __int64)*v21 >> 1;
                  wcsncpy((wchar_t *)&Dest[28], *((const wchar_t **)v21 + 1), v16);
                  ExFreePoolWithTagFn(v21, 0i64);
                }
                v17 = ExAcquireSpinLockExclusiveFn(&unk_FFFFF801BCFAC468);
                if ( qword_FFFFF801BCFAC458 == qword_FFFFF801BCFAC460 )
                  stl_vector_alloc_2(&qword_FFFFF801BCFAC450, (_BYTE *)qword_FFFFF801BCFAC458, Dest);
                else
                  sub_FFFFF801BCF43C20((__int64)&qword_FFFFF801BCFAC450, Dest);
                LOBYTE(v18) = v17;
                ExReleaseSpinLockExclusiveFn(&unk_FFFFF801BCFAC468, v18);
              }
            }
            if ( Process != CurrentProcess )
              ObfDereferenceObjectFn(Process);
          }
        }
      }
    }
  }
  else
  {
    status = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return (unsigned int)status;
}

__int64 __fastcall EmacNtQueueApcThreadExHandler(
        __int64 a1,
        __int64 a2,
        unsigned __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6)
{
  __int64 (__fastcall *v8)(__int64, __int64, unsigned __int64, __int64, __int64, __int64); // r10
  __int64 v9; // rax
  __int64 result; // rax
  char v11; // si
  int (__fastcall *v12)(__int64, unsigned __int64, _QWORD, __int128 *, __int64, __int64 *); // r12
  void (__fastcall *v13)(__int64, __int64 *); // r13
  __int64 (__fastcall *v14)(__int64); // rbx
  __int64 v15; // rax
  __int64 v16; // r14
  __int64 v17; // rax
  __int64 v18; // rbx
  unsigned __int64 v19; // rax
  __int64 v20; // rdx
  __int64 (*v21)(void); // r14
  __int64 v22; // rax
  int v23; // ebx
  __int64 v24; // rax
  __int64 (__fastcall *v25)(__int64); // [rsp+30h] [rbp-79h]
  __int64 v26; // [rsp+38h] [rbp-71h] BYREF
  void (__fastcall *v27)(__int64 *); // [rsp+40h] [rbp-69h]
  void (__fastcall *v28)(__int64); // [rsp+48h] [rbp-61h]
  __int64 (*v29)(void); // [rsp+50h] [rbp-59h]
  __int128 v30[2]; // [rsp+58h] [rbp-51h] BYREF
  __int128 v31; // [rsp+78h] [rbp-31h]
  __int64 v32; // [rsp+88h] [rbp-21h] BYREF
  __int128 v33; // [rsp+90h] [rbp-19h]
  __int128 v34; // [rsp+A0h] [rbp-9h]
  __int64 v35; // [rsp+B0h] [rbp+7h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  v8 = (__int64 (__fastcall *)(__int64, __int64, unsigned __int64, __int64, __int64, __int64))qword_FFFFF801BCFF0DB0;
  if ( qword_FFFFF801BCFF0DB0
    || (sub_FFFFF801BCF4A358(),
        qword_FFFFF801BCFF0DB0 = v9,
        (v8 = (__int64 (__fastcall *)(__int64, __int64, unsigned __int64, __int64, __int64, __int64))v9) != 0i64) )
  {
    v35 = 0i64;
    v32 = 0i64;
    v26 = 0i64;
    v11 = 0;
    v33 = 0i64;
    v28 = (void (__fastcall *)(__int64))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v34 = 0i64;
    memset(v30, 0, sizeof(v30));
    v25 = (__int64 (__fastcall *)(__int64))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v31 = 0i64;
    v12 = (int (__fastcall *)(__int64, unsigned __int64, _QWORD, __int128 *, __int64, __int64 *))(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v13 = (void (__fastcall *)(__int64, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v27 = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v14 = (__int64 (__fastcall *)(__int64))(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v29 = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      v15 = EmacReferenceThreadObjectByHandle(a1);
      v16 = v15;
      if ( v15 )
      {
        v17 = v14(v15);
        v18 = v17;
        if ( v17 && v25(v17) == g_GameProcessId )
        {
          v13(v18, &v32);
          if ( v12(-1i64, a3, 0i64, v30, 48i64, &v26) >= 0 )
          {
            if ( DWORD2(v31) == 0x1000000 )
            {
              if ( (v31 & 0x1000) != 0 )
              {
                v19 = (unsigned int)(DWORD1(v31) - 16);
                if ( (unsigned int)v19 <= 0x30 && (v20 = 0x1000000010001i64, _bittest64(&v20, v19))
                  || DWORD1(v31) == 128 )
                {
                  if ( a3 > (unsigned __int64)MmHighestUserAddress )
                  {
                    v11 = 7;
                  }
                  else if ( a3 < g_NtdllBase || a3 > g_NtdllSize + g_NtdllBase )
                  {
                    if ( a3 < g_Kernel32Base || a3 > g_Kernel32Size + g_Kernel32Base )
                    {
                      if ( a3 >= g_KernelBaseWow64Base
                        && a3 <= g_KernelBaseWow64Size + g_KernelBaseWow64Base
                        && (a3 == KERNELBASE_LoadLibraryA_Wow64
                         || a3 == KERNELBASE_LoadLibraryW_Wow64
                         || a3 == KERNELBASE_LoadLibraryExA_Wow64
                         || a3 == KERNELBASE_LoadLibraryExW_Wow64) )
                      {
                        v11 = 6;
                      }
                    }
                    else if ( a3 == Kernel32_LoadLibraryA
                           || a3 == Kernel32_LoadLibraryW
                           || a3 == Kernel32_LoadLibraryExA
                           || a3 == Kernel32_LoadLibraryExW )
                    {
                      v11 = 5;
                    }
                  }
                  else if ( a3 == Ntdll_LdrLoadDll
                         || a3 == Ntdll_DbgBreakPoint
                         || a3 == Ntdll_DbgUiRemoteBreakin
                         || a3 == Ntdll_DbgUserBreakPoint )
                  {
                    v11 = 4;
                  }
                }
                else
                {
                  v11 = 3;
                }
              }
              else
              {
                v11 = 2;
              }
            }
            else
            {
              v11 = 1;
            }
          }
          v27(&v32);
        }
        v28(v16);
        if ( v11 )
        {
          v21 = v29;
          v22 = v29();
          v23 = v25(v22);
          v24 = v21();
          EmacReportNtQueueApcThreadEx(v24, v23, a3, v11);
          result = 0xC0000022i64;
          goto LABEL_45;
        }
      }
      v8 = (__int64 (__fastcall *)(__int64, __int64, unsigned __int64, __int64, __int64, __int64))qword_FFFFF801BCFF0DB0;
    }
    result = v8(a1, a2, a3, a4, a5, a6);
    goto LABEL_45;
  }
  result = 0xC0000138i64;
LABEL_45:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

__int64 __fastcall EmacNtQueueApcThreadHandler(
        __int64 ThreadHandle,
        unsigned __int64 baseAddress,
        __int64 a3,
        __int64 a4,
        __int64 a5)
{
  __int64 (__fastcall *v7)(__int64, unsigned __int64, __int64, __int64, __int64); // r10
  __int64 v8; // rax
  __int64 result; // rax
  char reportFlag; // si
  int (__fastcall *ZwQueryVirtualMemoryFn)(__int64, unsigned __int64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *); // r12
  void (__fastcall *KeStackAttachProcessFn)(__int64, __int64 *); // r13
  __int64 (__fastcall *IoThreadToProcessFn)(__int64); // rbx
  __int64 Thread; // rax MAPDST
  __int64 v16; // rax MAPDST
  unsigned __int64 v18; // rax
  __int64 v19; // rdx
  __int64 CurrentProcess; // rax MAPDST
  int CurrentProcessId; // ebx
  __int64 (__fastcall *PsGetProcessIdFn)(__int64); // [rsp+30h] [rbp-71h]
  __int64 v25; // [rsp+38h] [rbp-69h] BYREF
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+40h] [rbp-61h]
  void (__fastcall *ObfDereferenceObjectFn)(__int64); // [rsp+48h] [rbp-59h]
  __int64 (*IoGetCurrentProcessFn)(void); // [rsp+50h] [rbp-51h] MAPDST
  MEMORY_BASIC_INFORMATION v29; // [rsp+58h] [rbp-49h] BYREF
  __int64 ApcState; // [rsp+88h] [rbp-19h] BYREF
  __int128 v31; // [rsp+90h] [rbp-11h]
  __int128 v32; // [rsp+A0h] [rbp-1h]
  __int64 v33; // [rsp+B0h] [rbp+Fh]

  _InterlockedIncrement(&g_EmacReferenceCount);
  v7 = (__int64 (__fastcall *)(__int64, unsigned __int64, __int64, __int64, __int64))qword_FFFFF801BCFE9890;
  if ( qword_FFFFF801BCFE9890
    || (sub_FFFFF801BCF4A358(),
        qword_FFFFF801BCFE9890 = v8,
        (v7 = (__int64 (__fastcall *)(__int64, unsigned __int64, __int64, __int64, __int64))v8) != 0i64) )
  {
    v33 = 0i64;
    ApcState = 0i64;
    v25 = 0i64;
    reportFlag = 0;
    v31 = 0i64;
    ObfDereferenceObjectFn = (void (__fastcall *)(__int64))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v32 = 0i64;
    memset(&v29, 0, sizeof(v29));
    PsGetProcessIdFn = (__int64 (__fastcall *)(__int64))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ZwQueryVirtualMemoryFn = (int (__fastcall *)(__int64, unsigned __int64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *))(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    KeStackAttachProcessFn = (void (__fastcall *)(__int64, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoThreadToProcessFn = (__int64 (__fastcall *)(__int64))(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      Thread = EmacReferenceThreadObjectByHandle(ThreadHandle);
      if ( Thread )
      {
        v16 = IoThreadToProcessFn(Thread);
        if ( v16 && PsGetProcessIdFn(v16) == g_GameProcessId )
        {
          KeStackAttachProcessFn(v16, &ApcState);
          if ( ZwQueryVirtualMemoryFn(-1i64, baseAddress, 0i64, &v29, 0x30i64, &v25) >= 0 )
          {
            if ( v29.Type == 0x1000000 )        // MEM_IMAGE
            {
              if ( (v29.State & 0x1000) != 0 )  // MEM_COMMIT
              {
                v18 = v29.Protect - 0x10;
                if ( (unsigned int)v18 <= 0x30 && (v19 = 0x1000000010001i64, _bittest64(&v19, v18))
                  || v29.Protect == 0x80 )      // Only care about executable memory
                {
                  if ( baseAddress > (unsigned __int64)MmHighestUserAddress )
                  {
                    reportFlag = 7;
                  }
                  else if ( baseAddress < g_NtdllBase || baseAddress > g_NtdllSize + g_NtdllBase )
                  {
                    if ( baseAddress < g_Kernel32Base || baseAddress > g_Kernel32Size + g_Kernel32Base )
                    {
                      if ( baseAddress >= g_KernelBaseWow64Base
                        && baseAddress <= g_KernelBaseWow64Size + g_KernelBaseWow64Base
                        && (baseAddress == KERNELBASE_LoadLibraryA_Wow64
                         || baseAddress == KERNELBASE_LoadLibraryW_Wow64
                         || baseAddress == KERNELBASE_LoadLibraryExA_Wow64
                         || baseAddress == KERNELBASE_LoadLibraryExW_Wow64) )
                      {
                        reportFlag = 6;
                      }
                    }
                    else if ( baseAddress == Kernel32_LoadLibraryA
                           || baseAddress == Kernel32_LoadLibraryW
                           || baseAddress == Kernel32_LoadLibraryExA
                           || baseAddress == Kernel32_LoadLibraryExW )
                    {
                      reportFlag = 5;
                    }
                  }
                  else if ( baseAddress == Ntdll_LdrLoadDll
                         || baseAddress == Ntdll_DbgBreakPoint
                         || baseAddress == Ntdll_DbgUiRemoteBreakin
                         || baseAddress == Ntdll_DbgUserBreakPoint )
                  {
                    reportFlag = 4;
                  }
                }
                else
                {
                  reportFlag = 3;
                }
              }
              else
              {
                reportFlag = 2;
              }
            }
            else
            {
              reportFlag = 1;
            }
          }
          KeUnstackDetachProcessFn(&ApcState);
        }
        ObfDereferenceObjectFn(Thread);
        if ( reportFlag )
        {
          CurrentProcess = IoGetCurrentProcessFn();
          CurrentProcessId = PsGetProcessIdFn(CurrentProcess);
          CurrentProcess = IoGetCurrentProcessFn();
          EmacReportCreateThread(CurrentProcess, CurrentProcessId, baseAddress, reportFlag);
          result = 0xC0000022i64;
          goto LABEL_45;
        }
      }
      v7 = (__int64 (__fastcall *)(__int64, unsigned __int64, __int64, __int64, __int64))qword_FFFFF801BCFE9890;
    }
    result = v7(ThreadHandle, baseAddress, a3, a4, a5);
    goto LABEL_45;
  }
  result = 0xC0000138i64;
LABEL_45:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

NTSTATUS __fastcall EmacNtReadVirtualMemoryHandler(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesReaded)
{
  __int64 (__fastcall *v9)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T); // r10
  __int64 v10; // rax
  NTSTATUS status; // edi
  NTSTATUS v12; // eax
  bool v13; // r9
  __int64 (__fastcall *v14)(PEPROCESS); // r12
  __int64 (*v15)(void); // r14
  unsigned __int8 (__fastcall *v16)(__int64); // r13
  __int64 v17; // rbp
  __int64 v18; // r14
  PEPROCESS v19; // rax
  PEPROCESS v20; // rsi
  void (__fastcall *v22)(PEPROCESS); // [rsp+30h] [rbp-38h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  v9 = (__int64 (__fastcall *)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))qword_FFFFF801BCFF0DC0;
  if ( qword_FFFFF801BCFF0DC0
    || (sub_FFFFF801BCF4A358(),
        qword_FFFFF801BCFF0DC0 = v10,
        (v9 = (__int64 (__fastcall *)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))v10) != 0i64) )
  {
    v12 = v9(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
    status = v12;
    v13 = !v12 || v12 == 0xC0000022 || v12 == 0xC0000005 || v12 == 0x113 || v12 == 0x8000000D;
    v14 = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v15 = (__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v16 = (unsigned __int8 (__fastcall *)(__int64))((PsIsProtectedProcess ^ qword_FFFFF801BCFACC40) & -(__int64)((PsIsProtectedProcess ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v22 = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      if ( ProcessHandle != (HANDLE)-1i64 && v13 )
      {
        v17 = ((__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
        v18 = v15();
        if ( v18 != g_GameProcessId )
        {
          v19 = EmacReferenceProcessObjectByHandle(ProcessHandle);
          v20 = v19;
          if ( v19 )
          {
            if ( v19 != (PEPROCESS)v17
              && v14(v19) == g_GameProcessId
              && !v16(v17)
              && ((unsigned __int64)BaseAddress >= g_Cs2Base && (unsigned __int64)BaseAddress <= g_Cs2Base + g_Cs2Size
               || (unsigned __int64)BaseAddress >= g_Engine2Base
               && (unsigned __int64)BaseAddress <= g_Engine2Size + g_Engine2Base) )
            {
              if ( (unsigned __int64)BaseAddress < g_Cs2Base || (unsigned __int64)BaseAddress > g_Cs2Base + g_Cs2Size )
              {
                if ( (unsigned __int64)BaseAddress >= g_Engine2Base
                  && (unsigned __int64)BaseAddress <= g_Engine2Base + g_Engine2Size )
                {
                  EmacReportNtReadVirtualMemory(
                    v17,
                    v18,
                    (__int64)BaseAddress,
                    NumberOfBytesToRead,
                    (_DWORD)BaseAddress - g_Engine2Base,
                    1);
                }
              }
              else
              {
                EmacReportNtReadVirtualMemory(
                  v17,
                  v18,
                  (__int64)BaseAddress,
                  NumberOfBytesToRead,
                  (_DWORD)BaseAddress - g_Cs2Base,
                  0);
              }
            }
            v22(v20);
          }
        }
      }
    }
  }
  else
  {
    status = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return status;
}

__int64 __fastcall EmacNtSetContextThreadHandler(__int64 ThreadHandle, _QWORD *Context)
{
  __int64 (__fastcall *v4)(_QWORD, _QWORD); // rax
  __int64 result; // rax
  char v6; // si
  void (__fastcall *v7)(_QWORD); // r13
  __int64 (__fastcall *v8)(__int64); // r12
  __int64 v9; // rax
  __int64 v10; // r14
  __int64 v11; // rax
  __int64 v12; // r12
  struct _KPROCESS *v13; // rax
  unsigned __int64 v14; // rax
  __int64 v15; // rdx
  __int64 (*v16)(void); // [rsp+38h] [rbp-5A0h]
  void (__fastcall *v17)(__int64, __int64 *); // [rsp+40h] [rbp-598h]
  __int64 v18; // [rsp+48h] [rbp-590h] BYREF
  int (__fastcall *v19)(__int64, ULONG64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *); // [rsp+50h] [rbp-588h]
  void (__fastcall *v20)(__int64 *); // [rsp+58h] [rbp-580h]
  __int64 v21; // [rsp+60h] [rbp-578h]
  void (__fastcall *v22)(_QWORD); // [rsp+68h] [rbp-570h]
  MEMORY_BASIC_INFORMATION v23; // [rsp+70h] [rbp-568h] BYREF
  __int64 v24; // [rsp+A0h] [rbp-538h] BYREF
  __int128 v25; // [rsp+A8h] [rbp-530h]
  __int128 v26; // [rsp+B8h] [rbp-520h]
  __int64 v27; // [rsp+C8h] [rbp-510h]
  CONTEXT ctx; // [rsp+D0h] [rbp-508h] BYREF
  __int64 (__fastcall *v29)(__int64); // [rsp+5F8h] [rbp+20h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFF0DC8 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFF0DC8 = v4) != 0i64) )
  {
    v18 = 0i64;
    memset(&ctx, 0, sizeof(ctx));
    v24 = 0i64;
    v25 = 0i64;
    v26 = 0i64;
    v27 = 0i64;
    memset(&v23, 0, sizeof(v23));
    v6 = 0;
    v7 = (void (__fastcall *)(_QWORD))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v22 = v7;
    v29 = (__int64 (__fastcall *)(__int64))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v19 = (int (__fastcall *)(__int64, ULONG64, _QWORD, MEMORY_BASIC_INFORMATION *, __int64, __int64 *))(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ZwQueryVirtualMemory ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v17 = (void (__fastcall *)(__int64, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v20 = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v8 = (__int64 (__fastcall *)(__int64))(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoThreadToProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v16 = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      v9 = EmacReferenceThreadObjectByHandle(ThreadHandle);
      v10 = v9;
      v21 = v9;
      if ( v9 )
      {
        v11 = v8(v9);
        v12 = v11;
        if ( v11 )
        {
          if ( v29(v11) == g_GameProcessId )
          {
            v13 = (struct _KPROCESS *)v16();
            if ( (int)EmacCopyProcessMemory(v13, Context, &ctx, 1232ui64, 0i64) >= 0 )
            {
              if ( ctx.Rip && ctx.Rip < (unsigned __int64)MmHighestUserAddress )
              {
                v17(v12, &v24);
                if ( v19(-1i64, ctx.Rip, 0i64, &v23, 48i64, &v18) >= 0 )
                {
                  if ( v23.Type == 0x1000000 )
                  {
                    if ( (v23.State & 0x1000) != 0 )
                    {
                      v14 = v23.Protect - 16;
                      if ( (unsigned int)v14 > 0x30 || (v15 = 0x1000000010001i64, !_bittest64(&v15, v14)) )
                      {
                        v6 = 0;
                        if ( v23.Protect != 0x80 )
                          v6 = 3;
                      }
                    }
                    else
                    {
                      v6 = 2;
                    }
                  }
                  else
                  {
                    v6 = 1;
                  }
                }
                v20(&v24);
              }
              if ( (int)sub_FFFFF801BCF1C0A0((unsigned __int64)Context, 0x4D0ui64, 4) >= 0 )
              {
                Context[14] = 0i64;
                Context[12] = 0i64;
                Context[11] = 0i64;
                Context[10] = 0i64;
                Context[9] = 0i64;
              }
            }
          }
        }
        v7(v10);
      }
    }
    if ( v6 )
      result = 3221225506i64;
    else
      result = qword_FFFFF801BCFF0DC8(ThreadHandle, Context);
  }
  else
  {
    result = 3221225784i64;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

__int64 __fastcall EmacNtUnmapViewOfSectionHandler(void *a1, __int64 a2)
{
  __int64 (__fastcall *v4)(_QWORD, _QWORD); // rax
  int v5; // ebp
  __int64 (__fastcall *v6)(PEPROCESS); // r15
  __int64 (*v7)(void); // rbx
  __int64 (__fastcall *v8)(void *); // r13
  __int64 v9; // r12
  PEPROCESS v10; // r14
  PEPROCESS v11; // rbx
  char v12; // al
  __int64 v13; // rdx
  _DWORD *v14; // rcx
  char v15; // di
  void (__fastcall *v17)(void *, __int64); // [rsp+70h] [rbp+18h]
  void (__fastcall *v18)(PEPROCESS); // [rsp+78h] [rbp+20h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFF0DD0 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFF0DD0 = v4) != 0i64) )
  {
    v6 = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v7 = (__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v18 = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v8 = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v17 = (void (__fastcall *)(void *, __int64))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    v9 = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
    v10 = (PEPROCESS)v7();
    KeGetCurrentIrql();
    v5 = qword_FFFFF801BCFF0DD0(a1, a2);
    if ( v5 >= 0 && a2 && g_GameProcessId )
    {
      v11 = a1 == (void *)-1i64 && v9 == g_GameProcessId ? v10 : EmacReferenceProcessObjectByHandle(a1);
      if ( v11 )
      {
        if ( v6(v11) == g_GameProcessId )
        {
          v12 = v8(&unk_FFFFF801BCFAC468);
          v14 = qword_FFFFF801BCFAC450;
          v15 = v12;
          if ( qword_FFFFF801BCFAC450 != (void *)qword_FFFFF801BCFAC458 )
          {
            while ( v14[6] != ' SVM' || *(_QWORD *)v14 != a2 )
            {
              v14 += 0x9E;
              if ( v14 == (_DWORD *)qword_FFFFF801BCFAC458 )
                goto LABEL_19;
            }
            memmove_2(v14, v14 + 0x9E, qword_FFFFF801BCFAC458 - (_QWORD)(v14 + 0x9E));
            qword_FFFFF801BCFAC458 -= 0x278i64;
          }
LABEL_19:
          LOBYTE(v13) = v15;
          v17(&unk_FFFFF801BCFAC468, v13);
        }
        if ( v11 != v10 )
          v18(v11);
      }
    }
  }
  else
  {
    v5 = -1073741512;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return (unsigned int)v5;
}

void __fastcall EmacNtUserFindWindowExHandler(
        HWND hwndParent,
        HWND hwndChild,
        PUNICODE_STRING pstrClassName,
        PUNICODE_STRING pstrWindowName,
        DWORD dwType)
{
  __int64 (__fastcall *v9)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD); // rax
  __int64 (*IoGetCurrentProcess)(void); // r12
  __int64 (*PsGetCurrentProcessIdFn)(void); // r13
  unsigned __int8 (*ExGetPreviousModeFn)(void); // rdi
  char *Buffer; // rcx
  unsigned int Length; // eax
  __int64 CaseInSensitive; // r8
  HANDLE currentProcessId; // rdi
  struct _KPROCESS *currentProcess; // rax
  wchar_t a2[8]; // [rsp+40h] [rbp-C8h] BYREF
  __m128 v19; // [rsp+50h] [rbp-B8h] BYREF
  __m128 v20; // [rsp+60h] [rbp-A8h] BYREF
  unsigned int (__fastcall *RtlCompareUnicodeStringFn)(PUNICODE_STRING, UNICODE_STRING *, __int64); // [rsp+70h] [rbp-98h]
  UNICODE_STRING WindowName; // [rsp+78h] [rbp-90h] BYREF
  __m128 v23; // [rsp+90h] [rbp-78h]
  __m128 v24; // [rsp+A0h] [rbp-68h]
  __m128 v25; // [rsp+B0h] [rbp-58h]
  HANDLE v26; // [rsp+C0h] [rbp-48h]
  struct _KPROCESS *v27; // [rsp+C8h] [rbp-40h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFF80F0 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFF80F0 = v9) != 0i64) )
  {
    RtlCompareUnicodeStringFn = (unsigned int (__fastcall *)(PUNICODE_STRING, UNICODE_STRING *, __int64))(((unsigned __int64)RtlCompareUnicodeString ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)RtlCompareUnicodeString ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcess = (__int64 (*)(void))(((unsigned __int64)::IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)::IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetCurrentProcessIdFn = (__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExGetPreviousModeFn = (unsigned __int8 (*)(void))(((unsigned __int64)ExGetPreviousMode ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExGetPreviousMode ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    WindowName = 0i64;
    wmemcpy(a2, L"㠢䂳멱娄燐➭䢠쓃縚鏃擙峫垑쑑쏳㒗䛚曬쁔㭫䓃ꩬ", 24);
    v23.m128_u64[0] = 0xBA1F40C6384DE0DFui64;
    v23.m128_u64[1] = 0x488D27DFF98B5A70i64;
    v24.m128_u64[0] = 0x93AA7E68C4B7F691ui64;
    v24.m128_u64[1] = 0xC46357B15C8E64B2ui64;
    v25.m128_u64[0] = 0x66EC46DA3497C3F3i64;
    v25.m128_u64[1] = 0xAA6C44C33B6BC054ui64;
    *(__m128 *)a2 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)a2), v23);// Decrypted Raw (unprintable): 43 00 6f 00 75 00 6e 00 66 2c 4a a1 b9 dc 12 fc
    v19 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v19), v24);// Decrypted Raw (unprintable): 53 00 74 00 72 00 69 00 b1 64 8e 5c b1 57 63 c4
    v20 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v20), v25);// Decrypted Raw (unprintable): 00 00 00 00 00 00 00 00 7f c1 6b 3b c3 44 6c aa
    RtlInitUnicodeStringInline(&WindowName, a2);// L"Counter-"
    if ( g_GameProcessId )
    {
      if ( ExGetPreviousModeFn() == 1 )
      {
        if ( pstrWindowName )
        {
          if ( (int)EmacProbeForRead((char *)pstrWindowName, 0x10ui64, 4u) >= 0 )
          {
            Buffer = (char *)pstrWindowName->Buffer;
            if ( Buffer )
            {
              Length = pstrWindowName->Length;
              if ( Length > 2
                && (unsigned __int16)Length <= pstrWindowName->MaximumLength
                && (int)EmacProbeForRead(Buffer, pstrWindowName->Length, 4u) >= 0 )
              {
                LOBYTE(CaseInSensitive) = 1;
                if ( !RtlCompareUnicodeStringFn(pstrWindowName, &WindowName, CaseInSensitive) )
                {
                  currentProcessId = (HANDLE)PsGetCurrentProcessIdFn();
                  v26 = currentProcessId;
                  currentProcess = (struct _KPROCESS *)IoGetCurrentProcess();
                  v27 = currentProcess;
                  if ( currentProcessId != (HANDLE)g_GameProcessId
                    && currentProcessId != (HANDLE)g_SteamProcessId
                    && currentProcessId != g_EmacProcesses[0].ProcessId )
                  {
                    EmacReportNtUserFindWindowEx(currentProcess, (ULONG)currentProcessId);
                  }
                }
              }
            }
          }
        }
      }
    }
    qword_FFFFF801BCFF80F0(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
    _InterlockedDecrement(&g_EmacReferenceCount);
  }
  else
  {
    _InterlockedDecrement(&g_EmacReferenceCount);
  }
}

NTSTATUS __fastcall EmacNtUserSendInputHandler(UINT Count, INPUT *Inputs, INT Size)
{
  __int64 v5; // rsi
  __int64 (__fastcall *v6)(UINT, INPUT *, INT); // rax
  NTSTATUS result; // eax
  bool v8; // r12
  void (__fastcall *PsGetCurrentThreadIdFn)(); // rbx
  __int64 (__fastcall *PsGetCurrentProcessIdFn)(); // rdi
  __int64 CurrentProcess; // r13
  __int64 i; // rbx
  INPUT *CurrentInput; // rdi
  int CurrentProcessId; // [rsp+28h] [rbp-50h]

  v5 = Count;
  _InterlockedIncrement(&g_EmacReferenceCount);
  if ( qword_FFFFF801BCFFF490 || (sub_FFFFF801BCF4A358(), (qword_FFFFF801BCFFF490 = v6) != 0i64) )
  {
    v8 = 0;
    PsGetCurrentThreadIdFn = (void (__fastcall *)())(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetCurrentProcessIdFn = (__int64 (__fastcall *)())(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      if ( Size == sizeof(INPUT) )
      {
        CurrentProcess = ((__int64 (__fastcall *)(unsigned __int64))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40);
        CurrentProcessId = PsGetCurrentProcessIdFn();
        PsGetCurrentThreadIdFn();
        if ( (int)EmacProbeForRead((char *)Inputs, sizeof(INPUT) * v5, 0) >= 0 )
        {
          for ( i = 0i64; (unsigned int)i < (unsigned int)v5; i = (unsigned int)(i + 1) )
          {
            CurrentInput = &Inputs[i];
            if ( !CurrentInput->type
              && byte_FFFFF801BCF55AD0
              && byte_FFFFF801BCF55AD2
              && (CurrentInput->mi.dwFlags & 1) != 0 )// MOUSEEVENTF_MOVE
            {
              if ( !v8 )
                v8 = EmacReportNtSendUserInput(CurrentProcess, CurrentProcessId, 0) != 0;
              *(_OWORD *)&CurrentInput->type = 0i64;// Zero-out so no input is ever processed.
              *(_OWORD *)(&CurrentInput->hi + 1) = 0i64;
              CurrentInput->mi.dwExtraInfo = 0i64;
            }
          }
        }
      }
    }
    result = qword_FFFFF801BCFFF490(v5, Inputs, Size);
  }
  else
  {
    result = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}

// write access to const memory has been detected, the output may be wrong!
__int64 __fastcall EmacNtWriteVirtualMemoryHandler(void *a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 (__fastcall *v9)(void *, __int64, __int64, __int64, __int64); // rax
  int v10; // esi
  void (*PsGetCurrentThreadIdFn)(void); // r13
  __int64 (*PsGetCurrentProcessIdFn)(void); // rdi
  void (__fastcall *ObfDereferenceObjectFn)(PEPROCESS); // r12
  struct _KPROCESS *currentProcess; // rbp
  __int64 CurrentProcessId; // rdi
  PEPROCESS Process; // rbx MAPDST
  __int64 (__fastcall *PsGetProcessIdFn)(PEPROCESS); // [rsp+30h] [rbp-38h]
  unsigned __int8 (__fastcall *PsGetProcessExitProcessCalledFn)(PEPROCESS); // [rsp+38h] [rbp-30h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  sub_FFFFF801BCF4A358();
  qword_FFFFF801BD006AB0 = (__int64)v9;
  if ( v9 )
  {
    v10 = v9(a1, a2, a3, a4, a5);
    PsGetProcessIdFn = (__int64 (__fastcall *)(PEPROCESS))(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetCurrentThreadIdFn = (void (*)(void))(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetCurrentProcessIdFn = (__int64 (*)(void))(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)PsGetCurrentProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessExitProcessCalledFn = (unsigned __int8 (__fastcall *)(PEPROCESS))((PsGetProcessExitProcessCalled ^ qword_FFFFF801BCFACC40) & -(__int64)((PsGetProcessExitProcessCalled ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ObfDereferenceObjectFn = (void (__fastcall *)(PEPROCESS))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    if ( g_GameProcessId )
    {
      if ( v10 >= 0 && a1 != (void *)-1i64 )
      {
        currentProcess = (struct _KPROCESS *)((__int64 (*)(void))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
        CurrentProcessId = PsGetCurrentProcessIdFn();
        PsGetCurrentThreadIdFn();
        Process = EmacReferenceProcessObjectByHandle(a1);
        if ( Process )
        {
          if ( Process != currentProcess
            && CurrentProcessId != g_SteamProcessId
            && CurrentProcessId != g_CsrssProcessId
            && CurrentProcessId != 4
            && g_GameProcessId == PsGetProcessIdFn(Process)
            && !PsGetProcessExitProcessCalledFn(Process) )
          {
            EmacNtWriteVirtualMemoryReport(currentProcess, CurrentProcessId, a2, a4);
          }
          ObfDereferenceObjectFn(Process);
        }
      }
    }
  }
  else
  {
    v10 = 0xC0000138;
  }
  _InterlockedDecrement(&g_EmacReferenceCount);
  return (unsigned int)v10;
}