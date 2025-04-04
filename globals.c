void *__fastcall EmacGetSystemRoutineAddress(
        const char *routineName,
        bool useMmGetSystemRoutineAddress,
        void *imageBase)
{
  _IMAGE_DOS_HEADER *imageBaseCast; // rbx
  int (__fastcall *v4)(__int128 *, __int128 *, __int64); // r9
  void (__fastcall *RtlFreeUnicodeStringFn)(__int128 *); // r13
  __int64 v6; // rbp
  unsigned __int64 v7; // rdx
  char *exportAddress; // rsi
  _IMAGE_NT_HEADERS64 *v9; // rax
  __int64 VirtualAddress; // rcx
  char *v11; // rdi
  char *v12; // r12
  char *v13; // r14
  char *v14; // r15
  __int64 v15; // r8
  void (__fastcall *RtlInitAnsiStringFn)(__int128 *, const char *); // [rsp+28h] [rbp-70h]
  __int128 v18; // [rsp+30h] [rbp-68h] BYREF
  __int128 v19[5]; // [rsp+40h] [rbp-58h] BYREF
  int (__fastcall *RtlAnsiStringToUnicodeStringFn)(__int128 *, __int128 *, __int64); // [rsp+B0h] [rbp+18h]
  __int64 (__fastcall *MmGetSystemRoutineAddressFn)(__int128 *); // [rsp+B8h] [rbp+20h]

  imageBaseCast = (_IMAGE_DOS_HEADER *)g_NtoskrnlBase;// Use NtoskrnlBase if none was provided
  v19[0] = 0i64;
  RtlInitAnsiStringFn = (void (__fastcall *)(__int128 *, const char *))(((unsigned __int64)RtlInitAnsiString ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)RtlInitAnsiString ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  v18 = 0i64;
  v4 = (int (__fastcall *)(__int128 *, __int128 *, __int64))(((unsigned __int64)RtlAnsiStringToUnicodeString ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)RtlAnsiStringToUnicodeString ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  RtlAnsiStringToUnicodeStringFn = v4;
  RtlFreeUnicodeStringFn = (void (__fastcall *)(__int128 *))(((unsigned __int64)RtlFreeUnicodeString ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)RtlFreeUnicodeString ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  v6 = 0i64;
  v7 = ((unsigned __int64)MmGetSystemRoutineAddress ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)MmGetSystemRoutineAddress ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38);
  MmGetSystemRoutineAddressFn = (__int64 (__fastcall *)(__int128 *))v7;
  if ( imageBase )
    imageBaseCast = (_IMAGE_DOS_HEADER *)imageBase;
  exportAddress = 0i64;
  if ( !imageBaseCast )
    return 0i64;
  if ( imageBaseCast->e_magic != 0x5A4D )
    return 0i64;
  v9 = (_IMAGE_NT_HEADERS64 *)((char *)imageBaseCast + imageBaseCast->e_lfanew);
  if ( v9->Signature != 0x4550 )
    return 0i64;
  if ( v9->OptionalHeader.Magic != 0x20B )
    return 0i64;
  VirtualAddress = v9->OptionalHeader.DataDirectory[0].VirtualAddress;
  if ( !(_DWORD)VirtualAddress || !v9->OptionalHeader.DataDirectory[0].Size )
    return 0i64;
  v11 = (char *)imageBaseCast + VirtualAddress;
  v12 = (char *)imageBaseCast + *(unsigned int *)((char *)&imageBaseCast->e_res[2] + VirtualAddress);
  v13 = (char *)imageBaseCast + *(unsigned int *)((char *)&imageBaseCast->e_res[4] + VirtualAddress);
  v14 = (char *)imageBaseCast + *(unsigned int *)((char *)imageBaseCast->e_res + VirtualAddress);
  if ( *(_DWORD *)((char *)&imageBaseCast->e_lfarlc + VirtualAddress) )
  {
    while ( stricmp(routineName, (const char *)imageBaseCast + *(unsigned int *)&v12[4 * v6]) )
    {
      v6 = (unsigned int)(v6 + 1);
      if ( (unsigned int)v6 >= *((_DWORD *)v11 + 6) )
        goto LABEL_14;
    }
    exportAddress = (char *)imageBaseCast + *(unsigned int *)&v14[4 * *(unsigned __int16 *)&v13[2 * v6]];
LABEL_14:
    v4 = RtlAnsiStringToUnicodeStringFn;
    v7 = (unsigned __int64)MmGetSystemRoutineAddressFn;
  }
  if ( RtlInitAnsiStringFn && v4 && v7 && RtlFreeUnicodeStringFn && useMmGetSystemRoutineAddress )
  {
    RtlInitAnsiStringFn(v19, routineName);
    LOBYTE(v15) = 1;
    if ( RtlAnsiStringToUnicodeStringFn(&v18, v19, v15) >= 0 )
    {
      exportAddress = (char *)MmGetSystemRoutineAddressFn(&v18);
      RtlFreeUnicodeStringFn(&v18);
    }
  }
  return exportAddress;
}

void *__stdcall FindWin32kbase_gDxgkInterface()
{
  __m128 v0; // xmm0
  void *PatternIDAStyle; // rax
  __m128 si128; // xmm0
  __m128 v3; // xmm1
  void *ModuleInformation; // rax
  void *v5; // rbx
  __m128 v6; // xmm0
  __m128 v7; // xmm1
  __m128 v8; // xmm0
  void *result; // rax
  char routineName[16]; // [rsp+20h] [rbp-49h] BYREF
  __m128 v11; // [rsp+30h] [rbp-39h] BYREF
  __m128 v12; // [rsp+40h] [rbp-29h]
  wchar_t moduleName[8]; // [rsp+50h] [rbp-19h] BYREF
  __m128 v14; // [rsp+60h] [rbp-9h] BYREF
  __m128 v15; // [rsp+70h] [rbp+7h] BYREF
  __m128i v16; // [rsp+80h] [rbp+17h] BYREF
  __m128 v17; // [rsp+90h] [rbp+27h] BYREF
  __m128 v18; // [rsp+A0h] [rbp+37h] BYREF

  if ( (dword_FFFFF801BCFADBD8 & 1) != 0 )
  {
    PatternIDAStyle = RtlFindExportedRoutineByName;
  }
  else
  {
    *(_QWORD *)moduleName = 0xDA39E026A201B59Fui64;
    dword_FFFFF801BCFADBD8 |= 1u;
    wmemcpy(&moduleName[4], L"涄몕볿⦯⊱焜ἤ雖楉빕截", 12);
    *(_QWORD *)routineName = 0x9F5D8E4FE46DC1CDui64;
    *(_QWORD *)&routineName[8] = 0x7BCBD98BC8FA1DFCi64;
    v0 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)routineName), *(__m128 *)moduleName);
    v11.m128_u64[0] = 0x66661472849157DEi64;
    v11.m128_u64[1] = 0x622ABE550C24F798i64;
    v11 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v11), v14);// Decrypted UTF-8: outineByName
    *(__m128 *)routineName = v0;                // Decrypted UTF-8: RtlFindExportedR
    PatternIDAStyle = EmacGetSystemRoutineAddress(routineName, 0, 0i64);
    RtlFindExportedRoutineByName = (__int64 (__fastcall *)(_QWORD, _QWORD))PatternIDAStyle;
  }
  if ( !PatternIDAStyle )
    return 0i64;
  *(_QWORD *)routineName = 0xDA39E026A201B59Fui64;
  *(_QWORD *)moduleName = 0xDA0AE048A268B5E8ui64;
  *(_QWORD *)&routineName[8] = 0x29AFBCFFBA956D84i64;
  si128 = (__m128)_mm_load_si128((const __m128i *)routineName);
  wmemcpy(&moduleName[4], L"涶뫾벝⧎⋂焲ὗ隯椺빕截", 12);
  v3 = (__m128)_mm_load_si128((const __m128i *)&v14);
  v11.m128_u64[0] = 0x1F24711CEDE522B1i64;
  v11.m128_u64[1] = 0x622ABE55694996D6i64;
  v14 = _mm_xor_ps(v3, v11);                    // Decrypted Raw (unprintable): 1c 75 11 69 40 65 31 79 4e 61 6d 65 00 00 00 00
  *(__m128 *)moduleName = _mm_xor_ps(si128, *(__m128 *)moduleName);// Decrypted Raw (unprintable): 77 00 69 00 6e 00 33 00 78 70 6f 72 74 65 64 52
  ModuleInformation = EmacFindKernelModule(moduleName, 0i64);
  v5 = ModuleInformation;
  if ( !ModuleInformation )
    return 0i64;
  *(_QWORD *)routineName = 0xDA39E026A201B59Fui64;
  v16.m128i_i64[0] = 0xB4708B41DA45D2A0ui64;
  *(_QWORD *)&routineName[8] = 0x29AFBCFFBA956D84i64;
  v16.m128i_i64[1] = 0x69CADF9EDCE708F0i64;
  v6 = _mm_xor_ps((__m128)_mm_load_si128(&v16), *(__m128 *)routineName);
  v17.m128_u64[0] = 0x54632958B2B011F1i64;
  v17.m128_u64[1] = 0x2B75F5675A07DF81i64;
  v7 = (__m128)_mm_load_si128((const __m128i *)&v17);
  v18.m128_u64[0] = 0xB8DEA714DB17EB4Dui64;
  v18.m128_u64[1] = 0x54A88CAB882236A8i64;
  v12.m128_u64[0] = 0xFD9DE6528952BF03ui64;
  v16 = (__m128i)v6;                            // Decrypted UTF-8: ?gDxgkInterface@
  v8 = (__m128)_mm_load_si128((const __m128i *)&v18);
  v12.m128_u64[1] = 0x54A88CAB886376E8i64;
  v11.m128_u64[0] = 0x1F24711CEDE522B1i64;
  v11.m128_u64[1] = 0x622ABE55694996D6i64;
  v18 = _mm_xor_ps(v8, v12);                    // Decrypted UTF-8: NTERFACE@@A
  v17 = _mm_xor_ps(v7, v11);                    // Decrypted Raw (unprintable): 40 33 55 5f 44 58 47 4b 19 28 23 56 32 4b 5f 49
  result = (void *)RtlFindExportedRoutineByName(ModuleInformation, &v16);
  if ( !result )
  {
    *(_QWORD *)routineName = 0xDA39E026A201B59Fui64;
    v15.m128_u64[0] = 0xAE57A94DC579F1F8ui64;
    *(_QWORD *)&routineName[8] = 0x29AFBCFFBA956D84i64;
    v15.m128_u64[1] = 0x29AFD99CDBF31FE1i64;
    v15 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v15), *(__m128 *)routineName);// Decrypted UTF-8: gDxgkInterface
    result = (void *)RtlFindExportedRoutineByName(v5, &v15);
    if ( !result )
      return 0i64;
  }
  return result;
}

char *FindClasspnpClassGlobalDispatch()
{
  char *result; // rax
  __m128 v1; // xmm0
  __m128 si128; // xmm1
  __m128 v3; // xmm0
  char *Pattern; // rax
  char patternMask[16]; // [rsp+20h] [rbp-60h] BYREF
  char sectionName[16]; // [rsp+30h] [rbp-50h] BYREF
  __m128 v7; // [rsp+40h] [rbp-40h] BYREF
  __m128 v8; // [rsp+50h] [rbp-30h]
  wchar_t moduleName[8]; // [rsp+60h] [rbp-20h] BYREF
  __m128 v10; // [rsp+70h] [rbp-10h] BYREF

  result = (char *)g_ClasspnpClassGlobalDispatch;
  if ( !g_ClasspnpClassGlobalDispatch )
  {
    *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
    *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
    v7.m128_u64[0] = 0xDA39E026A201B59Fui64;
    *(_QWORD *)patternMask = 0xA206DF199D79CDE7ui64;
    *(_QWORD *)&patternMask[8] = 0x29D78387C2ED52FCi64;
    v1 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)patternMask), *(__m128 *)sectionName);
    *(_QWORD *)sectionName = 0xDA39E026E746F4CFui64;
    *(_QWORD *)moduleName = 0xDA4AE047A26DB5DCui64;
    v7.m128_u64[1] = 0x29AFBCFFBA956D84i64;
    wmemcpy(&moduleName[4], L"混뫥벑⧟⊟煥ὗ雖楉빕截", 12);
    *(__m128 *)patternMask = v1;                // Decrypted UTF-8: xxx????xx?xxx?x
    si128 = (__m128)_mm_load_si128((const __m128i *)&v10);
    *(__m128 *)sectionName = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v7), *(__m128 *)sectionName);// Decrypted UTF-8: PAGE
    v3 = (__m128)_mm_load_si128((const __m128i *)moduleName);
    v7.m128_u64[0] = 0xDA39E026A201B59Fui64;
    v7.m128_u64[1] = 0x29AFBCFFBA956D84i64;
    v8.m128_u64[1] = 0x622ABE55694996D6i64;
    v8.m128_u64[0] = 0x1F24711CEDE522B1i64;
    v10 = _mm_xor_ps(si128, v8);                // Decrypted Raw (unprintable): 78 ef ef 70 7c ae 51 bd 00 00 00 00 00 00 00 00
    *(__m128 *)moduleName = _mm_xor_ps(v3, v7); // Decrypted UTF-16: Classpnp
    Pattern = (char *)FindPattern(
                        moduleName,
                        sectionName,
                        (unsigned __int8 *)&g_ClasspnpClassGlobalDispatchPattern,
                        patternMask);
    if ( Pattern )
    {
      result = &Pattern[*(int *)(Pattern + 3) + 7];
      g_ClasspnpClassGlobalDispatch = (__int64)result;
    }
    else
    {
      return (char *)g_ClasspnpClassGlobalDispatch;
    }
  }
  return result;
}

void *__stdcall FindNtKdpDebugRoutineSelect()
{
  void *result; // rax
  char *patternMask; // r9
  __m128 v2; // xmm0
  __m128 v3; // xmm0
  __m128 v4; // xmm0
  char *sectionName_1; // rdx
  __m128 v6; // xmm0
  __m128 v7; // xmm1
  __m128 si128; // xmm0
  __m128 v9; // xmm0
  __m128 v10; // xmm0
  char pattern[16]; // [rsp+20h] [rbp-19h] BYREF
  __int64 NtKdpDebugRoutineSelectPattern[2]; // [rsp+30h] [rbp-9h] BYREF
  char sectionName[16]; // [rsp+40h] [rbp+7h] BYREF
  __m128 v14; // [rsp+50h] [rbp+17h]
  __m128 v15; // [rsp+60h] [rbp+27h]
  wchar_t moduleName[8]; // [rsp+70h] [rbp+37h] BYREF
  __m128 v17; // [rsp+80h] [rbp+47h] BYREF

  result = (void *)g_NtKdpDebugRoutineSelect;
  if ( !g_NtKdpDebugRoutineSelect )
  {
    v14.m128_u64[0] = 0xDA39E026A201B59Fui64;
    if ( (unsigned int)GetNtBuildNumber() < 26100 )
    {
      patternMask = sectionName;
      *(_QWORD *)sectionName = 0xA206DF199D3ECDE7ui64;
      NtKdpDebugRoutineSelectPattern[0] = 0x50F52CEA6ECD881Ci64;
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956DFCi64;
      si128 = (__m128)_mm_load_si128((const __m128i *)sectionName);
      NtKdpDebugRoutineSelectPattern[1] = 0x29AFBCFFBA956DC0i64;
      *(_QWORD *)pattern = 0xDA39E052DA64C1B1ui64;
      v14.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)sectionName = _mm_xor_ps(si128, v14);// Decrypted UTF-8: xx?????x
      v9 = (__m128)_mm_load_si128((const __m128i *)NtKdpDebugRoutineSelectPattern);
      *(_QWORD *)moduleName = 0xDA4AE049A275B5F1ui64;
      v14.m128_u64[0] = 0xDA39E026A201B59Fui64;
      wmemcpy(&moduleName[4], L"淯뫧벑⧃⊟煤ὁ雖楉빕截", 12);
      *(__m128 *)NtKdpDebugRoutineSelectPattern = _mm_xor_ps(v9, v14);// Decrypted Raw (unprintable): 83 3d cc cc cc cc cc 8a b6 44 24 68 00 00 00 00
      *(_QWORD *)&pattern[8] = 0x29AFBCFFBA956D84i64;
      v10 = (__m128)_mm_load_si128((const __m128i *)pattern);
      v14.m128_u64[0] = 0xDA39E026A201B59Fui64;
      v14.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      v15.m128_u64[1] = 0x622ABE55694996D6i64;
      sectionName_1 = pattern;
      *(__m128 *)pattern = _mm_xor_ps(v10, v14);// Decrypted Raw (unprintable): 2e 74 65 78 74 00 00 00 78 78 78 78 00 00 00 00
    }
    else
    {
      *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
      patternMask = pattern;
      NtKdpDebugRoutineSelectPattern[0] = 0xD5392CEA6ECD881Cui64;
      NtKdpDebugRoutineSelectPattern[1] = 0x29AFBCFFD2B12932i64;
      *(_QWORD *)pattern = 0xA241DF199D3ECDE7ui64;
      *(_QWORD *)&pattern[8] = 0x29AFBCFFC2ED15FCi64;
      v2 = (__m128)_mm_load_si128((const __m128i *)pattern);
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)pattern = _mm_xor_ps(v2, *(__m128 *)sectionName);// Decrypted UTF-8: xx????xxxxxx
      *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
      v3 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)sectionName), *(__m128 *)NtKdpDebugRoutineSelectPattern);
      *(_QWORD *)sectionName = 0xDA39E052DA64C1B1ui64;
      *(_QWORD *)moduleName = 0xDA4AE049A275B5F1ui64;
      wmemcpy(&moduleName[4], L"淯뫧벑⧃⊟煤ὁ雖楉빕截", 12);
      *(__m128 *)NtKdpDebugRoutineSelectPattern = v3;// Decrypted Raw (unprintable): 83 3d cc cc cc cc 00 0f b6 44 24 68 00 00 00 00
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      v4 = (__m128)_mm_load_si128((const __m128i *)sectionName);
      v14.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      v15.m128_u64[1] = 0x622ABE55694996D6i64;
      sectionName_1 = sectionName;
      *(__m128 *)sectionName = _mm_xor_ps(v4, v14);// Decrypted UTF-8: .text
    }
    v6 = (__m128)_mm_load_si128((const __m128i *)moduleName);
    v7 = (__m128)_mm_load_si128((const __m128i *)&v17);
    v14.m128_u64[1] = 0x29AFBCFFBA956D84i64;
    v14.m128_u64[0] = 0xDA39E026A201B59Fui64;
    v15.m128_u64[0] = 0x1F24711CEDE522B1i64;
    v17 = _mm_xor_ps(v7, v15);                  // Decrypted Raw (unprintable): 2e e3 e4 37 36 91 78 c5 00 00 00 00 00 00 00 00
    *(__m128 *)moduleName = _mm_xor_ps(v6, v14);// Decrypted UTF-16: ntoskrnl
    result = FindPattern(moduleName, sectionName_1, (unsigned __int8 *)NtKdpDebugRoutineSelectPattern, patternMask);
    if ( result )
      g_NtKdpDebugRoutineSelect = (__int64)result;
  }
  return result;
}

__int64 FindNtWmipSMBiosTableLength()
{
  __int64 result; // rax
  char *v1; // r9
  unsigned __int8 *v2; // r8
  __m128 v3; // xmm0
  __m128 v4; // xmm0
  __m128 v5; // xmm0
  char *v6; // rdx
  __m128 v7; // xmm0
  __m128 v8; // xmm0
  __m128 si128; // xmm0
  __m128 v10; // xmm0
  __m128 v11; // xmm1
  char *v12; // rax
  char sectionName[16]; // [rsp+20h] [rbp-60h] BYREF
  char pattern[16]; // [rsp+30h] [rbp-50h] BYREF
  __m128 v15; // [rsp+40h] [rbp-40h] BYREF
  __m128 v16; // [rsp+50h] [rbp-30h]
  wchar_t moduleName[8]; // [rsp+60h] [rbp-20h] BYREF
  __m128 v18; // [rsp+70h] [rbp-10h] BYREF

  result = g_NtWmipSMBiosTableLength;
  if ( !g_NtWmipSMBiosTableLength )
  {
    if ( IsWindows10() || IsWindows11() )
    {
      v2 = (unsigned __int8 *)&g_WmipSMBiosTableLengthPattern;
      *(_QWORD *)pattern = 0xA241DF199D3ECDE7ui64;
      v15.m128_u64[0] = 0xDA39E026A201B59Fui64;
      *(_QWORD *)&pattern[8] = 0x29AFBCFFBA9515FCi64;
      si128 = (__m128)_mm_load_si128((const __m128i *)pattern);
      v15.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)pattern = _mm_xor_ps(si128, v15);// Decrypted UTF-8: xx????xxx
      *(_QWORD *)sectionName = 0xDA39E026E746F4CFui64;
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      v8 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v15), *(__m128 *)sectionName);
    }
    else
    {
      if ( !IsWindows8() && !IsWindows8_1() )
      {
        if ( !IsWindows7() )
          return g_NtWmipSMBiosTableLength;
        v1 = sectionName;
        *(_QWORD *)sectionName = 0xA241DF199D3ECDE7ui64;
        v2 = (unsigned __int8 *)g_NtWmipSMBiosTableLengthPatternWin7;
        *(_QWORD *)pattern = 0xDA39E026A201B59Fui64;
        *(_QWORD *)&sectionName[8] = 0x29AFBCFFC2ED15FCi64;
        v3 = (__m128)_mm_load_si128((const __m128i *)sectionName);
        *(_QWORD *)&pattern[8] = 0x29AFBCFFBA956D84i64;
        v4 = _mm_xor_ps(v3, *(__m128 *)pattern);
        *(_QWORD *)pattern = 0xDA39E026E746F4CFui64;
        *(_QWORD *)moduleName = 0xDA4AE049A275B5F1ui64;
        wmemcpy(&moduleName[4], L"淯뫧벑⧃⊟煤ὁ雖楉빕截", 12);
        *(__m128 *)sectionName = v4;            // Decrypted UTF-8: xx????xxxxxx
        v5 = (__m128)_mm_load_si128((const __m128i *)pattern);
        v15.m128_u64[0] = 0xDA39E026A201B59Fui64;
        v15.m128_u64[1] = 0x29AFBCFFBA956D84i64;
        v16.m128_u64[1] = 0x622ABE55694996D6i64;
        v6 = pattern;
        *(__m128 *)pattern = _mm_xor_ps(v5, v15);// Decrypted UTF-8: (9xz??xx
LABEL_11:
        v10 = (__m128)_mm_load_si128((const __m128i *)moduleName);
        v11 = (__m128)_mm_load_si128((const __m128i *)&v18);
        v15.m128_u64[1] = 0x29AFBCFFBA956D84i64;
        v15.m128_u64[0] = 0xDA39E026A201B59Fui64;
        v16.m128_u64[0] = 0x1F24711CEDE522B1i64;
        v18 = _mm_xor_ps(v11, v16);             // Decrypted Raw (unprintable): 50 d6 c6 0a 42 91 78 c5 00 00 00 00 00 00 00 00
        *(__m128 *)moduleName = _mm_xor_ps(v10, v15);// Decrypted UTF-16: ntoskrnl
        v12 = (char *)FindPattern(moduleName, v6, v2, v1);
        if ( v12 )
        {
          result = (__int64)&v12[*(int *)(v12 + 2) + 6];
          g_NtWmipSMBiosTableLength = result;
          return result;
        }
        return g_NtWmipSMBiosTableLength;
      }
      v2 = (unsigned __int8 *)g_NtWmipSMBiosTableLengthPatternWin8;
      *(_QWORD *)pattern = 0xA241DF199D3ECDE7ui64;
      v15.m128_u64[0] = 0xDA39E026A201B59Fui64;
      *(_QWORD *)&pattern[8] = 0x29AFBCFFBA956DFCi64;
      v7 = (__m128)_mm_load_si128((const __m128i *)pattern);
      v15.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)pattern = _mm_xor_ps(v7, v15); // Decrypted UTF-8: xx????xx
      *(_QWORD *)sectionName = 0xDA39E026E746F4CFui64;
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      v8 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)sectionName), v15);
    }
    *(__m128 *)sectionName = v8;                // Decrypted Raw (unprintable): 50 41 47 45 00 00 00 00 78 78 78 78 00 00 00 00
    *(_QWORD *)moduleName = 0xDA4AE049A275B5F1ui64;
    v1 = pattern;
    wmemcpy(&moduleName[4], L"淯뫧벑⧃⊟煤ὁ雖楉빕截", 12);
    v16.m128_u64[1] = 0x622ABE55694996D6i64;
    v6 = sectionName;
    goto LABEL_11;
  }
  return result;
}

char *FindNtWmipSMBiosTablePhysicalAddress()
{
  char *result; // rax
  __m128 v1; // xmm0
  __m128 v2; // xmm1
  __m128 *v3; // r9
  __m128 v4; // xmm0
  __m128 v5; // xmm1
  char *v6; // rdx
  unsigned __int8 *v7; // r8
  wchar_t *v8; // rcx
  __m128 v9; // xmm0
  __m128 v10; // xmm0
  __m128 v11; // xmm1
  __m128 v12; // xmm0
  __m128 si128; // xmm0
  __m128 v14; // xmm1
  __m128 v15; // xmm0
  __m128 v16; // xmm0
  __m128 v17; // xmm1
  char *v18; // rax
  wchar_t moduleName[8]; // [rsp+20h] [rbp-29h] BYREF
  __m128i v20; // [rsp+30h] [rbp-19h] BYREF
  char sectionName[16]; // [rsp+40h] [rbp-9h] BYREF
  __m128 v22; // [rsp+50h] [rbp+7h]
  __m128 v23; // [rsp+60h] [rbp+17h] BYREF
  __m128 v24; // [rsp+70h] [rbp+27h] BYREF
  char pattern[16]; // [rsp+80h] [rbp+37h] BYREF
  __m128 v26; // [rsp+90h] [rbp+47h] BYREF

  result = (char *)g_NtWmipSMBiosTablePhysicalAddress;
  if ( !g_NtWmipSMBiosTablePhysicalAddress )
  {
    if ( IsWindows10() || IsWindows11() )
    {
      v23.m128_u64[0] = 0xDA39E026A201B59Fui64;
      v24.m128_u64[0] = 0x1F24711CEDE522B1i64;
      *(_QWORD *)pattern = 0xA206DF199D79CDE7ui64;
      *(_QWORD *)sectionName = 0xDA39E026E746F4CFui64;
      *(_QWORD *)&pattern[8] = 0x169083C0C2ED15FCi64;
      si128 = (__m128)_mm_load_si128((const __m128i *)pattern);
      *(_QWORD *)moduleName = 0xDA4AE049A275B5F1ui64;
      v24.m128_u64[1] = 0x622ABE55694996D6i64;
      wmemcpy(&moduleName[4], L"淯뫧벑⧃⊟煤ὁ雖楉빕截", 12);
      v26.m128_u64[0] = 0x1F24711CED9D5AC9i64;
      v23.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)pattern = _mm_xor_ps(si128, v23);// Decrypted Raw (unprintable): 78 78 78 3f 3f 3f 3f 78 6b 00 72 00 6e 00 6c 00
      v26.m128_u64[1] = 0x622ABE55694996D6i64;
      v14 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v26), v24);
      v15 = (__m128)_mm_load_si128((const __m128i *)&v23);
      v3 = (__m128 *)pattern;
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)sectionName = _mm_xor_ps(v15, *(__m128 *)sectionName);// Decrypted UTF-8: PAGE
      v16 = (__m128)_mm_load_si128((const __m128i *)moduleName);
      v26 = v14;                                // Decrypted UTF-8: xxx
      v7 = (unsigned __int8 *)&g_NtWmipSMBiosTablePhysicalAddressPattern;
      v8 = moduleName;
      v17 = _mm_xor_ps((__m128)_mm_load_si128(&v20), v24);
      v23.m128_u64[0] = 0xDA39E026A201B59Fui64;
      v23.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      *(__m128 *)moduleName = _mm_xor_ps(v16, v23);// Decrypted Raw (unprintable): 6e 00 74 00 6f 00 73 00 78 78 78 3f 78 78 78 00
      v20 = (__m128i)v17;                       // Decrypted UTF-16: .exe
    }
    else
    {
      if ( !IsWindows8() && !IsWindows8_1() )
      {
        if ( !IsWindows7() )
          return (char *)g_NtWmipSMBiosTablePhysicalAddress;
        *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
        v22.m128_u64[0] = 0x1F24711CEDE522B1i64;
        v23.m128_u64[0] = 0xA206DF199D79CDE7ui64;
        *(_QWORD *)moduleName = 0xDA39E026E746F4CFui64;
        v23.m128_u64[1] = 0x169083C0C2ED15FCi64;
        v1 = (__m128)_mm_load_si128((const __m128i *)&v23);
        *(_QWORD *)pattern = 0xDA4AE049A275B5F1ui64;
        v22.m128_u64[1] = 0x622ABE55694996D6i64;
        *(_QWORD *)&pattern[8] = 0x29C3BC91BAE76DEFi64;
        v24.m128_u64[0] = 0x1F24711CEDE522C9i64;
        *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
        v23 = _mm_xor_ps(v1, *(__m128 *)sectionName);// Decrypted UTF-8: xxx????xxxxx????
        v24.m128_u64[1] = 0x622ABE55694996D6i64;
        v2 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v24), v22);
        v26.m128_u64[0] = 0x1F417164ED80229Fi64;
        v3 = &v23;
        v26.m128_u64[1] = 0x622ABE55694996D6i64;
        *(_QWORD *)&moduleName[4] = 0x29AFBCFFBA956D84i64;
        *(__m128 *)moduleName = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)moduleName), *(__m128 *)sectionName);// Decrypted UTF-8: PAGE
        v4 = (__m128)_mm_load_si128((const __m128i *)pattern);
        v24 = v2;                               // Decrypted UTF-8: x
        v5 = (__m128)_mm_load_si128((const __m128i *)&v26);
        *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
        v6 = (char *)moduleName;
        v7 = (unsigned __int8 *)g_NtWmipSMBiosTablePhysicalAddressPatternWin7;
        v8 = (wchar_t *)pattern;
        *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
        *(__m128 *)pattern = _mm_xor_ps(v4, *(__m128 *)sectionName);// Decrypted UTF-16: ntoskrnl
        v26 = _mm_xor_ps(v5, v22);              // Decrypted UTF-16: .exe
LABEL_11:
        v18 = (char *)FindPattern(v8, v6, v7, (char *)v3);
        if ( v18 )
        {
          result = &v18[*(int *)(v18 + 3) + 7];
          g_NtWmipSMBiosTablePhysicalAddress = (__int64)result;
          return result;
        }
        return (char *)g_NtWmipSMBiosTablePhysicalAddress;
      }
      *(_QWORD *)sectionName = 0xDA39E026A201B59Fui64;
      *(_QWORD *)moduleName = 0xA206DF199D79CDE7ui64;
      v23.m128_u64[0] = 0xDA39E026A201B59Fui64;
      *(_QWORD *)&moduleName[4] = 0x29D7C48785ED15FCi64;
      v9 = (__m128)_mm_load_si128((const __m128i *)moduleName);
      *(_QWORD *)&sectionName[8] = 0x29AFBCFFBA956D84i64;
      v10 = _mm_xor_ps(v9, *(__m128 *)sectionName);
      *(_QWORD *)sectionName = 0xDA39E026E746F4CFui64;
      *(_QWORD *)pattern = 0xDA4AE049A275B5F1ui64;
      *(__m128 *)moduleName = v10;              // Decrypted UTF-8: xxx????x
      *(_QWORD *)&pattern[8] = 0x29C3BC91BAE76DEFi64;
      v23.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      v26.m128_u64[0] = 0x1F417164ED80229Fi64;
      v3 = (__m128 *)moduleName;
      v26.m128_u64[1] = 0x622ABE55694996D6i64;
      v11 = (__m128)_mm_load_si128((const __m128i *)&v26);
      *(__m128 *)sectionName = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)sectionName), v23);// Decrypted Raw (unprintable): 50 41 47 45 00 00 00 00 78 78 78 78 3f 3f 3f 3f
      v12 = (__m128)_mm_load_si128((const __m128i *)pattern);
      v24.m128_u64[0] = 0x1F24711CEDE522B1i64;
      v7 = (unsigned __int8 *)g_NtWmipSMBiosTablePhysicalAddressPatternWin8;
      v24.m128_u64[1] = 0x622ABE55694996D6i64;
      v8 = (wchar_t *)pattern;
      v23.m128_u64[0] = 0xDA39E026A201B59Fui64;
      v23.m128_u64[1] = 0x29AFBCFFBA956D84i64;
      v26 = _mm_xor_ps(v11, v24);               // Decrypted UTF-16: Vexe
      *(__m128 *)pattern = _mm_xor_ps(v12, v23);// Decrypted Raw (unprintable): 6e 00 74 00 6f 00 73 00 13 78 0a 78 51 3f 53 3f
    }
    v6 = sectionName;
    goto LABEL_11;
  }
  return result;
}