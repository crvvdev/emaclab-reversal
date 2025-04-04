void *__fastcall EmacFindKernelModule(wchar_t *moduleName, _DWORD *moduleSize)
{
  __m128 si128; // xmm0
  __m128 v5; // xmm1
  _KLDR_DATA_TABLE_ENTRY *Flink; // rbx
  unsigned __int16 a2[8]; // [rsp+20h] [rbp-48h] BYREF
  __m128 v9; // [rsp+30h] [rbp-38h] BYREF
  __m128 v10; // [rsp+40h] [rbp-28h]
  __m128 v11; // [rsp+50h] [rbp-18h]

  if ( moduleSize )
    *moduleSize = 0;
  if ( !moduleName )
    goto LABEL_13;
  v9.m128_u64[1] = 0x882D38BEA8EF0EACui64;
  *(_QWORD *)a2 = 0xB44465D21088C44Bui64;
  *(_QWORD *)&a2[4] = 0xB7C44DAAC144A759ui64;
  si128 = (__m128)_mm_load_si128((const __m128i *)a2);
  v9.m128_u64[0] = 0x914EE02F3D8B65A9ui64;
  v5 = (__m128)_mm_load_si128((const __m128i *)&v9);
  v10.m128_u64[0] = 0xB43765BD10FCC425ui64;
  v10.m128_u64[1] = 0xB7A84DC4C136A732ui64;
  v11.m128_u64[1] = 0x882D38BEA8EF0EACui64;
  v11.m128_u64[0] = 0x912BE0573DEE6587ui64;
  v9 = _mm_xor_ps(v5, v11);                     // .exe
  *(__m128 *)a2 = _mm_xor_ps(si128, v10);       // Decrypted UTF-16: 
  if ( (unsigned int)wcsicmp(moduleName, a2) )  // If not 'ntoskrnl.exe'
  {
    if ( !PsLoadedModuleList )
      return 0i64;
    Flink = (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList->Flink;
    if ( PsLoadedModuleList->Flink == PsLoadedModuleList )
    {
      return 0i64;
    }
    else
    {
      while ( (unsigned int)wcsnicmp(
                              moduleName,
                              Flink->BaseDllName.Buffer,
                              (unsigned __int64)Flink->BaseDllName.Length >> 1) )
      {
        Flink = (_KLDR_DATA_TABLE_ENTRY *)Flink->InLoadOrderLinks.Flink;
        if ( Flink == (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList )
          return 0i64;
      }
      if ( moduleSize )
        *moduleSize = Flink->SizeOfImage;
      return Flink->DllBase;
    }
  }
  else                                          // Use cached value for ntoskrnl.exe
  {
LABEL_13:
    if ( moduleSize )
      *moduleSize = g_NtoskrnlSize;
    return g_NtoskrnlBase;
  }
}

void *__fastcall EmacFindExportByName(wchar_t *moduleName, char *procedureName)
{
  void *v2; // rbx
  _IMAGE_DOS_HEADER *moduleBase; // rdi
  _IMAGE_NT_HEADERS64 *nth; // rcx
  __int64 VirtualAddress; // rax
  _IMAGE_EXPORT_DIRECTORY *exportDirectory; // rbp
  int v7; // esi
  DWORD *exportNamePointers; // r13
  WORD *ordinalTable; // r15
  DWORD *functionAddressTable; // r12
  void *retaddr; // [rsp+48h] [rbp+0h]

  v2 = 0i64;
  if ( !retaddr )
    __fastfail(1337u);
  moduleBase = (_IMAGE_DOS_HEADER *)EmacFindKernelModule(moduleName, 0i64);
  if ( moduleBase )
  {
    if ( moduleBase->e_magic == 0x5A4D )
    {
      nth = (_IMAGE_NT_HEADERS64 *)((char *)moduleBase + moduleBase->e_lfanew);
      if ( nth->Signature == 0x4550 && nth->OptionalHeader.Magic == 0x20B )
      {
        VirtualAddress = nth->OptionalHeader.DataDirectory[0].VirtualAddress;
        if ( (_DWORD)VirtualAddress )
        {
          if ( nth->OptionalHeader.DataDirectory[0].Size )// Export Directory
          {
            exportDirectory = (_IMAGE_EXPORT_DIRECTORY *)((char *)moduleBase + VirtualAddress);
            v7 = 0;
            exportNamePointers = (DWORD *)((char *)&moduleBase->e_magic
                                         + *(unsigned int *)((char *)&moduleBase->e_res[2] + VirtualAddress));
            ordinalTable = (USHORT *)((char *)&moduleBase->e_magic
                                    + *(unsigned int *)((char *)&moduleBase->e_res[4] + VirtualAddress));
            functionAddressTable = (DWORD *)((char *)&moduleBase->e_magic
                                           + *(unsigned int *)((char *)moduleBase->e_res + VirtualAddress));
            if ( *(_DWORD *)((char *)&moduleBase->e_lfarlc + VirtualAddress) )
            {
              while ( stricmp((const char *)moduleBase + exportNamePointers[v7], procedureName) )
              {
                if ( ++v7 >= exportDirectory->NumberOfNames )
                  return v2;
              }
              return (void *)(qword_FFFFF801BCFACC40 ^ ((unsigned __int64)moduleBase
                                                      + functionAddressTable[ordinalTable[v7]]));
            }
          }
        }
      }
    }
  }
  return v2;
}