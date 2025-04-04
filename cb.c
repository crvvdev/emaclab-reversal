__int64 __fastcall EmacFltCallback(PFLT_CALLBACK_DATA fltCallbackData)
{
  unsigned int v2; // ebp
  ULONG (__fastcall *FltGetRequestorProcessIdFn)(PFLT_CALLBACK_DATA); // rsi
  NTSTATUS (__fastcall *FltGetFileNameInformationFn)(PFLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION *); // r12
  NTSTATUS (__fastcall *FltParseFileNameInformationFn)(PFLT_FILE_NAME_INFORMATION); // r15
  NTSTATUS (__stdcall *FltReleaseFileNameInformationFn)(PFLT_FILE_NAME_INFORMATION); // r14
  PFLT_IO_PARAMETER_BLOCK Iopb; // rdi
  ULONG processId; // esi
  struct _FLT_FILE_NAME_INFORMATION *v9; // rcx
  PFLT_FILE_NAME_INFORMATION fileNameInformation; // [rsp+50h] [rbp+8h] BYREF

  v2 = 1;
  _InterlockedAdd(&g_EmacReferenceCount, 1u);
  fileNameInformation = 0i64;
  FltGetRequestorProcessIdFn = (ULONG (__fastcall *)(PFLT_CALLBACK_DATA))(((unsigned __int64)FltGetRequestorProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetRequestorProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltGetFileNameInformationFn = (NTSTATUS (__fastcall *)(PFLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION *))(((unsigned __int64)FltGetFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltParseFileNameInformationFn = (NTSTATUS (__fastcall *)(PFLT_FILE_NAME_INFORMATION))(((unsigned __int64)FltParseFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltParseFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltReleaseFileNameInformationFn = (NTSTATUS (__stdcall *)(PFLT_FILE_NAME_INFORMATION))(((unsigned __int64)FltReleaseFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltReleaseFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( fltCallbackData )
  {
    Iopb = fltCallbackData->Iopb;
    if ( Iopb )
    {
      if ( Iopb->Parameters.Read.Length == 1 && Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == 0x10 )
      {
        ((void (__fastcall *)(PFLT_CALLBACK_DATA))(((unsigned __int64)FltGetRequestorProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetRequestorProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))(fltCallbackData);
        processId = FltGetRequestorProcessIdFn(fltCallbackData);
        if ( (processId == 4 || g_GameProcessId && processId == (_DWORD)g_GameProcessId)
          && (FltGetFileNameInformationFn(fltCallbackData, 0x101i64, &fileNameInformation) & 0xC0000000) != 0xC0000000
          && (FltParseFileNameInformationFn(fileNameInformation) & 0xC0000000) != 0xC0000000
          && processId == 4
          && EmacFltVerifyFileName(Iopb, fileNameInformation) )
        {
          fltCallbackData->IoStatus.Information = 0i64;
          v2 = 4;
          v9 = fileNameInformation;
          fltCallbackData->IoStatus.Status = 0xC000009A;// Block from loading
          if ( !v9 )
            goto LABEL_17;
        }
        else
        {
          v9 = fileNameInformation;
        }
        if ( v9 )
          FltReleaseFileNameInformationFn(v9);
      }
    }
  }
LABEL_17:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return v2;
}

void *__fastcall EmacFltReadFileToBuffer(
        struct _FLT_INSTANCE *Instance,
        struct _FILE_OBJECT *FileObject,
        _DWORD *fileSize)
{
  void *(__fastcall *ExAllocatePoolWithTagFn)(_QWORD, _QWORD, _QWORD); // r12
  void (__fastcall *ExFreePoolWithTagFn)(void *, _QWORD); // r15
  NTSTATUS (__fastcall *FltQueryInformationFileFn)(PFLT_INSTANCE, PFILE_OBJECT, PVOID, ULONG, FILE_INFORMATION_CLASS, PULONG); // r10
  NTSTATUS (__fastcall *FtlReadFileFn)(PFLT_INSTANCE, PFILE_OBJECT, PLARGE_INTEGER, ULONG, PVOID, FLT_IO_OPERATION_FLAGS, PULONG, PFLT_COMPLETED_ASYNC_IO_CALLBACK, PVOID); // r13
  void *fileBuffer; // rax MAPDST
  NTSTATUS status; // eax
  int fsi; // [rsp+50h] [rbp-20h] BYREF
  size_t Size[2]; // [rsp+54h] [rbp-1Ch]
  int v16; // [rsp+64h] [rbp-Ch]
  int v17; // [rsp+C0h] [rbp+50h] BYREF
  __int64 v18; // [rsp+C8h] [rbp+58h] BYREF

  v16 = 0;
  v17 = 0;
  v18 = 0i64;
  fsi = 0;
  fileBuffer = 0i64;
  *(_OWORD *)Size = 0i64;
  ExAllocatePoolWithTagFn = (void *(__fastcall *)(_QWORD, _QWORD, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExFreePoolWithTagFn = (void (__fastcall *)(void *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltQueryInformationFileFn = (NTSTATUS (__fastcall *)(PFLT_INSTANCE, PFILE_OBJECT, PVOID, ULONG, FILE_INFORMATION_CLASS, PULONG))(((unsigned __int64)FltQueryInformationFile ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltQueryInformationFile ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FtlReadFileFn = (NTSTATUS (__fastcall *)(PFLT_INSTANCE, PFILE_OBJECT, PLARGE_INTEGER, ULONG, PVOID, FLT_IO_OPERATION_FLAGS, PULONG, PFLT_COMPLETED_ASYNC_IO_CALLBACK, PVOID))((FtlReadFile ^ qword_FFFFF801BCFACC40) & -(__int64)((FtlReadFile ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( fileSize )
    *fileSize = 0;
  if ( !KeGetCurrentIrql() )
  {
    if ( Instance )
    {
      if ( FileObject )
      {
        if ( FltQueryInformationFileFn(Instance, FileObject, &fsi, 24i64, FileStandardInformation, (PULONG)&v17) >= 0 )
        {
          if ( HIDWORD(Size[0]) )
          {
            fileBuffer = ExAllocatePoolWithTagFn((unsigned int)g_EmacPoolType, HIDWORD(Size[0]), 'CAME');
            if ( fileBuffer )
            {
              memset(fileBuffer, 0, HIDWORD(Size[0]));
              status = FtlReadFileFn(
                         Instance,
                         FileObject,
                         (PLARGE_INTEGER)&v18,
                         HIDWORD(Size[0]),
                         fileBuffer,
                         5,
                         (PULONG)&v17,
                         0i64,
                         0i64);
              if ( (status & 0xC0000000) != 0xC0000000 && fileSize )
                *fileSize = HIDWORD(Size[0]);
              if ( status < 0 )
                ExFreePoolWithTagFn(fileBuffer, 'CAME');
            }
          }
        }
      }
    }
  }
  return fileBuffer;
}

bool __fastcall EmacFltVerifyFileName(PFLT_IO_PARAMETER_BLOCK Iopb, PFLT_FILE_NAME_INFORMATION fileNameInformation)
{
  char v3; // di
  void (__fastcall *ExFreePoolWithTagFn)(_IMAGE_DOS_HEADER *, _QWORD); // r14
  _IMAGE_DOS_HEADER *fileBuffer; // rbx
  __int64 e_lfanew; // rax
  _EMAC_IMAGE_SIGN_INFO a3; // [rsp+20h] [rbp-E0h] BYREF
  unsigned __int64 fileSize; // [rsp+310h] [rbp+210h] BYREF

  LODWORD(fileSize) = 0;
  *(_QWORD *)&a3.VerificationStatus = 0i64;
  a3.PolicyInfoSize = 0;
  v3 = 0;
  a3.IsVerified = 0;
  memset(&a3.SigningTime, 0, 681);
  ExFreePoolWithTagFn = (void (__fastcall *)(_IMAGE_DOS_HEADER *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( !byte_FFFFF801BCFAC6D8 )                 // Probably a master switch for file verification
  {
    if ( fileNameInformation && EmacCheckDbkProcessHackerByFileName(&fileNameInformation->Name) )
    {
      return 1;
    }
    else
    {
      fileBuffer = (_IMAGE_DOS_HEADER *)EmacFltReadFileToBuffer(Iopb->TargetInstance, Iopb->TargetFileObject, &fileSize);
      if ( fileBuffer )
      {
        if ( fileBuffer->e_magic == 0x5A4D )
        {
          e_lfanew = fileBuffer->e_lfanew;
          if ( (int)e_lfanew < 4096
            && (unsigned int)fileSize > 0x1000
            && *(_DWORD *)((char *)&fileBuffer->e_magic + e_lfanew) == 0x4550
            && *(USHORT *)((char *)&fileBuffer->e_lfarlc + e_lfanew) == 0x20B
            && *(USHORT *)((char *)fileBuffer[1].e_res + e_lfanew) == 1 )// Validate PE
          {
            if ( EmacVerifyFileSigned(fileBuffer, (unsigned int)fileSize, &a3) >= 0
              && LOBYTE(a3.Unknown1)
              && EmacVerifyFileCertificateName(a3.SubjectName) )
            {
              v3 = 1;
            }
            else
            {
              v3 = EmacVerifyFileUnknown((__int64)fileBuffer);
            }
          }
        }
        ExFreePoolWithTagFn(fileBuffer, 'CAME');
      }
    }
  }
  return v3;
}

unsigned __int8 __fastcall EmacImageCallback(
        const UNICODE_STRING *imageFileName,
        __int64 ProcessId,
        _EMAC_IMAGE_INFO *imageInfo)
{
  unsigned __int8 result; // al
  struct _FILE_OBJECT *FileObject; // rbx
  const UNICODE_STRING *p_FileName; // rbx
  __int64 (__fastcall *PsGetProcessWow64ProcessFn)(__int64); // rbx
  __int64 IoGetCurrentProcessFn; // rax
  struct _KPROCESS *Process; // r13
  char IsProcessWow64; // r15
  unsigned __int64 v13; // r8
  unsigned __int64 i; // rcx
  unsigned __int64 v15; // rax
  wchar_t *imageNameLowercase; // rsi
  __m128 si128; // xmm0
  __m128 v18; // xmm1
  __m128 v19; // xmm0
  __m128 v20; // xmm1
  __m128 v21; // xmm0
  __m128 v22; // xmm0
  __m128 v23; // xmm1
  __m128 v24; // xmm0
  __m128 v25; // xmm1
  __m128 v26; // xmm0
  __m128 v27; // xmm1
  __m128 v28; // xmm1
  __m128 v29; // xmm0
  PVOID ImageBase; // r8
  unsigned __int64 ProcedureAddress; // rax
  unsigned __int64 v32; // rax
  unsigned __int64 v33; // rax
  __m128 v34; // xmm0
  __m128 v35; // xmm1
  __m128 v36; // xmm0
  __m128 v37; // xmm1
  __m128 v38; // xmm0
  __m128 v39; // xmm1
  PVOID v40; // r8
  unsigned __int64 v41; // rax
  unsigned __int64 v42; // rax
  __m128 v43; // xmm0
  __m128 v44; // xmm1
  __m128 v45; // rcx
  __m128 v46; // xmm0
  __m128 v47; // xmm1
  __m128 v48; // xmm0
  int ProcessFileNameHash; // eax
  __m128 *EMACDllPath; // rdx
  __m128 v51; // xmm0
  __m128 v52; // xmm1
  __m128 v53; // xmm0
  __m128 v54; // xmm0
  __m128 v55; // xmm1
  __m128 v56; // xmm0
  __m128 v57; // xmm0
  __m128 v58; // xmm1
  __m128 v59; // xmm0
  __m128 v60; // xmm0
  __m128 v61; // xmm1
  __m128 v62; // xmm0
  __m128 v63; // xmm0
  __m128 v64; // xmm1
  __m128 v65; // xmm0
  __m128 v66; // xmm1
  __m128 v67; // xmm1
  __m128 v68; // xmm0
  __m128 v69; // xmm1
  __m128 v70; // xmm0
  __m128 v71; // xmm1
  __m128 v72; // xmm0
  __m128 v73; // xmm1
  SIZE_T ImageSize; // rcx
  char v75; // al
  PVOID v76; // rdx
  __int64 v77; // r8
  char v78; // bl
  void (__fastcall *ZwCloseHandleFn)(HANDLE); // [rsp+20h] [rbp-E0h]
  __m128 ZwCloseHandleFn_8; // [rsp+20h] [rbp-E0h]
  __m128 ZwCloseHandleFna; // [rsp+20h] [rbp-E0h]
  __m128 ZwCloseHandleFnb; // [rsp+20h] [rbp-E0h]
  __m128 v83; // [rsp+30h] [rbp-D0h]
  __m128 v84; // [rsp+30h] [rbp-D0h]
  __m128 v85; // [rsp+30h] [rbp-D0h]
  __m128 v86; // [rsp+30h] [rbp-D0h]
  __m128 v87; // [rsp+40h] [rbp-C0h] BYREF
  __m128 v88; // [rsp+50h] [rbp-B0h] BYREF
  __m128 v89; // [rsp+60h] [rbp-A0h] BYREF
  __m128 v90; // [rsp+70h] [rbp-90h] BYREF
  __m128 v91; // [rsp+80h] [rbp-80h] BYREF
  __m128 v92; // [rsp+90h] [rbp-70h] BYREF
  __m128 v93; // [rsp+A0h] [rbp-60h] BYREF
  __m128 v94; // [rsp+B0h] [rbp-50h] BYREF
  __m128 v95; // [rsp+C0h] [rbp-40h] BYREF
  __m128 v96; // [rsp+D0h] [rbp-30h] BYREF
  wchar_t Source[8]; // [rsp+E0h] [rbp-20h] BYREF
  wchar_t v98[8]; // [rsp+F0h] [rbp-10h] BYREF
  wchar_t v99[8]; // [rsp+100h] [rbp+0h] BYREF
  wchar_t v100[8]; // [rsp+110h] [rbp+10h] BYREF
  wchar_t v101[8]; // [rsp+120h] [rbp+20h] BYREF
  __m128 v102; // [rsp+130h] [rbp+30h] BYREF
  wchar_t v103[8]; // [rsp+140h] [rbp+40h] BYREF
  __m128 v104; // [rsp+150h] [rbp+50h] BYREF
  wchar_t v105[8]; // [rsp+160h] [rbp+60h] BYREF
  __m128 v106; // [rsp+170h] [rbp+70h] BYREF
  wchar_t v107[8]; // [rsp+180h] [rbp+80h] BYREF
  __m128 v108; // [rsp+190h] [rbp+90h] BYREF
  wchar_t SubStr[8]; // [rsp+1A0h] [rbp+A0h] BYREF
  __m128 v110; // [rsp+1B0h] [rbp+B0h]
  __m128 v111; // [rsp+1C0h] [rbp+C0h] BYREF
  __m128 v112; // [rsp+1D0h] [rbp+D0h] BYREF
  __m128 v113; // [rsp+1E0h] [rbp+E0h] BYREF
  __m128 v114; // [rsp+1F0h] [rbp+F0h] BYREF
  wchar_t v115[8]; // [rsp+200h] [rbp+100h] BYREF
  __m128 v116; // [rsp+210h] [rbp+110h] BYREF
  wchar_t v117[8]; // [rsp+220h] [rbp+120h] BYREF
  __m128 v118; // [rsp+230h] [rbp+130h] BYREF
  __m128 v119; // [rsp+240h] [rbp+140h] BYREF
  wchar_t v120[8]; // [rsp+250h] [rbp+150h] BYREF
  __m128 v121; // [rsp+260h] [rbp+160h] BYREF
  __m128 v122; // [rsp+270h] [rbp+170h] BYREF
  __m128 v123; // [rsp+280h] [rbp+180h] BYREF
  __m128 v124; // [rsp+290h] [rbp+190h] BYREF
  __m128 v125; // [rsp+2A0h] [rbp+1A0h] BYREF
  wchar_t v126[8]; // [rsp+2B0h] [rbp+1B0h] BYREF
  __m128 v127; // [rsp+2C0h] [rbp+1C0h] BYREF
  __m128 v128; // [rsp+2D0h] [rbp+1D0h] BYREF
  wchar_t v129[8]; // [rsp+2E0h] [rbp+1E0h] BYREF
  __m128 v130; // [rsp+2F0h] [rbp+1F0h] BYREF
  __m128 v131; // [rsp+300h] [rbp+200h] BYREF
  wchar_t v132[8]; // [rsp+310h] [rbp+210h] BYREF
  __m128 v133; // [rsp+320h] [rbp+220h] BYREF
  __m128 v134; // [rsp+330h] [rbp+230h] BYREF
  wchar_t v135[8]; // [rsp+340h] [rbp+240h] BYREF
  __m128 v136; // [rsp+350h] [rbp+250h] BYREF
  __m128 v137; // [rsp+360h] [rbp+260h] BYREF
  wchar_t v138[8]; // [rsp+370h] [rbp+270h] BYREF
  __m128 v139; // [rsp+380h] [rbp+280h] BYREF
  __m128 v140; // [rsp+390h] [rbp+290h] BYREF
  __m128 v141; // [rsp+3A0h] [rbp+2A0h] BYREF
  wchar_t v142[8]; // [rsp+3B0h] [rbp+2B0h] BYREF
  __m128 v143; // [rsp+3C0h] [rbp+2C0h] BYREF
  __m128 v144; // [rsp+3D0h] [rbp+2D0h] BYREF
  __m128 v145; // [rsp+3E0h] [rbp+2E0h] BYREF
  wchar_t v146[8]; // [rsp+3F0h] [rbp+2F0h] BYREF
  __m128 v147; // [rsp+400h] [rbp+300h] BYREF
  __m128 v148; // [rsp+410h] [rbp+310h] BYREF
  __m128 v149; // [rsp+420h] [rbp+320h] BYREF
  __int64 (__fastcall *ExAcquireSpinLockExclusiveFn)(void *); // [rsp+430h] [rbp+330h]
  __int64 (__fastcall *ExReleaseSpinLockExclusiveFn)(void *, PVOID); // [rsp+438h] [rbp+338h]
  __int64 (__fastcall *PsGetProcessImageFileNameFn)(struct _KPROCESS *); // [rsp+440h] [rbp+340h]
  __m128 v153; // [rsp+450h] [rbp+350h]
  __m128i v154; // [rsp+460h] [rbp+360h] BYREF
  __m128 v155; // [rsp+470h] [rbp+370h]
  __m128 v156; // [rsp+480h] [rbp+380h]
  __m128 v157; // [rsp+490h] [rbp+390h]
  __m128 v158; // [rsp+4A0h] [rbp+3A0h]
  __m128 v159; // [rsp+4B0h] [rbp+3B0h]
  __m128 v160; // [rsp+4C0h] [rbp+3C0h]
  __m128 v161; // [rsp+4D0h] [rbp+3D0h]
  __m128 v162; // [rsp+4E0h] [rbp+3E0h]
  __m128 v163; // [rsp+4F0h] [rbp+3F0h]
  __m128 v164; // [rsp+500h] [rbp+400h]
  __m128 v165; // [rsp+510h] [rbp+410h]
  __m128 v166; // [rsp+520h] [rbp+420h]
  __m128 v167; // [rsp+530h] [rbp+430h]
  __m128 v168; // [rsp+540h] [rbp+440h]
  __m128 v169; // [rsp+550h] [rbp+450h]
  __m128 v170; // [rsp+560h] [rbp+460h]
  __m128 v171; // [rsp+570h] [rbp+470h]
  __m128 v172; // [rsp+580h] [rbp+480h]
  __m128 v173; // [rsp+590h] [rbp+490h]
  __m128 v174; // [rsp+5A0h] [rbp+4A0h]
  __m128 v175; // [rsp+5B0h] [rbp+4B0h]
  __m128 v176; // [rsp+5C0h] [rbp+4C0h]
  __m128 v177; // [rsp+5D0h] [rbp+4D0h]
  __m128 v178; // [rsp+5E0h] [rbp+4E0h]
  __m128 v179; // [rsp+5F0h] [rbp+4F0h]
  __m128 v180; // [rsp+600h] [rbp+500h]
  __m128 v181; // [rsp+610h] [rbp+510h]
  __m128 v182; // [rsp+620h] [rbp+520h]
  __m128 v183; // [rsp+630h] [rbp+530h]
  __m128 v184; // [rsp+640h] [rbp+540h]
  __m128 v185; // [rsp+650h] [rbp+550h]
  __m128 v186; // [rsp+660h] [rbp+560h]
  __m128 v187; // [rsp+670h] [rbp+570h]
  __m128 v188; // [rsp+680h] [rbp+580h]
  __m128 v189; // [rsp+690h] [rbp+590h]
  __m128 v190; // [rsp+6A0h] [rbp+5A0h]
  __m128 v191; // [rsp+6B0h] [rbp+5B0h]
  __m128 v192; // [rsp+6C0h] [rbp+5C0h]
  __m128 v193; // [rsp+6D0h] [rbp+5D0h]
  __m128 v194; // [rsp+6E0h] [rbp+5E0h]
  __m128 v195; // [rsp+6F0h] [rbp+5F0h]
  __m128 v196; // [rsp+700h] [rbp+600h]
  __m128 v197; // [rsp+710h] [rbp+610h]
  __m128 v198; // [rsp+720h] [rbp+620h]
  __m128 v199; // [rsp+730h] [rbp+630h]
  __m128 v200; // [rsp+740h] [rbp+640h]
  __m128 v201; // [rsp+750h] [rbp+650h]
  char v202[16]; // [rsp+760h] [rbp+660h] BYREF
  wchar_t DllPath[304]; // [rsp+770h] [rbp+670h] BYREF
  wchar_t Str[300]; // [rsp+9D0h] [rbp+8D0h] BYREF
  char v205[300]; // [rsp+C28h] [rbp+B28h] BYREF
  int v206; // [rsp+D54h] [rbp+C54h]
  PVOID v207; // [rsp+D58h] [rbp+C58h]
  SIZE_T v208; // [rsp+D60h] [rbp+C60h]
  HANDLE ThreadHandle; // [rsp+DB0h] [rbp+CB0h] BYREF
  __int64 (__fastcall *ExAllocatePoolWithTagFn)(_QWORD, __int64, _QWORD); // [rsp+DC8h] [rbp+CC8h]

  _InterlockedIncrement(&g_EmacReferenceCount);
  memset(Str, 0, sizeof(Str));
  memset(v205, 0, sizeof(v205));
  v207 = 0i64;
  v206 = 0;
  v208 = 0i64;
  result = KeGetCurrentIrql();
  if ( !g_EmacNotReady && imageInfo )
  {
    if ( (imageInfo->ImageInfo.Properties & 0x400) != 0 )
    {
      FileObject = imageInfo->FileObject;
      if ( FileObject )
      {
        p_FileName = &FileObject->FileName;
        if ( IsUnicodeStringValid(p_FileName) )
          imageFileName = p_FileName;
      }
    }
    ExAllocatePoolWithTagFn = (__int64 (__fastcall *)(_QWORD, __int64, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessWow64ProcessFn = (__int64 (__fastcall *)(__int64))((PsGetProcessWow64Process ^ qword_FFFFF801BCFACC40) & -(__int64)((PsGetProcessWow64Process ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PsGetProcessImageFileNameFn = (__int64 (__fastcall *)(struct _KPROCESS *))((PsGetProcessImageFileName ^ qword_FFFFF801BCFACC40) & -(__int64)((PsGetProcessImageFileName ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ZwCloseHandleFn = (void (__fastcall *)(HANDLE))((ZwCloseHandle ^ qword_FFFFF801BCFACC40) & -(__int64)((ZwCloseHandle ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExAcquireSpinLockExclusiveFn = (__int64 (__fastcall *)(void *))(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ExReleaseSpinLockExclusiveFn = (__int64 (__fastcall *)(void *, PVOID))(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseSpinLockExclusive ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    IoGetCurrentProcessFn = ((__int64 (__fastcall *)(unsigned __int64))(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))((unsigned __int64)ExAcquireSpinLockExclusive ^ qword_FFFFF801BCFACC40);
    Process = (struct _KPROCESS *)IoGetCurrentProcessFn;
    if ( !PsGetProcessWow64ProcessFn || (IsProcessWow64 = 1, !PsGetProcessWow64ProcessFn(IoGetCurrentProcessFn)) )
      IsProcessWow64 = 0;
    if ( (unsigned int)ProcessId <= 4 && (imageInfo->ImageInfo.Properties & 0x100) != 0 )
    {
      result = (unsigned __int8)EmacCreateModuleEntry(
                                  imageInfo->ImageInfo.ImageBase,
                                  imageInfo->ImageInfo.ImageSize,
                                  imageFileName);
      goto LABEL_78;
    }
    result = g_GameProcessId;
    if ( g_GameProcessId )
    {
      if ( g_GameProcessId == ProcessId )
      {
        result = IsUnicodeStringValid(imageFileName);
        if ( result )
        {
          sub_FFFFF801BCF28DB8(Process);
          if ( (imageFileName->Length & 0xFFFEu) >= 0x256 )
            v13 = 299i64;
          else
            v13 = (unsigned __int64)imageFileName->Length >> 1;
          wcsncpy(Str, imageFileName->Buffer, v13);
          for ( i = 0i64; ; ++i )
          {
            v15 = (imageFileName->Length & 0xFFFEu) >= 0x256 ? 299i64 : (unsigned __int64)imageFileName->Length >> 1;
            if ( i >= v15 )
              break;
            v205[i] = Str[i];
          }
          imageNameLowercase = wcslwr(Str);
          wmemcpy(SubStr, L"擁鑜嫻X艪㚼䊸ω➣游䔦슸ᔓ䏬㰨", 16);
          si128 = (__m128)_mm_load_si128((const __m128i *)SubStr);
          v153.m128_u64[0] = 0x3C5A8F9432649Di64;
          v154.m128i_i64[1] = 0x3C2843EC1513C2B8i64;
          v154.m128i_i64[0] = 0x4526EB856E5427CFi64;
          v18 = _mm_xor_ps((__m128)_mm_load_si128(&v154), v110);
          v153.m128_u64[1] = 0x3AD429636D08206i64;
          v110 = v18;                           // Decrypted UTF-16: ll
          *(__m128 *)SubStr = _mm_xor_ps(si128, v153);
          if ( wcsstr(imageNameLowercase, SubStr) && g_NtdllBase )// L"\ntdll.dll"
          {
            if ( !IsProcessWow64 )
              goto LABEL_29;
            v188.m128_u64[0] = 0x4526EB856E5427CFi64;
            wmemcpy(v132, L"擁鑁嫶O艱㚿䋡Λ⟻済䕒시ᕿ䎀㰆끥젨惗⎠⭪볋ቂ⺦", 24);
            v19 = (__m128)_mm_load_si128((const __m128i *)v132);
            v187.m128_u64[0] = 0x3C5A8F9432649Di64;
            v20 = (__m128)_mm_load_si128((const __m128i *)&v133);
            v188.m128_u64[1] = 0x3C2843EC1513C2B8i64;
            v187.m128_u64[1] = 0x3AD429636D08206i64;
            *(__m128 *)v132 = _mm_xor_ps(v19, v187);// Decrypted Raw (unprintable): 0e 43 15 fa 73 b1 69 45 77 00 6f 00 77 00 36 00
            v21 = (__m128)_mm_load_si128((const __m128i *)&v134);
            v189.m128_u64[0] = 0x23A060BBC844B001i64;
            v189.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
            v134 = _mm_xor_ps(v21, v189);       // Decrypted Raw (unprintable): f8 d4 1a 5c 58 3a 9c 23 00 00 00 00 00 00 00 00
            v133 = _mm_xor_ps(v20, v188);       // Decrypted UTF-16: 4\ntdll.
            if ( wcsstr(imageNameLowercase, v132) )// L"ntdll.dll"
            {
LABEL_29:
              ZwCloseHandleFn_8.m128_u64[1] = 0x3AD429636D08206i64;
              g_NtdllBase = (__int64)imageInfo->ImageInfo.ImageBase;
              g_NtdllSize = imageInfo->ImageInfo.ImageSize;
              v88.m128_u64[0] = 0x44583BE0D84000D1i64;
              v88.m128_u64[1] = 0x3AD429636D0EE6Ai64;
              ZwCloseHandleFn_8.m128_u64[0] = 0x3C5A8F9432649Di64;
              v88 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v88), ZwCloseHandleFn_8);
              Ntdll_LdrLoadDll = FindProcedureAddress(IsProcessWow64 != 1, Process, g_NtdllBase, (const char *)&v88);
              ZwCloseHandleFn_8.m128_u64[0] = 0x3C5A8F9432649Di64;
              v89.m128_u64[0] = 0x6B5D3FFDD65506D9i64;
              ZwCloseHandleFn_8.m128_u64[1] = 0x3AD429636D08206i64;
              v89.m128_u64[1] = 0x3AD42E258B9ED56i64;
              v89 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v89), ZwCloseHandleFn_8);// Decrypted UTF-8: DbgBreakPoint
              Ntdll_DbgBreakPoint = FindProcedureAddress(IsProcessWow64 != 1, Process, g_NtdllBase, (const char *)&v89);
              v112.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v111.m128_u64[0] = 0x6D5908E6C15506D9i64;
              v155.m128_u64[0] = 0x3C5A8F9432649Di64;
              v111.m128_u64[1] = 0x68CC27E474B5F669i64;
              v22 = (__m128)_mm_load_si128((const __m128i *)&v111);
              v112.m128_u64[0] = 0x4526EB856E5449A6i64;
              v23 = (__m128)_mm_load_si128((const __m128i *)&v112);
              v155.m128_u64[1] = 0x3AD429636D08206i64;
              v156.m128_u64[0] = 0x4526EB856E5427CFi64;
              v156.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v112 = _mm_xor_ps(v23, v156);
              v111 = _mm_xor_ps(v22, v155);     // Decrypted UTF-8: DbgUiRemoteBreak
              Ntdll_DbgUiRemoteBreakin = FindProcedureAddress(
                                           IsProcessWow64 != 1,
                                           Process,
                                           g_NtdllBase,
                                           (const char *)&v111);
              v114.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v113.m128_u64[0] = 0x424E3FFCC15506D9i64;
              v113.m128_u64[1] = 0x6DC42DC65DB1E774i64;
              v24 = (__m128)_mm_load_si128((const __m128i *)&v113);
              v114.m128_u64[0] = 0x4526EB856E5427BBi64;
              v25 = (__m128)_mm_load_si128((const __m128i *)&v114);
              v157.m128_u64[0] = 0x3C5A8F9432649Di64;
              v157.m128_u64[1] = 0x3AD429636D08206i64;
              v158.m128_u64[0] = 0x4526EB856E5427CFi64;
              v158.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v114 = _mm_xor_ps(v25, v158);
              v113 = _mm_xor_ps(v24, v157);     // Decrypted UTF-8: DbgUserBreakPoin
              Ntdll_DbgUserBreakPoint = FindProcedureAddress(
                                          IsProcessWow64 != 1,
                                          Process,
                                          g_NtdllBase,
                                          (const char *)&v113);
            }
            goto LABEL_69;
          }
          v159.m128_u64[1] = 0x3AD429636D08206i64;
          wmemcpy(v115, L"擁鑙嫪N艨㚵䋺Ξ⟽湺䕊싔ᔓ䏬㰨", 16);
          v26 = (__m128)_mm_load_si128((const __m128i *)v115);
          v159.m128_u64[0] = 0x3C5A8F9432649Di64;
          v160.m128_u64[0] = 0x4526EB856E5427CFi64;
          v27 = (__m128)_mm_load_si128((const __m128i *)&v116);
          v160.m128_u64[1] = 0x3C2843EC1513C2B8i64;
          v116 = _mm_xor_ps(v27, v160);         // Decrypted UTF-16: 2.dll
          *(__m128 *)v115 = _mm_xor_ps(v26, v159);// Decrypted UTF-16: \kernel3
          if ( wcsstr(imageNameLowercase, v115) && !g_Kernel32Base )// L"\kernel32.dll"
          {
            if ( !IsProcessWow64 )
              goto LABEL_34;
            v169.m128_u64[1] = 0x3AD429636D08206i64;
            wmemcpy(v135, L"擁鑁嫶O艱㚿䋡Λ⟻済䕃싊ᕽ䎉㱄뀲졶悕⏄⬆벧ቂ⺦", 24);
            v169.m128_u64[0] = 0x3C5A8F9432649Di64;
            *(__m128 *)v135 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v135), v169);// Decrypted UTF-16: \syswow6
            v28 = (__m128)_mm_load_si128((const __m128i *)&v136);
            v29 = (__m128)_mm_load_si128((const __m128i *)&v137);
            v170.m128_u64[0] = 0x4526EB856E5427CFi64;
            v170.m128_u64[1] = 0x3C2843EC1513C2B8i64;
            v171.m128_u64[0] = 0x23A060BBC844B001i64;
            v171.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
            v136 = _mm_xor_ps(v28, v170);       // Decrypted Raw (unprintable): 66 43 3a fa 61 b1 7f 45 72 00 6e 00 65 00 6c 00
            v137 = _mm_xor_ps(v29, v171);       // Decrypted Raw (unprintable): af d4 44 5c 1a 3a f8 23 6c 00 6c 00 00 00 00 00
            if ( wcsstr(imageNameLowercase, v135) )// L"\kernel32.dll"
            {
LABEL_34:
              ImageBase = imageInfo->ImageInfo.ImageBase;
              ZwCloseHandleFna.m128_u64[1] = 0x3AD429636D08206i64;
              v87.m128_u64[0] = 0x725E33C3F0530BD1i64;
              g_Kernel32Base = (__int64)ImageBase;
              g_Kernel32Size = imageInfo->ImageInfo.ImageSize;
              v87.m128_u64[1] = 0x3AD429677A9F067i64;
              ZwCloseHandleFna.m128_u64[0] = 0x3C5A8F9432649Di64;
              v87 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v87), ZwCloseHandleFna);// Decrypted UTF-8: LoadLibraryA
              ProcedureAddress = FindProcedureAddress(
                                   IsProcessWow64 != 1,
                                   Process,
                                   (unsigned __int64)ImageBase,
                                   (const char *)&v87);
              v91.m128_u64[0] = 0x725E33C3F0530BD1i64;
              Kernel32_LoadLibraryA = ProcedureAddress;
              ZwCloseHandleFna.m128_u64[0] = 0x3C5A8F9432649Di64;
              v91.m128_u64[1] = 0x3AD429661A9F067i64;
              ZwCloseHandleFna.m128_u64[1] = 0x3AD429636D08206i64;
              v91 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v91), ZwCloseHandleFna);// Decrypted UTF-8: LoadLibraryW
              v32 = FindProcedureAddress(IsProcessWow64 != 1, Process, g_Kernel32Base, (const char *)&v91);
              v92.m128_u64[0] = 0x725E33C3F0530BD1i64;
              Kernel32_LoadLibraryW = v32;
              ZwCloseHandleFna.m128_u64[0] = 0x3C5A8F9432649Di64;
              v92.m128_u64[1] = 0x3AD03EE73A9F067i64;
              ZwCloseHandleFna.m128_u64[1] = 0x3AD429636D08206i64;
              v92 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v92), ZwCloseHandleFna);// Decrypted UTF-8: LoadLibraryExA
              v33 = FindProcedureAddress(IsProcessWow64 != 1, Process, g_Kernel32Base, (const char *)&v92);
              v93.m128_u64[0] = 0x725E33C3F0530BD1i64;
              Kernel32_LoadLibraryExA = v33;
              ZwCloseHandleFna.m128_u64[0] = 0x3C5A8F9432649Di64;
              v93.m128_u64[1] = 0x3AD15EE73A9F067i64;
              ZwCloseHandleFna.m128_u64[1] = 0x3AD429636D08206i64;
              v93 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v93), ZwCloseHandleFna);// Decrypted UTF-8: LoadLibraryExW
              Kernel32_LoadLibraryExW = FindProcedureAddress(
                                          IsProcessWow64 != 1,
                                          Process,
                                          g_Kernel32Base,
                                          (const char *)&v93);
            }
            goto LABEL_69;
          }
          v161.m128_u64[1] = 0x3AD429636D08206i64;
          wmemcpy(v101, L"擁鑙嫪N艨㚵䋺Ϗ➮渧䔈시ᕿ䎀㰨", 16);
          v34 = (__m128)_mm_load_si128((const __m128i *)v101);
          v35 = (__m128)_mm_load_si128((const __m128i *)&v102);
          v161.m128_u64[0] = 0x3C5A8F9432649Di64;
          v162.m128_u64[0] = 0x4526EB856E5427CFi64;
          v162.m128_u64[1] = 0x3C2843EC1513C2B8i64;
          v102 = _mm_xor_ps(v35, v162);         // Decrypted UTF-16: ase.dll
          *(__m128 *)v101 = _mm_xor_ps(v34, v161);// Decrypted UTF-16: \ker
          if ( wcsstr(imageNameLowercase, v101) && !g_KernelBaseWow64Base )// L"\kernelbase.dll"
          {
            if ( !IsProcessWow64 )
              goto LABEL_39;
            v190.m128_u64[1] = 0x3AD429636D08206i64;
            wmemcpy(
              v138,
              L"擁鑁嫶O艱㚿䋡Λ⟻済䕃싊ᕽ䎉㱄끣젥惈⏅⭄벯ሮ⻊䰌戜발䕘设",
              32);
            v36 = (__m128)_mm_load_si128((const __m128i *)v138);
            v190.m128_u64[0] = 0x3C5A8F9432649Di64;
            v37 = (__m128)_mm_load_si128((const __m128i *)&v139);
            v191.m128_u64[0] = 0x4526EB856E5427CFi64;
            v191.m128_u64[1] = 0x3C2843EC1513C2B8i64;
            *(__m128 *)v138 = _mm_xor_ps(v36, v190);// Decrypted UTF-16: \syswow6
            v38 = (__m128)_mm_load_si128((const __m128i *)&v140);
            v139 = _mm_xor_ps(v37, v191);       // Decrypted Raw (unprintable): 66 43 3a fa 61 b1 7f 45 72 00 6e 00 65 00 6c 00
            v39 = (__m128)_mm_load_si128((const __m128i *)&v141);
            v193.m128_u64[0] = 0x4C0CE831EFE5F533i64;
            v192.m128_u64[0] = 0x23A060BBC844B001i64;
            v192.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
            v193.m128_u64[1] = 0x8BBE4558BC1C621Cui64;
            v141 = _mm_xor_ps(v39, v193);       // Decrypted Raw (unprintable): ae 91 d7 7b be b2 30 4c 00 00 00 00 00 00 00 00
            v140 = _mm_xor_ps(v38, v192);       // Decrypted Raw (unprintable): fe d4 17 5c 47 3a f9 23 2e 00 64 00 6c 00 6c 00
            if ( wcsstr(imageNameLowercase, v138) )// L"\SysWOW64\kernelbase.dll"
            {
LABEL_39:
              v40 = imageInfo->ImageInfo.ImageBase;
              ZwCloseHandleFnb.m128_u64[1] = 0x3AD429636D08206i64;
              v94.m128_u64[0] = 0x725E33C3F0530BD1i64;
              g_KernelBaseWow64Base = (__int64)v40;
              g_KernelBaseWow64Size = imageInfo->ImageInfo.ImageSize;
              v94.m128_u64[1] = 0x3AD429677A9F067i64;
              ZwCloseHandleFnb.m128_u64[0] = 0x3C5A8F9432649Di64;
              v94 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v94), ZwCloseHandleFnb);// Decrypted Raw (unprintable): 10 6f 0a 64 29 69 10 72 61 72 79 41 00 00 00 00
              v41 = FindProcedureAddress(IsProcessWow64 != 1, Process, (unsigned __int64)v40, (const char *)&v94);
              v95.m128_u64[0] = 0x725E33C3F0530BD1i64;
              KERNELBASE_LoadLibraryA_Wow64 = v41;
              ZwCloseHandleFnb.m128_u64[0] = 0x3C5A8F9432649Di64;
              v95.m128_u64[1] = 0x3AD429661A9F067i64;
              ZwCloseHandleFnb.m128_u64[1] = 0x3AD429636D08206i64;
              v95 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v95), ZwCloseHandleFnb);// Decrypted UTF-8: LoadLibraryW
              v42 = FindProcedureAddress(IsProcessWow64 != 1, Process, g_KernelBaseWow64Base, (const char *)&v95);
              v96.m128_u64[0] = 0x725E33C3F0530BD1i64;
              KERNELBASE_LoadLibraryW_Wow64 = v42;
              ZwCloseHandleFnb.m128_u64[0] = 0x3C5A8F9432649Di64;
              v96.m128_u64[1] = 0x3AD03EE73A9F067i64;
              ZwCloseHandleFnb.m128_u64[1] = 0x3AD429636D08206i64;
              v96 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v96), ZwCloseHandleFnb);// Decrypted UTF-8: LoadLibraryExA
              v90.m128_u64[0] = 0x725E33C3F0530BD1i64;
              KERNELBASE_LoadLibraryExA_Wow64 = FindProcedureAddress(
                                                  IsProcessWow64 != 1,
                                                  Process,
                                                  g_KernelBaseWow64Base,
                                                  (const char *)&v96);
              ZwCloseHandleFnb.m128_u64[0] = 0x3C5A8F9432649Di64;
              v90.m128_u64[1] = 0x3AD15EE73A9F067i64;
              ZwCloseHandleFnb.m128_u64[1] = 0x3AD429636D08206i64;
              v90 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v90), ZwCloseHandleFnb);// Decrypted UTF-8: LoadLibraryExW
              KERNELBASE_LoadLibraryExW_Wow64 = FindProcedureAddress(
                                                  IsProcessWow64 != 1,
                                                  Process,
                                                  g_KernelBaseWow64Base,
                                                  (const char *)&v90);
            }
            goto LABEL_69;
          }
          v163.m128_u64[1] = 0x3AD429636D08206i64;
          v104.m128_u64[1] = 0x3C2843EC1513C2B8i64;
          v164.m128_u64[1] = 0x3C2843EC1513C2B8i64;
          *(_QWORD *)v103 = 0x595AFC944764C1i64;
          *(_QWORD *)&v103[4] = 0x38342A436E38274i64;
          v43 = (__m128)_mm_load_si128((const __m128i *)v103);
          v104.m128_u64[0] = 0x4526EBE96E3827ABi64;
          v44 = (__m128)_mm_load_si128((const __m128i *)&v104);
          v163.m128_u64[0] = 0x3C5A8F9432649Di64;
          v164.m128_u64[0] = 0x4526EB856E5427CFi64;
          v104 = _mm_xor_ps(v44, v164);         // Decrypted UTF-16: dll
          *(__m128 *)v103 = _mm_xor_ps(v43, v163);// Decrypted Raw (unprintable): 5c 00 75 00 73 00 65 00 61 72 79 41 00 00 00 00
          if ( !wcsstr(imageNameLowercase, v103) || g_EMACWow64Base )
          {
            v86.m128_u64[1] = 0x3AD429636D08206i64;
            wmemcpy(v100, L"擁鑗嫢]艥㚌䊖έ", 8);
            v86.m128_u64[0] = 0x3C5A8F9432649Di64;
            *(__m128 *)v100 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v100), v86);// Decrypted UTF-16: \emac\
            if ( !wcsstr(imageNameLowercase, v100) || g_EMACBase )
            {
              v194.m128_u64[1] = 0x3AD429636D08206i64;
              wmemcpy(
                v142,
                L"擁鑑嫼[艩㚌䋴τ➡済䕏싖ᔥ䏘㱴끢젨惒⏅⬄벿ቬ⻂䰌戜발䕘设",
                32);
              v194.m128_u64[0] = 0x3C5A8F9432649Di64;
              v67 = (__m128)_mm_load_si128((const __m128i *)&v143);
              *(__m128 *)v142 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v142), v194);// Decrypted Raw (unprintable): 5c 00 63 00 73 00 67 00 03 a9 47 8a b6 50 62 2d
              v68 = (__m128)_mm_load_si128((const __m128i *)&v144);
              v195.m128_u64[0] = 0x4526EB856E5427CFi64;
              v195.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v143 = _mm_xor_ps(v67, v195);     // Decrypted Raw (unprintable): 3c 43 3a fa 7d b1 73 45 6e 00 36 00 34 00 5c 00
              v69 = (__m128)_mm_load_si128((const __m128i *)&v145);
              v196.m128_u64[0] = 0x23A060BBC844B001i64;
              v196.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
              v197.m128_u64[0] = 0x4C0CE831EFE5F533i64;
              v197.m128_u64[1] = 0x8BBE4558BC1C621Cui64;
              v145 = _mm_xor_ps(v69, v197);     // Decrypted Raw (unprintable): 5e 45 cd 27 8a 88 ac 6f 00 00 00 00 00 00 00 00
              v144 = _mm_xor_ps(v68, v196);     // Decrypted Raw (unprintable): ad 97 7c a6 57 8b e3 66 6e 00 74 00 2e 00 64 00
              if ( wcsstr(imageNameLowercase, v142) )// \csgo\bin
              {
                g_Cs2Base = (__int64)imageInfo->ImageInfo.ImageBase;
                g_Cs2Size = imageInfo->ImageInfo.ImageSize;
              }
              else
              {
                wmemcpy(
                  v146,
                  L"擁鑕嫮Q艣㚌䋴τ➡済䕏싖ᔥ䏘㱴끤젪惜⏉⬄벮ተ⺈䰌戜발䕘设",
                  32);
                v198.m128_u64[0] = 0x3C5A8F9432649Di64;
                v70 = (__m128)_mm_load_si128((const __m128i *)v146);
                v71 = (__m128)_mm_load_si128((const __m128i *)&v147);
                v198.m128_u64[1] = 0x3AD429636D08206i64;
                v199.m128_u64[0] = 0x4526EB856E5427CFi64;
                *(__m128 *)v146 = _mm_xor_ps(v70, v198);// Decrypted UTF-16: \game\bi
                v72 = (__m128)_mm_load_si128((const __m128i *)&v148);
                v199.m128_u64[1] = 0x3C2843EC1513C2B8i64;
                v147 = _mm_xor_ps(v71, v199);   // Decrypted UTF-16: n\win64\
                v73 = (__m128)_mm_load_si128((const __m128i *)&v149);
                v200.m128_u64[0] = 0x23A060BBC844B001i64;
                v200.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
                v201.m128_u64[0] = 0x4C0CE831EFE5F533i64;
                v201.m128_u64[1] = 0x8BBE4558BC1C621Cui64;
                v149 = _mm_xor_ps(v73, v201);   // Decrypted UTF-16: dll
                v148 = _mm_xor_ps(v72, v200);   // Decrypted UTF-16: engine2.
                if ( wcsstr(imageNameLowercase, v146) )
                {
                  g_Engine2Base = (__int64)imageInfo->ImageInfo.ImageBase;
                  g_Engine2Size = imageInfo->ImageInfo.ImageSize;
                }
              }
            }
            else
            {
              wmemcpy(v105, L"擁鑗嫢]艥㛽䋵Ϟ➨渻䔦슸ᔓ䏬㰨", 16);
              v165.m128_u64[0] = 0x3C5A8F9432649Di64;
              v63 = (__m128)_mm_load_si128((const __m128i *)v105);
              v64 = (__m128)_mm_load_si128((const __m128i *)&v106);
              v165.m128_u64[1] = 0x3AD429636D08206i64;
              v166.m128_u64[0] = 0x4526EB856E5427CFi64;
              v166.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v106 = _mm_xor_ps(v64, v166);     // Decrypted Raw (unprintable): 67 00 6f 00 2d 00 00 00 df 32 ba 66 02 56 85 3f
              *(__m128 *)v105 = _mm_xor_ps(v63, v165);// Decrypted Raw (unprintable): 5c 00 65 00 6d 00 61 00 3c c6 72 e4 a0 50 0b 2d
              if ( wcsstr(imageNameLowercase, v105) )
                goto LABEL_64;
              v167.m128_u64[0] = 0x3C5A8F9432649Di64;
              wmemcpy(v107, L"擁鑗嫢]艥㛽䋵ρ➦渱䕒슕ᔓ䏬㰨", 16);
              v167.m128_u64[1] = 0x3AD429636D08206i64;
              v65 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v107), v167);
              v66 = (__m128)_mm_load_si128((const __m128i *)&v108);
              v168.m128_u64[0] = 0x4526EB856E5427CFi64;
              v168.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v108 = _mm_xor_ps(v66, v168);     // Decrypted UTF-16: ient-
              *(__m128 *)v107 = v65;            // Decrypted Raw (unprintable): 5c 00 65 00 6d 00 61 00 0f a9 36 8a b7 50 67 2d
              if ( wcsstr(imageNameLowercase, v107) )// L"\emac-cs"
LABEL_64:
                g_EMACBase = (__int64)imageInfo->ImageInfo.ImageBase;
            }
            goto LABEL_69;
          }
          v45.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
          v45.m128_u64[0] = 0x23CC60D7C820B02Fi64;
          if ( IsProcessWow64 )
          {
            v119 = v45;
            wmemcpy(v117, L"擁鑁嫶O艱㚿䋡Λ⟻済䕕식ᕡ䏟㰚", 16);
            v174.m128_u64[0] = 0x23A060BBC844B001i64;
            v46 = (__m128)_mm_load_si128((const __m128i *)v117);
            v47 = (__m128)_mm_load_si128((const __m128i *)&v118);
            v172.m128_u64[0] = 0x3C5A8F9432649Di64;
            v172.m128_u64[1] = 0x3AD429636D08206i64;
            v173.m128_u64[0] = 0x4526EB856E5427CFi64;
            *(__m128 *)v117 = _mm_xor_ps(v46, v172);// Decrypted Raw (unprintable): 0e 43 15 fa 73 b1 69 45 77 00 6f 00 77 00 36 00
            v48 = (__m128)_mm_load_si128((const __m128i *)&v119);
            v173.m128_u64[1] = 0x3C2843EC1513C2B8i64;
            v174.m128_u64[1] = v45.m128_u64[1];
            v118 = _mm_xor_ps(v47, v173);       // Decrypted Raw (unprintable): 66 43 3a fa 7f b1 69 45 65 00 72 00 33 00 32 00
            v119 = _mm_xor_ps(v48, v174);       // Decrypted UTF-16: .dll
            if ( !wcsstr(imageNameLowercase, v117) )
              goto LABEL_69;
          }
          g_EMACWow64Base = (__int64)imageInfo->ImageInfo.ImageBase;
          if ( !ExAllocatePoolWithTagFn((unsigned int)g_EmacPoolType, 0x58i64, 'CAME') )
          {
LABEL_69:
            ImageSize = imageInfo->ImageInfo.ImageSize;
            v207 = imageInfo->ImageInfo.ImageBase;
            v208 = ImageSize;
            if ( (unsigned __int64)v207 < qword_FFFFF801BCFAC258
              || (result = ImageSize + (_BYTE)v207, (unsigned __int64)v207 + ImageSize > qword_FFFFF801BCFAC260) )
            {
              v75 = ExAcquireSpinLockExclusiveFn(&unk_FFFFF801BCFAC430);
              v77 = qword_FFFFF801BCFAC438;
              v78 = v75;
              if ( qword_FFFFF801BCFAC438 != qword_FFFFF801BCFAC440 )
              {
                v76 = v207;
                do
                {
                  if ( *(PVOID *)(v77 + 0x388) == v207 )
                    break;
                  v77 += 0x398i64;
                }
                while ( v77 != qword_FFFFF801BCFAC440 );
              }
              if ( v77 == qword_FFFFF801BCFAC440 )
              {
                sub_FFFFF801BCEF0760((__int64)&qword_FFFFF801BCFAC438, v202, v77, Str);
                _InterlockedIncrement(&dword_FFFFF801BCFAC26C);
              }
              LOBYTE(v76) = v78;
              result = ExReleaseSpinLockExclusiveFn(&unk_FFFFF801BCFAC430, v76);
            }
            goto LABEL_78;
          }
          memset(DllPath, 0, 0x258ui64);
          wmemcpy(Source, L"擁鐍媰`舆㛐䊖έ", 8);
          v83.m128_u64[0] = 0x3C5A8F9432649Di64;
          v83.m128_u64[1] = 0x3AD429636D08206i64;
          *(__m128 *)Source = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)Source), v83);// Decrypted Raw (unprintable): 5c 00 3f 00 3f 00 5c 00 da 40 af 23 16 01 85 3f
          wcsncpy(DllPath, Source, 299ui64);
          wcsncat(DllPath, &::Source, 299ui64);
          if ( PsGetProcessImageFileNameFn(Process) )
          {
            ProcessFileNameHash = EmacGetProcessFileNameHash(ProcessId);
            if ( ProcessFileNameHash != 0x3105807B && ProcessFileNameHash != 0x29B90D41 )// csgo.exe and cs2.exe hash
            {
              if ( IsProcessWow64 )
                EMACDllPath = (__m128 *)L"\\EMAC-Client-x86.dll";
              else
                EMACDllPath = (__m128 *)L"\\EMAC-Client-x64.dll";
              goto LABEL_57;
            }
            if ( !IsProcessWow64 )
            {
              wmemcpy(v126, L"擁鑷嫂}艅㛽䋕Ͼ➈減䕞슎ᔧ䏂㱌끭젨悻⎠⭪볋ቂ⺦", 24);
              v57 = (__m128)_mm_load_si128((const __m128i *)v126);
              v58 = (__m128)_mm_load_si128((const __m128i *)&v127);
              v182.m128_u64[0] = 0x4526EB856E5427CFi64;
              v182.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v181.m128_u64[0] = 0x3C5A8F9432649Di64;
              v181.m128_u64[1] = 0x3AD429636D08206i64;
              *(__m128 *)v126 = _mm_xor_ps(v57, v181);// Decrypted Raw (unprintable): 0e 43 23 fa 47 b1 5b 45 be 40 c3 23 7a 01 85 3f
              v59 = (__m128)_mm_load_si128((const __m128i *)&v128);
              v183.m128_u64[0] = 0x23A060BBC844B001i64;
              v183.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
              v127 = _mm_xor_ps(v58, v182);     // Decrypted Raw (unprintable): 89 97 5f a6 13 8b fe 66 36 00 34 00 2e 00 64 00
              v128 = _mm_xor_ps(v59, v183);     // Decrypted Raw (unprintable): f0 d4 1a 5c 34 3a 9c 23 00 00 00 00 00 00 00 00
              wcsncat(DllPath, v126, 299ui64);  // L"\EMAC-CSGO-x64.dll"
              if ( (EmacTryCreateFile(DllPath) & 0xC0000000) != 0xC0000000 )
                goto LABEL_58;
              v85.m128_u64[0] = 0x3C5A8F9432649Di64;
              wmemcpy(v99, L"擁鐍媰`舆㛐䊖έ", 8);
              v85.m128_u64[1] = 0x3AD429636D08206i64;
              *(__m128 *)v99 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v99), v85);// Decrypted UTF-16: \??\
              wcsncpy(DllPath, v99, 0x12Bui64);
              wcsncat(DllPath, &::Source, 0x12Bui64);
              wmemcpy(v129, L"擁鑷嫂}艅㛽䋕ρ➦渱䕒슕ᕫ䏚㰜뀯젠惗⏌⭪볋ቂ⺦", 24);
              EMACDllPath = (__m128 *)v129;
              v60 = (__m128)_mm_load_si128((const __m128i *)v129);
              v61 = (__m128)_mm_load_si128((const __m128i *)&v130);
              v185.m128_u64[0] = 0x4526EB856E5427CFi64;
              v184.m128_u64[0] = 0x3C5A8F9432649Di64;
              v184.m128_u64[1] = 0x3AD429636D08206i64;
              *(__m128 *)v129 = _mm_xor_ps(v60, v184);// Decrypted Raw (unprintable): 0e 43 23 fa 47 b1 5b 45 43 00 2d 00 43 00 6c 00
              v62 = (__m128)_mm_load_si128((const __m128i *)&v131);
              v185.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v186.m128_u64[0] = 0x23A060BBC844B001i64;
              v186.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
              v130 = _mm_xor_ps(v61, v185);     // Decrypted Raw (unprintable): a7 97 75 a6 50 8b f2 66 2d 00 78 00 36 00 34 00
              v131 = _mm_xor_ps(v62, v186);     // Decrypted Raw (unprintable): b2 d4 12 5c 58 3a f0 23 00 00 00 00 00 00 00 00
              goto LABEL_57;
            }
            wmemcpy(v120, L"擁鑷嫂}艅㛽䋕Ͼ➈減䕞슀ᔥ䏂㱌끭젨悻⎠⭪볋ቂ⺦", 24);
            v51 = (__m128)_mm_load_si128((const __m128i *)v120);
            v52 = (__m128)_mm_load_si128((const __m128i *)&v121);
            v176.m128_u64[0] = 0x4526EB856E5427CFi64;
            v176.m128_u64[1] = 0x3C2843EC1513C2B8i64;
            v175.m128_u64[0] = 0x3C5A8F9432649Di64;
            v175.m128_u64[1] = 0x3AD429636D08206i64;
            *(__m128 *)v120 = _mm_xor_ps(v51, v175);// Decrypted UTF-16: \EMAC-CS
            v53 = (__m128)_mm_load_si128((const __m128i *)&v122);
            v177.m128_u64[0] = 0x23A060BBC844B001i64;
            v177.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
            v121 = _mm_xor_ps(v52, v176);       // Decrypted Raw (unprintable): 15 43 29 fa 27 b1 62 45 38 00 36 00 2e 00 64 00
            v122 = _mm_xor_ps(v53, v177);       // Decrypted Raw (unprintable): f0 d4 1a 5c 34 3a 9c 23 00 00 00 00 00 00 00 00
            wcsncat(DllPath, v120, 299ui64);    // L"\EMAC-CSGO-x86.dll"
            if ( (EmacTryCreateFile(DllPath) & 0xC0000000) == 0xC0000000 || !byte_FFFFF801BCFAC6B5 )
            {
              v84.m128_u64[0] = 0x3C5A8F9432649Di64;
              wmemcpy(v98, L"擁鐍媰`舆㛐䊖έ", 8);
              v84.m128_u64[1] = 0x3AD429636D08206i64;
              *(__m128 *)v98 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)v98), v84);// Decrypted UTF-16: \??\
              wcsncpy(DllPath, v98, 0x12Bui64);
              wcsncat(DllPath, &::Source, 0x12Bui64);
              v123.m128_u64[0] = 0x7D5AC2947764C1i64;
              v123.m128_u64[1] = 0x3C142D536FD8245i64;
              EMACDllPath = &v123;
              v54 = (__m128)_mm_load_si128((const __m128i *)&v123);
              v124.m128_u64[0] = 0x4552EBEB6E3127A6i64;
              v124.m128_u64[1] = 0x3C1E43D4156BC295i64;
              v55 = (__m128)_mm_load_si128((const __m128i *)&v124);
              v125.m128_u64[0] = 0x23CC60D7C820B02Fi64;
              v179.m128_u64[0] = 0x4526EB856E5427CFi64;
              v125.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
              v178.m128_u64[0] = 0x3C5A8F9432649Di64;
              v178.m128_u64[1] = 0x3AD429636D08206i64;
              v123 = _mm_xor_ps(v54, v178);     // Decrypted Raw (unprintable): 0e 43 23 fa 47 b1 5b 45 43 00 2d 00 43 00 6c 00
              v56 = (__m128)_mm_load_si128((const __m128i *)&v125);
              v179.m128_u64[1] = 0x3C2843EC1513C2B8i64;
              v180.m128_u64[0] = 0x23A060BBC844B001i64;
              v180.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
              v124 = _mm_xor_ps(v55, v179);     // Decrypted Raw (unprintable): a7 97 75 a6 50 8b f2 66 2d 00 78 00 38 00 36 00
              v125 = _mm_xor_ps(v56, v180);     // Decrypted Raw (unprintable): b2 d4 12 5c 58 3a f0 23 00 00 00 00 00 00 00 00
LABEL_57:
              wcsncat(DllPath, (const wchar_t *)EMACDllPath, 299ui64);// L"\EMAC-Client-x86.dll"
            }
          }
LABEL_58:
          ThreadHandle = 0i64;
          if ( EmacLoadLibrary(Process, DllPath, &ThreadHandle) >= 0 )
            ZwCloseHandleFn(ThreadHandle);
          goto LABEL_69;
        }
      }
    }
  }
LABEL_78:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return result;
}