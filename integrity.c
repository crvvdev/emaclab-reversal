void __fastcall EmacGetThreadStartAddressWorkItem(__int64 a1, _EMAC_WORK_ITEM_CONTEXT *context)
{
  void (__fastcall *KeSetEventFn)(PKEVENT, _QWORD, _QWORD); // rbp
  PIO_WORKITEM WorkItem; // rax
  _WORK_QUEUE_ITEM *Flink; // rdi
  _EMAC_WORK_ITEM_CONTEXT *Parameter; // rsi
  PIO_WORKITEM v7; // rcx
  void *ThreadWin32StartAddress; // rax

  if ( context )
  {
    KeSetEventFn = (void (__fastcall *)(PKEVENT, _QWORD, _QWORD))(((unsigned __int64)KeSetEvent ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeSetEvent ^ qword_FFFFF801BCFACC40)));
    WorkItem = context->WorkItem;
    if ( WorkItem )
    {
      if ( context->Thread )
      {
        Flink = *(_WORK_QUEUE_ITEM **)WorkItem;
        if ( *(_QWORD *)WorkItem )
        {
          if ( Flink == (_WORK_QUEUE_ITEM *)WorkItem )
          {
            while ( Flink != (_WORK_QUEUE_ITEM *)context->WorkItem )
            {
              Parameter = (_EMAC_WORK_ITEM_CONTEXT *)Flink->Parameter;
              if ( IsWindows10() && *(PVOID *)&Parameter[1].Event.Header.Lock == context->Thread
                || (v7 = Parameter->WorkItem) != 0i64 && !EmacGetModuleInfoFromAddress((unsigned __int64)v7, 1) )
              {
                context->Unknown2 = Parameter->WorkItem;
                break;
              }
              Flink = (_WORK_QUEUE_ITEM *)Flink->List.Flink;
              if ( !Flink )
                break;
            }
          }
        }
      }
    }
    ThreadWin32StartAddress = (void *)EmacGetThreadWin32StartAddress(KeGetCurrentThread());
    context->ThreadStartAddress = ThreadWin32StartAddress;
    if ( !EmacIsAddressInCodeSectionRange(
            (unsigned __int64)ThreadWin32StartAddress,
            (_IMAGE_DOS_HEADER *)g_NtoskrnlBase,
            0i64) )
      context->ThreadStartAddress = 0i64;
    KeSetEventFn(&context->Event, 0i64, 0i64);
  }
}

char __fastcall EmacGetThreadStartAddress(PETHREAD Thread, void **a2, void **StartAddress)
{
  char v3; // bl
  void (__fastcall *KeInitializeEventFn)(PKEVENT, _QWORD, _QWORD); // r13
  void (__fastcall *IoQueueWorkItemFn)(struct _IO_WORKITEM *, void (__fastcall *)(__int64, _EMAC_WORK_ITEM_CONTEXT *), __int64, _EMAC_WORK_ITEM_CONTEXT *); // r15
  void (__fastcall *KeWaitForSingleObjectFn)(void *, _QWORD, _QWORD, _QWORD, _QWORD); // r12
  __int64 (__fastcall *ExAllocatePoolWithTagFn)(_QWORD, __int64, _QWORD); // r9
  void (__fastcall *ExFreePoolWithTagFn)(_EMAC_WORK_ITEM_CONTEXT *, _QWORD); // rbp
  _EMAC_WORK_ITEM_CONTEXT *Context; // rax MAPDST
  struct _IO_WORKITEM *workItem; // rax
  __int64 (__fastcall *IoAllocateWorkItemFn)(__int64); // [rsp+78h] [rbp+10h]

  v3 = 0;
  KeInitializeEventFn = (void (__fastcall *)(PKEVENT, _QWORD, _QWORD))(((unsigned __int64)KeInitializeEvent ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeInitializeEvent ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  IoAllocateWorkItemFn = (__int64 (__fastcall *)(__int64))(((unsigned __int64)IoAllocateWorkItem ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoAllocateWorkItem ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  IoQueueWorkItemFn = (void (__fastcall *)(struct _IO_WORKITEM *, void (__fastcall *)(__int64, _EMAC_WORK_ITEM_CONTEXT *), __int64, _EMAC_WORK_ITEM_CONTEXT *))(((unsigned __int64)IoQueueWorkItem ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoQueueWorkItem ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeWaitForSingleObjectFn = (void (__fastcall *)(void *, _QWORD, _QWORD, _QWORD, _QWORD))(((unsigned __int64)KeWaitForSingleObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeWaitForSingleObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExAllocatePoolWithTagFn = (__int64 (__fastcall *)(_QWORD, __int64, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExFreePoolWithTagFn = (void (__fastcall *)(_EMAC_WORK_ITEM_CONTEXT *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( a2 )
    *a2 = 0i64;
  if ( StartAddress )
    *StartAddress = 0i64;
  Context = (_EMAC_WORK_ITEM_CONTEXT *)ExAllocatePoolWithTagFn(0i64, 0x38i64, 'CAME');
  if ( Context )
  {
    *(_OWORD *)&Context->Event.Header.Lock = 0i64;
    *(_OWORD *)&Context->Event.Header.WaitListHead.Blink = 0i64;
    *(_OWORD *)&Context->WorkItem = 0i64;
    Context->ThreadStartAddress = 0i64;
    KeInitializeEventFn(&Context->Event, 0i64, 0i64);
    Context->Thread = Thread;
    Context->ThreadStartAddress = 0i64;
    Context->Unknown2 = 0i64;
    workItem = (struct _IO_WORKITEM *)IoAllocateWorkItemFn(g_EmacDeviceObject);
    Context->WorkItem = workItem;
    if ( workItem )
    {
      IoQueueWorkItemFn(workItem, EmacGetThreadStartAddressWorkItem, 1i64, Context);
      KeWaitForSingleObjectFn(Context, 0i64, 0i64, 0i64, 0i64);
      if ( a2 )
        *a2 = Context->Unknown2;
      if ( StartAddress )
        *StartAddress = Context->ThreadStartAddress;
      if ( Context->Unknown2 || Context->ThreadStartAddress )
        v3 = 1;
    }
    ExFreePoolWithTagFn(Context, 'CAME');
    LOBYTE(Context) = v3;
  }
  return (char)Context;
}

ULONG_PTR *__fastcall EmacVerifyKernelThreadsStackTrace(unsigned __int64 a1, void *a2, unsigned int a3, ULONG64 a4)
{
  ULONG64 v4; // r12
  unsigned int status; // ebx MAPDST
  unsigned int v7; // esi
  int (__fastcall *PsLookupThreadByThreadIdFn)(_QWORD, struct _KTHREAD **); // r13 MAPDST
  void (__fastcall *KeStackAttachProcessFn)(PEPROCESS, __int64 *); // rdi
  int v10; // eax
  void (*ObfDereferenceObjectFn)(void); // r15
  __int64 PsGetCurrentThreadIdFn; // r14 MAPDST
  size_t v14; // r13
  int v16; // ecx
  int OffsetKThreadStackLimit; // eax
  int OffsetKThreadStackBase; // eax
  int OffsetKThreadThreadLock; // eax
  unsigned int OffsetKThreadKernelStack; // eax
  __int64 OffsetKThreadKernelStack_1; // rdi
  unsigned int OffsetKThreadState; // eax
  __int64 OffsetKThreadState_1; // rsi
  int v24; // r14d
  const void **threadInitialStack; // rdi
  _BYTE *threadState; // rsi
  void *threadStackBase; // r15
  __int64 v28; // rdx
  void *threadCurrentStack; // rcx
  int v31; // r15d
  void *CurrentRip; // rdi
  void **Rsp; // rsi
  size_t i; // r14
  __int64 FunctionEntry; // rax
  size_t FrameIndex; // rax
  size_t v38; // r15
  unsigned int StackTraceThreadId; // r13d
  size_t y; // rdi
  unsigned __int64 currentStackFrame; // r14
  EMAC_MODULE_ENTRY *ModuleInfoFromAddress; // rsi
  __m128 si128; // xmm0
  unsigned __int64 lastStackFrame; // rax
  ULONG_PTR v45; // rdi
  unsigned int *v47; // r8
  ULONG_PTR *result; // rax
  bool largePage; // [rsp+40h] [rbp-C0h] BYREF
  int ThreadId; // [rsp+44h] [rbp-BCh]
  char CurrentIrql; // [rsp+48h] [rbp-B8h]
  struct _KTHREAD *Thread; // [rsp+58h] [rbp-A8h] MAPDST BYREF
  ULONG64 poolAddress; // [rsp+60h] [rbp-A0h] MAPDST
  void (*v55)(void); // [rsp+68h] [rbp-98h]
  int v56; // [rsp+70h] [rbp-90h]
  __int64 ImageBase; // [rsp+78h] [rbp-88h] BYREF
  size_t stackFramesCount; // [rsp+80h] [rbp-80h]
  PVOID FrameFileHeader; // [rsp+88h] [rbp-78h] BYREF
  void *HandlerData; // [rsp+A0h] [rbp-60h] BYREF
  char SubStr[16]; // [rsp+B0h] [rbp-50h] BYREF
  wchar_t Str2[8]; // [rsp+C0h] [rbp-40h] BYREF
  __m128 v65; // [rsp+D0h] [rbp-30h]
  unsigned __int8 (__fastcall *PsIsThreadTerminatingFn)(struct _KTHREAD *); // [rsp+E0h] [rbp-20h]
  void *threadStackLimit; // [rsp+E8h] [rbp-18h]
  __int64 (__stdcall *MmGetPhysicalAddressFn)(void *); // [rsp+F0h] [rbp-10h]
  unsigned __int8 (__fastcall *MmIsAddressValidFn_2)(const void *); // [rsp+F8h] [rbp-8h]
  __int64 threadLock; // [rsp+100h] [rbp+0h]
  void (__fastcall *KeReleaseSpinLockFn)(__int64, __int64); // [rsp+108h] [rbp+8h]
  _IMAGE_NT_HEADERS64 *ntoskrnlHeader; // [rsp+110h] [rbp+10h]
  BOOLEAN (__stdcall *MmIsAddressValidFn)(PVOID); // [rsp+118h] [rbp+18h] MAPDST
  __int64 (__fastcall *RtlLookupFunctionTableEntryFn)(void *, __int64 *, _QWORD); // [rsp+120h] [rbp+20h]
  void (__fastcall *RtlVirtualUnwindFn)(_QWORD, __int64, ULONG64, __int64, CONTEXT *, void **, DWORD64 *, _QWORD); // [rsp+128h] [rbp+28h]
  void (__fastcall *ExFreePoolWithTagFn)(ULONG64, _QWORD); // [rsp+130h] [rbp+30h]
  unsigned __int8 (__fastcall *MmIsAddressValidFn_1)(__int64); // [rsp+138h] [rbp+38h]
  void (__fastcall *RtlPcToFileHeaderFn)(unsigned __int64, PVOID *); // [rsp+140h] [rbp+40h]
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+148h] [rbp+48h]
  struct _KTHREAD *CurrentThread; // [rsp+150h] [rbp+50h]
  __int128 EstablisherFrame; // [rsp+158h] [rbp+58h] BYREF
  __int64 (__fastcall *KeAcquireSpinLockRaiseToDpcFn)(__int64); // [rsp+168h] [rbp+68h]
  __m128i v83; // [rsp+170h] [rbp+70h] BYREF
  __m128 v84; // [rsp+180h] [rbp+80h]
  __m128i v85; // [rsp+190h] [rbp+90h] BYREF
  __int64 v86; // [rsp+1A0h] [rbp+A0h] BYREF
  __int128 v87; // [rsp+1A8h] [rbp+A8h]
  __int128 v88; // [rsp+1B8h] [rbp+B8h]
  unsigned __int64 baseAddress; // [rsp+1C8h] [rbp+C8h]
  __int64 stackFrames[32]; // [rsp+1D0h] [rbp+D0h] BYREF
  CONTEXT ContextRecord; // [rsp+2D0h] [rbp+1D0h] BYREF

  v4 = a4;
  status = 0;
  if ( KeGetCurrentIrql() > 1u )
  {
    v47 = (unsigned int *)(a4 + 0x30);
    status = 0xC0000148;
    result = (ULONG_PTR *)(a4 + 0x38);
    v45 = 0i64;
  }
  else
  {
    Thread = 0i64;
    v7 = 8;
    CurrentThread = KeGetCurrentThread();
    ThreadId = 8;
    baseAddress = 0i64;
    v86 = 0i64;
    v87 = 0i64;
    v88 = 0i64;
    memset(stackFrames, 0, sizeof(stackFrames));
    FrameFileHeader = 0i64;
    PsLookupThreadByThreadIdFn = (int (__fastcall *)(_QWORD, struct _KTHREAD **))(((unsigned __int64)PsLookupThreadByThreadId ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)PsLookupThreadByThreadId ^ qword_FFFFF801BCFACC40)));
    KeStackAttachProcessFn = (void (__fastcall *)(PEPROCESS, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40)));
    KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40)));
    RtlPcToFileHeaderFn = (void (__fastcall *)(unsigned __int64, PVOID *))((RtlPcToFileHeader ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < (RtlPcToFileHeader ^ (unsigned __int64)qword_FFFFF801BCFACC40)));
    v10 = *(_DWORD *)(a1 + 0x3F8);
    MmIsAddressValidFn_1 = (unsigned __int8 (__fastcall *)(__int64))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
    v56 = v10;
    ObfDereferenceObjectFn = (void (*)(void))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40)));
    v55 = ObfDereferenceObjectFn;
    if ( v10 >= 2 )
    {
      status = 0xC000000D;
      v45 = 0i64;
    }
    else
    {
      PsGetCurrentThreadIdFn = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40))))();
      KeStackAttachProcessFn(g_AttachedProcess, &v86);
      if ( !g_UnknownThreadStartAddress )
        EmacGetThreadStartAddress(KeGetCurrentThread(), 0i64, &g_UnknownThreadStartAddress);
      do
      {
        if ( *(_BYTE *)(a1 + 2000) || g_EmacNotReady )
          break;
        if ( v7 != (_DWORD)PsGetCurrentThreadIdFn && PsLookupThreadByThreadIdFn(v7, &Thread) >= 0 )
        {
          if ( Thread != CurrentThread && EmacIsSystemThread(Thread) )
          {
            ntoskrnlHeader = RtlImageNtHeader((_IMAGE_DOS_HEADER *)g_NtoskrnlBase);
            ImageBase = 0i64;
            EstablisherFrame = 0ui64;
            v14 = 0i64;
            HandlerData = 0i64;
            memset(&ContextRecord, 0, sizeof(ContextRecord));
            largePage = 0;
            stackFramesCount = 0i64;
            memset(stackFrames, 0, sizeof(stackFrames));
            if ( Thread && ntoskrnlHeader )
            {
              MmIsAddressValidFn = (BOOLEAN (__stdcall *)(PVOID))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
              RtlLookupFunctionTableEntryFn = (__int64 (__fastcall *)(void *, __int64 *, _QWORD))((qword_FFFFF801BCFACC40 ^ RtlLookupFunctionTableEntry) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)RtlLookupFunctionTableEntry)));
              RtlVirtualUnwindFn = (void (__fastcall *)(_QWORD, __int64, ULONG64, __int64, CONTEXT *, void **, DWORD64 *, _QWORD))((qword_FFFFF801BCFACC40 ^ RtlVirtualUnwind) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)RtlVirtualUnwind)));
              ExFreePoolWithTagFn = (void (__fastcall *)(ULONG64, _QWORD))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExFreePoolWithTag) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExFreePoolWithTag)));
              poolAddress = ((__int64 (__fastcall *)(_QWORD, __int64, _QWORD))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExAllocatePoolWithTag) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExAllocatePoolWithTag))))(
                              (unsigned int)g_EmacPoolType,
                              0x2000i64,
                              'CAME');
              if ( poolAddress )
              {
                v16 = dword_FFFFF801BCFCC174;
                if ( (dword_FFFFF801BCFCC174 & 1) == 0 )
                {
                  dword_FFFFF801BCFCC174 |= 1u;
                  OffsetKThreadStackLimit = GetOffsetKThreadStackLimit();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadStackLimit = OffsetKThreadStackLimit;
                }
                if ( (v16 & 2) == 0 )
                {
                  dword_FFFFF801BCFCC174 = v16 | 2;
                  OffsetKThreadStackBase = GetOffsetKThreadStackBase();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadStackBase = OffsetKThreadStackBase;
                }
                if ( (v16 & 4) == 0 )
                {
                  dword_FFFFF801BCFCC174 = v16 | 4;
                  OffsetKThreadThreadLock = GetOffsetKThreadThreadLock();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadThreadLock = OffsetKThreadThreadLock;
                }
                if ( (v16 & 8) != 0 )
                {
                  OffsetKThreadKernelStack_1 = (unsigned int)g_OffsetKThreadKernelStack;
                }
                else
                {
                  dword_FFFFF801BCFCC174 = v16 | 8;
                  OffsetKThreadKernelStack = GetOffsetKThreadKernelStack();
                  v16 = dword_FFFFF801BCFCC174;
                  OffsetKThreadKernelStack_1 = OffsetKThreadKernelStack;
                  g_OffsetKThreadKernelStack = OffsetKThreadKernelStack;
                }
                if ( (v16 & 0x10) != 0 )
                {
                  OffsetKThreadState_1 = (unsigned int)g_OffsetKThreadState;
                }
                else
                {
                  dword_FFFFF801BCFCC174 = v16 | 0x10;
                  OffsetKThreadState = GetOffsetKThreadState();
                  OffsetKThreadKernelStack_1 = (unsigned int)g_OffsetKThreadKernelStack;
                  OffsetKThreadState_1 = OffsetKThreadState;
                  g_OffsetKThreadState = OffsetKThreadState;
                }
                MmIsAddressValidFn_2 = (unsigned __int8 (__fastcall *)(const void *))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
                MmGetPhysicalAddressFn = (__int64 (__stdcall *)(void *))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)MmGetPhysicalAddress) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)MmGetPhysicalAddress)));
                KeAcquireSpinLockRaiseToDpcFn = (__int64 (__fastcall *)(__int64))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeAcquireSpinLockRaiseToDpc) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeAcquireSpinLockRaiseToDpc)));
                KeReleaseSpinLockFn = (void (__fastcall *)(__int64, __int64))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeReleaseSpinLock) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeReleaseSpinLock)));
                PsIsThreadTerminatingFn = (unsigned __int8 (__fastcall *)(struct _KTHREAD *))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)PsIsThreadTerminating) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)PsIsThreadTerminating)));
                KeGetCurrentIrql();
                v24 = 0;
                memset((void *)poolAddress, 0, 0x2000ui64);
                if ( g_OffsetKThreadStackLimit == -1
                  || g_OffsetKThreadStackBase == -1
                  || g_OffsetKThreadThreadLock == -1
                  || (_DWORD)OffsetKThreadKernelStack_1 == -1
                  || (_DWORD)OffsetKThreadState_1 == -1 )
                {
                  v31 = 0xC0000138;
                }
                else
                {
                  threadInitialStack = (const void **)((char *)Thread + OffsetKThreadKernelStack_1);
                  threadState = (char *)Thread + OffsetKThreadState_1;
                  threadStackBase = *(void **)((char *)Thread + (unsigned int)g_OffsetKThreadStackBase);
                  threadStackLimit = *(void **)((char *)Thread + (unsigned int)g_OffsetKThreadStackLimit);
                  threadLock = (__int64)Thread + (unsigned int)g_OffsetKThreadThreadLock;
                  CurrentIrql = KeAcquireSpinLockRaiseToDpcFn(threadLock);
                  if ( PsIsThreadTerminatingFn(Thread) || *threadState != 5 )
                  {
                    v24 = 0xC000004B;
                  }
                  else
                  {
                    threadCurrentStack = (void *)*threadInitialStack;
                    if ( *threadInitialStack > threadStackLimit
                      && threadCurrentStack < threadStackBase
                      && MmGetPhysicalAddressFn(threadCurrentStack)
                      && MmIsAddressValidFn_2(*threadInitialStack) )
                    {
                      v14 = (_BYTE *)threadStackBase - (_BYTE *)*threadInitialStack;
                      if ( v14 > 0x2000 )
                        v14 = 0x2000i64;
                      memmove_2((void *)poolAddress, *threadInitialStack, v14);
                    }
                    else
                    {
                      v24 = 0xC0000141;
                    }
                  }
                  LOBYTE(v28) = CurrentIrql;
                  KeReleaseSpinLockFn(threadLock, v28);
                  v31 = v24;
                  if ( v24 >= 0
                    && v14 - 73 <= 8118
                    && EmacVerifyInTextSection(*(_QWORD *)(poolAddress + 0x38), (__int64)g_NtoskrnlBase, ntoskrnlHeader) )
                  {
                    memset(&ContextRecord, 0, sizeof(ContextRecord));
                    CurrentRip = *(void **)(poolAddress + 0x38);
                    Rsp = (void **)(poolAddress + 0x40);
                    i = stackFramesCount;
                    ContextRecord.Rsp = (ULONG64)Rsp;
                    ContextRecord.Rip = (ULONG64)CurrentRip;
                    do
                    {
                      ImageBase = 0i64;
                      HandlerData = 0i64;
                      EstablisherFrame = 0i64;
                      if ( (unsigned __int64)CurrentRip <= qword_FFFFF801BCFACC38 )
                        break;
                      if ( (unsigned __int64)Rsp <= qword_FFFFF801BCFACC38 )
                        break;
                      if ( !MmIsAddressValidFn(CurrentRip) )
                        break;
                      if ( !MmIsAddressValidFn(Rsp) )
                        break;
                      largePage = 0;
                      if ( !EmacIsPageEntryValid((__int64)CurrentRip, &largePage, 0i64) )
                        break;
                      if ( largePage )
                        break;
                      stackFrames[i] = (__int64)CurrentRip;
                      if ( !EmacGetModuleInfoFromAddress((unsigned __int64)CurrentRip, 1) )
                        break;
                      FunctionEntry = RtlLookupFunctionTableEntryFn(CurrentRip, &ImageBase, 0i64);
                      if ( FunctionEntry )
                      {
                        RtlVirtualUnwindFn(
                          0i64,
                          ImageBase,
                          ContextRecord.Rip,
                          FunctionEntry,
                          &ContextRecord,
                          &HandlerData,
                          (DWORD64 *)&EstablisherFrame,
                          0i64);
                        CurrentRip = (void *)ContextRecord.Rip;
                        Rsp = (void **)ContextRecord.Rsp;
                      }
                      else
                      {
                        CurrentRip = *Rsp;
                        Rsp = (void **)(ContextRecord.Rsp + 8);
                        ContextRecord.Rip = (ULONG64)CurrentRip;
                        ContextRecord.Rsp += 8i64;
                      }
                      FrameIndex = i++;
                      stackFramesCount = i;
                      if ( FrameIndex >= 32 )
                        break;
                    }
                    while ( (unsigned __int64)CurrentRip >= qword_FFFFF801BCFACC38 && !g_EmacNotReady );
                  }
                }
                ExFreePoolWithTagFn(poolAddress, 'CAME');
                if ( v31 < 0 || (v38 = stackFramesCount, stackFramesCount - 1 > 31) )
                {
                  v7 = ThreadId;
                }
                else
                {
                  StackTraceThreadId = ThreadId;
                  y = 0i64;
                  do
                  {
                    if ( *(_BYTE *)(a1 + 0x7D0) )
                      break;
                    if ( g_EmacNotReady )
                      break;
                    currentStackFrame = stackFrames[y];
                    if ( currentStackFrame <= qword_FFFFF801BCFACC38 || !MmIsAddressValidFn_1(stackFrames[y]) )
                      break;
                    ModuleInfoFromAddress = EmacGetModuleInfoFromAddress(currentStackFrame, 1);
                    RtlPcToFileHeaderFn(currentStackFrame, &FrameFileHeader);
                    if ( ModuleInfoFromAddress )
                    {
                      if ( FrameFileHeader != ModuleInfoFromAddress->ImageBase )
                        break;
                      if ( ModuleInfoFromAddress->SubjectName[0] )
                      {
                        *(_QWORD *)Str2 = 0xB07F113F97FF5772ui64;
                        *(_QWORD *)&Str2[4] = 0x13112D07CA8DB1F8i64;
                        si128 = (__m128)_mm_load_si128((const __m128i *)Str2);
                        v65.m128_u64[0] = 0x77B95CDEC3F425C2i64;
                        v84.m128_u64[0] = 0xD6106250E59C3E3Fui64;
                        v65.m128_u64[1] = 0xA8723627E07A05FEui64;
                        v84.m128_u64[1] = 0x647E4969A3DA918Ci64;
                        v85.m128i_i64[1] = 0xA8723627E07A05FEui64;
                        v85.m128i_i64[0] = 0x77B95CDEC3F425B1i64;
                        v65 = _mm_xor_ps((__m128)_mm_load_si128(&v85), v65);// Decrypted UTF-8: s
                        *(__m128 *)Str2 = _mm_xor_ps(si128, v84);// Decrypted Raw (unprintable): 44 85 40 94 3f 11 7f b0 74 20 57 69 6e 64 6f 77
                        if ( strcmp(ModuleInfoFromAddress->SubjectName, (const char *)Str2) )// "Microsoft Corporation"
                          break;
                      }
                      if ( ModuleInfoFromAddress->AdditionalData[0] )
                      {
                        *(_QWORD *)SubStr = 0xB364033495E95D52ui64;
                        v83.m128i_i64[0] = 0xD6106250E59C3E3Fui64;
                        *(_QWORD *)&SubStr[8] = 0x647E4969A3DA918Ci64;
                        v83.m128i_i64[1] = 0x647E4969A3DA918Ci64;
                        *(__m128 *)SubStr = _mm_xor_ps((__m128)_mm_load_si128(&v83), *(__m128 *)SubStr);
                        if ( strstr((const char *)ModuleInfoFromAddress->AdditionalData, SubStr) )// "mcupdate"
                          break;
                      }
                    }
                    if ( v56 )
                    {
                      if ( v56 == 1
                        && ModuleInfoFromAddress
                        && !EmacIsAddressInCodeSectionRange(
                              currentStackFrame,
                              (_IMAGE_DOS_HEADER *)ModuleInfoFromAddress->ImageBase,
                              0i64) )
                      {
                        EmacReportThreadInvalidStackTrace_2(
                          Thread,
                          (__int64)g_UnknownThreadStartAddress,
                          StackTraceThreadId,
                          y,
                          v38,
                          currentStackFrame,
                          (__int64)ModuleInfoFromAddress,
                          a1);
                      }
                    }
                    else if ( !ModuleInfoFromAddress && !FrameFileHeader )
                    {
                      if ( y && y < v38 )
                        lastStackFrame = stackFrames[y - 1];
                      else
                        lastStackFrame = 0i64;
                      EmacReportThreadInvalidStackTrace(
                        Thread,
                        g_UnknownThreadStartAddress,
                        StackTraceThreadId,
                        y,
                        v38,
                        currentStackFrame,
                        lastStackFrame,
                        a1);
                    }
                    ++y;
                  }
                  while ( y <= v38 );
                  v7 = StackTraceThreadId;
                }
              }
              else
              {
                v7 = ThreadId;
              }
              ObfDereferenceObjectFn = v55;
            }
            else
            {
              v7 = ThreadId;
            }
          }
          ObfDereferenceObjectFn();
        }
        v7 += 4;
        ThreadId = v7;
        EmacDelayExecutionThread(1);
      }
      while ( v7 < 0x10000 );
      KeUnstackDetachProcessFn(&v86);
      v45 = 2008i64;
      if ( a3 < 2008 )
        status = 0xC0000004;
      else
        memmove_2(a2, (const void *)a1, 2008ui64);
      v4 = a4;
    }
    v47 = (unsigned int *)(v4 + 0x30);
    result = (ULONG_PTR *)(v4 + 0x38);
  }
  *result = v45;
  *v47 = status;
  return result;
}

__int64 EmacVerifyDriverIntegrityImportTable()
{
  void (__fastcall *ExFreePoolWithTagFn)(_IMAGE_DOS_HEADER *, _QWORD); // rbp
  void *driverDecrypted; // rax MAPDST
  _IMAGE_NT_HEADERS64 *nth; // rax
  _IMAGE_NT_HEADERS64 *v4; // rbx
  unsigned __int16 i; // si
  char *v6; // r15
  __int64 v7; // rcx
  __m128 si128; // xmm0
  unsigned int v9; // r9d
  int v10; // edx
  __int64 v11; // r8
  char Str2[16]; // [rsp+20h] [rbp-48h] BYREF
  __m128 v14; // [rsp+30h] [rbp-38h]

  ExFreePoolWithTagFn = (void (__fastcall *)(_IMAGE_DOS_HEADER *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  driverDecrypted = EmacGetDriverDecrypted_0();
  if ( !driverDecrypted )
    return 0i64;
  nth = RtlImageNtHeader((_IMAGE_DOS_HEADER *)driverDecrypted);
  v4 = nth;
  if ( !nth || (i = 0, v6 = (char *)nth + nth->FileHeader.SizeOfOptionalHeader, !nth->FileHeader.NumberOfSections) )
  {
LABEL_10:
    ExFreePoolWithTagFn((_IMAGE_DOS_HEADER *)driverDecrypted, 'CAME');
    return 0i64;
  }
  while ( 1 )
  {
    v7 = (__int64)&v6[40 * i + 24];
    if ( (*(_DWORD *)(v7 + 0x24) & 0xC2000000) == 0x40000000 )
    {
      *(_QWORD *)&Str2[8] = 0x3AD429636D08206i64;
      *(_QWORD *)Str2 = 0x3C3BFBF5560DB3i64;
      si128 = (__m128)_mm_load_si128((const __m128i *)Str2);
      v14.m128_u64[1] = 0x3AD429636D08206i64;
      v14.m128_u64[0] = 0x3C5A8F9432649Di64;
      *(__m128 *)Str2 = _mm_xor_ps(si128, v14);
      if ( strncmp((const char *)v7, Str2, 8ui64) )// .idata
      {
        v9 = *(_DWORD *)&v6[40 * i + 40];
        v10 = 0;
        v11 = *(unsigned int *)&v6[40 * i + 36];
        if ( v9 )
          break;
      }
    }
LABEL_9:
    if ( ++i >= v4->FileHeader.NumberOfSections )
      goto LABEL_10;
  }
  while ( *((_BYTE *)g_DriverBase + v11) == *((_BYTE *)driverDecrypted + *(unsigned int *)&v6[40 * i + 44]) )
  {
    if ( ++v10 >= v9 )
      goto LABEL_9;
  }
  return (unsigned int)(v10 + v11);
}

__int64 EmacVerifyDriverIntegrityReadableSection()
{
  void (__fastcall *v0)(_IMAGE_DOS_HEADER *, __int64); // rdi
  void *DriverDecrypted; // rax MAPDST
  _IMAGE_NT_HEADERS64 *v3; // rax
  unsigned __int16 i; // dx
  USHORT NumberOfSections; // r10
  char *section; // r8
  unsigned int v7; // esi
  __int64 virtualAddress; // r9
  int BytesMatch; // ecx

  v0 = (void (__fastcall *)(_IMAGE_DOS_HEADER *, __int64))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  DriverDecrypted = EmacGetDriverDecrypted();
  if ( !DriverDecrypted )
    return 0i64;
  v3 = RtlImageNtHeader((_IMAGE_DOS_HEADER *)DriverDecrypted);
  if ( !v3
    || (i = 0,
        NumberOfSections = v3->FileHeader.NumberOfSections,
        section = (char *)v3 + v3->FileHeader.SizeOfOptionalHeader,
        !NumberOfSections) )
  {
CleanupAndExit:
    v0((_IMAGE_DOS_HEADER *)DriverDecrypted, 'CAME');
    return 0i64;
  }
  while ( 1 )
  {
    if ( (*(_DWORD *)&section[40 * i + 60] & 0xC2000000) == 0x40000000 )// Is readable, non-executable, non-shared, non-discardable
    {
      v7 = *(_DWORD *)&section[40 * i + 32];    // SizeOfRawData
      virtualAddress = *(unsigned int *)&section[40 * i + 36];// VirtualAddress
      BytesMatch = 0;
      if ( v7 )
        break;
    }
NextSection:
    if ( ++i >= NumberOfSections )
      goto CleanupAndExit;
  }
  while ( *((_BYTE *)g_DriverBase + virtualAddress) == *((_BYTE *)DriverDecrypted + virtualAddress) )
  {
    if ( ++BytesMatch >= v7 )
      goto NextSection;
  }
  return (unsigned int)(BytesMatch + virtualAddress);
}

char __fastcall EmacVerifyHalDispatchTableKeBugCheckEx(_DWORD *detectionFlag)
{
  __m128 v2; // xmm0
  _IMAGE_DOS_HEADER *ntoskrnl; // rax
  unsigned __int8 (__fastcall *MmIsAddressValidFn)(void *); // r14
  __m128 si128; // xmm0
  ULONG64 dataSectionAddress; // rdi
  void *KeBugCheckEx; // rsi
  __m128 v8; // xmm0
  __m128 v9; // xmm1
  void *DbgBreakPointWithStatus; // r8
  ULONG64 curAddr; // rcx
  void *NtHalInitializeProcessorFileHeader; // rsi
  __m128 v13; // xmm0
  __m128 v14; // xmm1
  char **HalPrivateDispatchTable; // rdi
  _IMAGE_NT_HEADERS64 *v16; // rax MAPDST
  ULONG64 prevAddress; // rdi
  char sectionName[16]; // [rsp+20h] [rbp-50h] BYREF
  char routineName[16]; // [rsp+30h] [rbp-40h] BYREF
  __m128 v22; // [rsp+40h] [rbp-30h]
  wchar_t moduleName[8]; // [rsp+50h] [rbp-20h] BYREF
  __m128 v24; // [rsp+60h] [rbp-10h] BYREF
  ULONG dataSectionSize; // [rsp+A8h] [rbp+38h] BYREF

  wmemcpy(moduleName, L"蘻铫䑜頵蜕帆ⱔ鯛쀹垱⻡絬锸醼蜀琊", 16);
  v22.m128_u64[1] = 0x740A870091BC9538i64;
  v22.m128_u64[0] = 0x7D092E9957D4C017i64;
  *(_QWORD *)routineName = 0x98464433949F8655ui64;
  *(_QWORD *)&routineName[8] = 0x9BB72C3A5E74877Eui64;
  v2 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)moduleName), *(__m128 *)routineName);
  v24 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v24), v22);// Decrypted Raw (unprintable): 01 55 0d c6 e1 a9 66 09 00 00 00 00 00 00 00 00
  *(__m128 *)moduleName = v2;                   // Decrypted Raw (unprintable): 03 13 57 05 5c c3 3f ec 6b 00 72 00 6e 00 6c 00
  ntoskrnl = (_IMAGE_DOS_HEADER *)EmacFindKernelModule(moduleName, 0i64);
  if ( ntoskrnl )
  {
    *(_QWORD *)&sectionName[8] = 0x9BB72C3A5E74877Eui64;
    *(_QWORD *)routineName = 0x98464433949F8655ui64;
    dataSectionSize = 0;
    MmIsAddressValidFn = (unsigned __int8 (__fastcall *)(void *))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
    *(_QWORD *)&routineName[8] = 0x9BB72C3A5E74877Eui64;
    si128 = (__m128)_mm_load_si128((const __m128i *)routineName);
    *(_QWORD *)sectionName = 0x98464452E0FEE27Bui64;
    *(__m128 *)sectionName = _mm_xor_ps(si128, *(__m128 *)sectionName);// Decrypted Raw (unprintable): 2b 01 eb ca 09 68 f1 03 00 00 00 00 00 00 00 00
    dataSectionAddress = (ULONG64)GetImageSectionAddress(ntoskrnl, sectionName, &dataSectionSize);// .data
    if ( dataSectionAddress )
    {
      wmemcpy(moduleName, L"處钟䐳顆蝾年ⰺ鮷", 8);
      *(_QWORD *)routineName = 0xFD2E0754E1DDE31Eui64;
      *(_QWORD *)&routineName[8] = 0x9BB72C3A2631EC1Dui64;
      *(__m128 *)routineName = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)routineName), *(__m128 *)moduleName);// Decrypted Raw (unprintable): 4b 65 42 75 67 43 68 65 6b 00 72 00 6e 00 6c 00
      KeBugCheckEx = EmacGetSystemRoutineAddress(routineName, 0, 0i64);// "KeBugCheckEx"
      *(_QWORD *)routineName = 0x98464433949F8655ui64;
      wmemcpy(moduleName, L"훸⅁〝筎鍿㚠寭絺锸醼蜀琊", 16);
      *(_QWORD *)&routineName[8] = 0x9BB72C3A5E74877Eui64;
      v8 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)moduleName), *(__m128 *)routineName);
      v9 = (__m128)_mm_load_si128((const __m128i *)&v24);
      v22.m128_u64[0] = 0x7D092E9957D4C017i64;
      v22.m128_u64[1] = 0x740A870091BC9538i64;
      v24 = _mm_xor_ps(v9, v22);                // Decrypted UTF-8: hStatus
      *(__m128 *)moduleName = v8;               // Decrypted UTF-8: DbgBreakckEx
      DbgBreakPointWithStatus = EmacGetSystemRoutineAddress((const char *)moduleName, 0, 0i64);// "DbgBreakPointWithStatus"
      if ( dataSectionSize )
      {
        curAddr = dataSectionAddress;
        while ( *(void **)curAddr != KeBugCheckEx || *(void **)(curAddr + 0x20) != DbgBreakPointWithStatus )
        {
          curAddr += 8i64;
          if ( curAddr - dataSectionAddress >= dataSectionSize )
            goto LABEL_8;
        }
        prevAddress = curAddr - 8;
        if ( curAddr != 8 && MmIsAddressValidFn((void *)(curAddr - 8)) && !*(_QWORD *)prevAddress )
        {
          if ( detectionFlag )
            *detectionFlag = 1;                 // Flag detection
          return 0;
        }
      }
    }
LABEL_8:
    NtHalInitializeProcessorFileHeader = FindNtHalInitializeProcessorFileHeader();
    if ( NtHalInitializeProcessorFileHeader )
    {
      *(_QWORD *)routineName = 0x98464433949F8655ui64;
      wmemcpy(moduleName, L"쓳ⵁ擄㜰屉꡴㚀䋻絬锸醼蜀琊", 16);
      *(_QWORD *)&routineName[8] = 0x9BB72C3A5E74877Eui64;
      v13 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)moduleName), *(__m128 *)routineName);
      v14 = (__m128)_mm_load_si128((const __m128i *)&v24);
      v22.m128_u64[0] = 0x7D092E9957D4C017i64;
      v22.m128_u64[1] = 0x740A870091BC9538i64;
      v24 = _mm_xor_ps(v14, v22);               // Decrypted UTF-8: chTable
      *(__m128 *)moduleName = v13;              // Decrypted UTF-8: HalPrivaPointWit
      HalPrivateDispatchTable = (char **)EmacGetSystemRoutineAddress((const char *)moduleName, 0, 0i64);// "HalPrivateDispatchTable"
      if ( MmIsAddressValidFn(HalPrivateDispatchTable) )
      {
        v16 = RtlImageNtHeader((_IMAGE_DOS_HEADER *)NtHalInitializeProcessorFileHeader);
        if ( v16 )
        {
          if ( *(_DWORD *)HalPrivateDispatchTable >= 21u
            && !EmacVerifyInTextSection(
                  (__int64)HalPrivateDispatchTable[53],
                  (__int64)NtHalInitializeProcessorFileHeader,
                  v16)                          // HalNotifyProcessorFreeze
            || *(_DWORD *)HalPrivateDispatchTable >= 23u
            && !EmacVerifyInTextSection(
                  (__int64)HalPrivateDispatchTable[103],
                  (__int64)NtHalInitializeProcessorFileHeader,
                  v16)                          // HalTimerWatchdogStop
            || *(_DWORD *)HalPrivateDispatchTable >= 6u
            && !EmacVerifyInTextSection(
                  (__int64)HalPrivateDispatchTable[33],
                  (__int64)NtHalInitializeProcessorFileHeader,
                  v16)                          // HalPrepareForBugcheck
            || *(_DWORD *)HalPrivateDispatchTable >= 21u
            && !EmacVerifyInTextSection(
                  (__int64)HalPrivateDispatchTable[67],
                  (__int64)NtHalInitializeProcessorFileHeader,
                  v16) )                        // HalRestoreHvEnlightenment
          {
            if ( detectionFlag )
              *detectionFlag = 2;
            return 0;
          }
        }
      }
    }
  }
  return 1;
}

char __fastcall EmacVerifyInTextSection(__int64 dst, __int64 src, _IMAGE_NT_HEADERS64 *nth)
{
  int i; // edi
  IMAGE_SECTION_HEADER *section; // r14
  char str2[16]; // [rsp+20h] [rbp-38h] BYREF
  __m128 v8; // [rsp+30h] [rbp-28h]

  if ( !dst )
    return 0;
  if ( !src )
    return 0;
  if ( !nth )
    return 0;
  i = 0;
  section = (IMAGE_SECTION_HEADER *)((char *)&nth->OptionalHeader + nth->FileHeader.SizeOfOptionalHeader);
  if ( !nth->FileHeader.NumberOfSections )
    return 0;
  v8.m128_u64[0] = 0xB43765BD10FCC425ui64;
  v8.m128_u64[1] = 0xB7A84DC4C136A732ui64;
  while ( 1 )
  {
    *(_QWORD *)&str2[8] = 0xB7A84DC4C136A732ui64;
    *(_QWORD *)str2 = 0xB43765C96899B00Bui64;
    *(__m128 *)str2 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)str2), v8);// Decrypted UTF-8: .text
    if ( !(unsigned int)strincmp((char *)&section[i], str2, 8i64)// Is readable, executable, contains code, not writable
      && (section[i].Characteristics & 0xEA000000) == 0x68000000 )
    {
      break;
    }
    if ( ++i >= (unsigned int)nth->FileHeader.NumberOfSections )
      return 0;
  }
  return 1;
}

__int64 EmacVerifyLoadedModulesList()
{
  __int64 (__fastcall *ExAllocatePoolWithTagFn)(_QWORD, unsigned __int64, _QWORD); // r14
  _KLDR_DATA_TABLE_ENTRY *i; // rdi
  _EMAC_MODULE_ENTRY *moduleEntry; // rax MAPDST
  _IMAGE_DOS_HEADER *DllBase; // rdx
  ULONG CoverageSection; // eax
  ULONG idx; // ecx
  wchar_t *FullDllName; // rdx
  unsigned __int64 FullDllName_Length; // rcx
  size_t v10; // r8
  unsigned __int64 v11; // rcx
  WCHAR *j; // rdx
  unsigned __int64 v13; // rax
  struct _LIST_ENTRY *Blink; // rax
  _EMAC_IMAGE_SIGN_INFO signInfo; // [rsp+20h] [rbp-E0h] BYREF

  signInfo.VerificationStatus = 0;
  signInfo.PolicyBits = 0;
  signInfo.PolicyInfoSize = 0;
  memset(&signInfo.SigningTime, 0, 681);
  signInfo.IsVerified = 0;
  ExAllocatePoolWithTagFn = (__int64 (__fastcall *)(_QWORD, unsigned __int64, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( !PsLoadedModuleList )
    return 0xC0000138i64;
  if ( PsLoadedModuleList->Flink == PsLoadedModuleList )
    return 0xC0000001i64;
  g_EmacModulesList.Blink = &g_EmacModulesList; // InitializeListHead
  g_EmacModulesList.Flink = &g_EmacModulesList;
  EmacInitializeVerifiedImagesList();
  EmacInstallHooks();
  for ( i = (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList->Flink;
        i != (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList;
        i = (_KLDR_DATA_TABLE_ENTRY *)i->InLoadOrderLinks.Flink )
  {
    moduleEntry = (_EMAC_MODULE_ENTRY *)ExAllocatePoolWithTagFn(
                                          (unsigned int)g_EmacPoolType,
                                          sizeof(_EMAC_MODULE_ENTRY),
                                          'CAME');
    if ( moduleEntry )
    {
      memset(moduleEntry, 0, sizeof(_EMAC_MODULE_ENTRY));
      DllBase = (_IMAGE_DOS_HEADER *)i->DllBase;
      moduleEntry->ImageBase = DllBase;
      moduleEntry->ImageSize = i->SizeOfImage;
      CoverageSection = (ULONG)i->CoverageSection;
      if ( !CoverageSection )
        CoverageSection = EmacGetImageTimeDateStamp(DllBase);
      idx = g_EmacModulesListCount;
      moduleEntry->TimeDateStamp = CoverageSection;
      moduleEntry->EntryId = idx;
      FullDllName = i->FullDllName.Buffer;
      g_EmacModulesListCount = idx + 1;
      if ( FullDllName )
      {
        FullDllName_Length = i->FullDllName.Length;
        if ( (unsigned __int16)FullDllName_Length > 2u
          && (unsigned __int16)FullDllName_Length <= i->FullDllName.MaximumLength )
        {
          if ( (FullDllName_Length & 0xFFFE) <= 0x256 )
            v10 = FullDllName_Length >> 1;
          else
            v10 = 299i64;
          wcsncpy(moduleEntry->ModuleName, FullDllName, v10);
          v11 = 0i64;
          for ( j = moduleEntry->ModuleName; ; ++j )
          {
            v13 = (i->FullDllName.Length & 0xFFFEu) >= 0x256 ? 299i64 : (unsigned __int64)i->FullDllName.Length >> 1;
            if ( v11 >= v13 )
              break;
            moduleEntry->AdditionalData[v11++] = *(_BYTE *)j;
          }
          EmacVerifyFileSignedByFileName(moduleEntry->ModuleName, &signInfo);
          if ( LOBYTE(signInfo.Unknown1) && signInfo.SubjectName[0] )
            strcpy_and_zero(moduleEntry->SubjectName, signInfo.SubjectName, 299ui64);
          EmacVerifyModuleEntry(moduleEntry);
        }
      }
      Blink = g_EmacModulesList.Blink;
      if ( g_EmacModulesList.Blink->Flink != &g_EmacModulesList )
        __fastfail(3u);
      moduleEntry->ListEntry.Flink = &g_EmacModulesList;// InsertListTail
      moduleEntry->ListEntry.Blink = Blink;
      Blink->Flink = &moduleEntry->ListEntry;
      g_EmacModulesList.Blink = &moduleEntry->ListEntry;
    }
  }
  return 0i64;
}

__int64 __fastcall EmacVerifyMmUnloadedDrivers(wchar_t *Dest, _OWORD *a2, unsigned int a3, __int64 a4)
{
  __int64 v4; // r13
  unsigned int v5; // r12d
  _OWORD *v6; // rsi
  __int64 result; // rax
  __m128 si128; // xmm0
  unsigned __int64 v10; // rbx
  unsigned __int64 v11; // r8
  __m128 v12; // xmm1
  __m128 v13; // xmm0
  unsigned __int64 v14; // r8
  __m128 v15; // xmm1
  __m128 v16; // xmm0
  unsigned __int64 v17; // r8
  __m128 v18; // xmm1
  __m128 v19; // xmm0
  unsigned __int64 v20; // r8
  __m128 v21; // xmm1
  unsigned __int64 v22; // r8
  __m128 v23; // xmm0
  __m128 v24; // xmm1
  unsigned __int64 v25; // r8
  __m128 v26; // xmm0
  __m128 v27; // xmm1
  __m128 v28; // xmm0
  unsigned __int64 v29; // r8
  __m128 v30; // xmm1
  __m128 v31; // xmm0
  unsigned __int64 v32; // r8
  __m128 v33; // xmm1
  unsigned __int64 v34; // r8
  __m128 v35; // xmm0
  __m128 v36; // xmm1
  __m128 v37; // xmm0
  unsigned __int64 v38; // r8
  __m128 v39; // xmm0
  __m128 v40; // xmm1
  unsigned __int64 v41; // r8
  __m128 v42; // xmm0
  __m128 v43; // xmm1
  unsigned __int64 v44; // r8
  __m128 v45; // xmm0
  __m128 v46; // xmm1
  unsigned __int64 v47; // r8
  __m128 v48; // xmm0
  __m128 v49; // xmm1
  __m128 v50; // xmm0
  __m128 v51; // xmm1
  __int64 v52; // rbx
  __int64 *v53; // r14
  _MM_UNLOADED_DRIVER *MmUnloadedDrivers; // r14
  __int64 PsLoadedModuleResource; // r15
  void (__fastcall *ExAcquireResourceExclusiveLiteFn)(__int64, BOOLEAN); // rbx
  __int64 v57; // rdx
  __int64 v58; // rbx
  char v59; // si
  unsigned int v60; // r12d
  __int64 v61; // rbx
  unsigned __int64 v62; // r13
  unsigned __int64 v63; // r14
  __int64 v64; // r15
  wchar_t *v65; // rcx
  unsigned __int64 v66; // r8
  __int64 v67; // rax
  __int128 v68; // xmm1
  __m128 v69; // [rsp+20h] [rbp-E0h]
  __m128 v70; // [rsp+20h] [rbp-E0h]
  __m128 v71; // [rsp+20h] [rbp-E0h]
  __m128 v72; // [rsp+20h] [rbp-E0h]
  __m128 v73; // [rsp+20h] [rbp-E0h]
  __m128 v74; // [rsp+20h] [rbp-E0h]
  __m128 v75; // [rsp+20h] [rbp-E0h]
  __m128 v76; // [rsp+20h] [rbp-E0h]
  __m128 v77; // [rsp+20h] [rbp-E0h]
  __m128 v78; // [rsp+20h] [rbp-E0h]
  __m128 v79; // [rsp+20h] [rbp-E0h]
  __m128 v80; // [rsp+30h] [rbp-D0h]
  __m128 v81; // [rsp+30h] [rbp-D0h]
  __m128 v82; // [rsp+30h] [rbp-D0h]
  __m128 v83; // [rsp+30h] [rbp-D0h]
  __m128 v84; // [rsp+30h] [rbp-D0h]
  __m128 v85; // [rsp+30h] [rbp-D0h]
  __m128 v86; // [rsp+30h] [rbp-D0h]
  __m128 v87; // [rsp+30h] [rbp-D0h]
  __m128 v88; // [rsp+30h] [rbp-D0h]
  __m128 v89; // [rsp+30h] [rbp-D0h]
  __m128 v90; // [rsp+30h] [rbp-D0h]
  __m128 v91; // [rsp+40h] [rbp-C0h]
  __m128 v92; // [rsp+40h] [rbp-C0h]
  __m128 v93; // [rsp+40h] [rbp-C0h]
  __m128 v94; // [rsp+40h] [rbp-C0h]
  __m128 v95; // [rsp+40h] [rbp-C0h]
  __m128 v96; // [rsp+40h] [rbp-C0h]
  __m128 v97; // [rsp+40h] [rbp-C0h]
  __m128 v98; // [rsp+40h] [rbp-C0h]
  __m128 v99; // [rsp+40h] [rbp-C0h]
  __m128 v100; // [rsp+40h] [rbp-C0h]
  __m128 v101; // [rsp+40h] [rbp-C0h]
  __m128 v102; // [rsp+50h] [rbp-B0h]
  __m128 v103; // [rsp+60h] [rbp-A0h] BYREF
  __m128 v104; // [rsp+70h] [rbp-90h] BYREF
  __m128 v105; // [rsp+80h] [rbp-80h] BYREF
  char *v106; // [rsp+90h] [rbp-70h] BYREF
  __int128 *v107; // [rsp+98h] [rbp-68h] BYREF
  __m128 v108; // [rsp+A0h] [rbp-60h] BYREF
  __m128 v109; // [rsp+B0h] [rbp-50h] BYREF
  __m128 v110; // [rsp+C0h] [rbp-40h] BYREF
  __m128 v111; // [rsp+D0h] [rbp-30h] BYREF
  __m128 v112; // [rsp+E0h] [rbp-20h] BYREF
  __m128 v113; // [rsp+F0h] [rbp-10h] BYREF
  __int128 v114; // [rsp+100h] [rbp+0h] BYREF
  __int64 v115; // [rsp+110h] [rbp+10h]
  __m128 v116; // [rsp+120h] [rbp+20h] BYREF
  __m128 v117; // [rsp+130h] [rbp+30h] BYREF
  __m128 v118; // [rsp+140h] [rbp+40h] BYREF
  __m128 v119; // [rsp+150h] [rbp+50h] BYREF
  __m128 v120; // [rsp+160h] [rbp+60h] BYREF
  __m128 v121; // [rsp+170h] [rbp+70h] BYREF
  __m128 v122; // [rsp+180h] [rbp+80h] BYREF
  __m128 v123; // [rsp+190h] [rbp+90h] BYREF
  __m128 v124; // [rsp+1A0h] [rbp+A0h] BYREF
  __m128 v125; // [rsp+1B0h] [rbp+B0h] BYREF
  __m128 v126; // [rsp+1C0h] [rbp+C0h] BYREF
  __m128 v127; // [rsp+1D0h] [rbp+D0h] BYREF
  __m128 v128; // [rsp+1E0h] [rbp+E0h] BYREF
  __m128 v129; // [rsp+1F0h] [rbp+F0h] BYREF
  __m128 v130; // [rsp+200h] [rbp+100h] BYREF
  __m128 v131; // [rsp+210h] [rbp+110h] BYREF
  __m128 v132; // [rsp+220h] [rbp+120h] BYREF
  __m128 v133; // [rsp+230h] [rbp+130h] BYREF
  __m128 v134; // [rsp+240h] [rbp+140h] BYREF
  __m128 v135; // [rsp+250h] [rbp+150h] BYREF
  __m128 v136; // [rsp+260h] [rbp+160h] BYREF
  __m128 v137; // [rsp+270h] [rbp+170h] BYREF
  __m128 v138; // [rsp+280h] [rbp+180h] BYREF
  __m128 v139; // [rsp+290h] [rbp+190h] BYREF
  __m128 v140; // [rsp+2A0h] [rbp+1A0h] BYREF
  __m128 v141; // [rsp+2B0h] [rbp+1B0h] BYREF
  __m128 v142; // [rsp+2C0h] [rbp+1C0h] BYREF
  __m128 v143; // [rsp+2D0h] [rbp+1D0h] BYREF
  __m128 v144; // [rsp+2E0h] [rbp+1E0h] BYREF
  __m128i v145; // [rsp+2F0h] [rbp+1F0h] BYREF
  __m128 v146; // [rsp+300h] [rbp+200h] BYREF
  void (__fastcall *ExReleaseResourceLiteFn)(__int64); // [rsp+310h] [rbp+210h]
  void (*KeLeaveCriticalRegionFn)(void); // [rsp+318h] [rbp+218h]
  __int128 v149[2]; // [rsp+320h] [rbp+220h] BYREF
  __int128 v150[2]; // [rsp+340h] [rbp+240h] BYREF
  __int128 v151[2]; // [rsp+360h] [rbp+260h] BYREF
  __int128 v152[2]; // [rsp+380h] [rbp+280h] BYREF
  __int128 v153[2]; // [rsp+3A0h] [rbp+2A0h] BYREF
  __int128 v154[2]; // [rsp+3C0h] [rbp+2C0h] BYREF
  __int128 v155[2]; // [rsp+3E0h] [rbp+2E0h] BYREF
  __int128 v156[2]; // [rsp+400h] [rbp+300h] BYREF
  __int128 v157[2]; // [rsp+420h] [rbp+320h] BYREF
  __int128 v158[2]; // [rsp+440h] [rbp+340h] BYREF
  __int128 v159[2]; // [rsp+460h] [rbp+360h] BYREF
  __int128 v160[2]; // [rsp+480h] [rbp+380h] BYREF
  __int128 v161[2]; // [rsp+4A0h] [rbp+3A0h] BYREF
  __int128 v162[2]; // [rsp+4C0h] [rbp+3C0h] BYREF
  char v163[48]; // [rsp+4E0h] [rbp+3E0h] BYREF

  v4 = a4;
  v5 = a3;
  v6 = a2;
  result = KeGetCurrentIrql();
  if ( (_BYTE)result )
  {
    *(_QWORD *)(a4 + 56) = 0i64;
    *(_DWORD *)(a4 + 48) = -1073741496;
  }
  else
  {
    v103.m128_u64[0] = 0x7220C9ABC5990DF5i64;
    v69.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v103.m128_u64[1] = 0xC1D7A6CC7F7ACCD7ui64;
    si128 = (__m128)_mm_load_si128((const __m128i *)&v103);
    v104.m128_u64[0] = 0x5770B442C6497BD4i64;
    v10 = -1i64;
    v69.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v104.m128_u64[1] = 0x9A74011A5733A129ui64;
    v11 = -1i64;
    v12 = (__m128)_mm_load_si128((const __m128i *)&v104);
    v105.m128_u64[0] = 0xC5BBA33E04E7D808ui64;
    v105.m128_u64[1] = 0x1CC64997304B2120i64;
    v103 = _mm_xor_ps(si128, v69);              // Decrypted UTF-16: blac
    v80.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v91.m128_u64[1] = 0x1CC64997304B2120i64;
    v80.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v91.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v105 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v105), v91);// Decrypted Raw (unprintable): 73 2a 1d e8 79 e7 fd 5d 4b b4 8e a1 e4 ce b8 68
    v104 = _mm_xor_ps(v12, v80);
    memset(v149, 0, sizeof(v149));
    do
      ++v11;
    while ( v103.m128_i16[v11] );
    std_vector_push_back(v149, &v103, v11);
    v81.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v116.m128_u64[0] = 0x7220C9ABC5990DF5i64;
    v70.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v116.m128_u64[1] = 0xC1D7A6CC7F7ACCD7ui64;
    v13 = (__m128)_mm_load_si128((const __m128i *)&v116);
    v117.m128_u64[0] = 0x5770B442C6497BD4i64;
    v14 = -1i64;
    v70.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v117.m128_u64[1] = 0x9A74011A5733A126ui64;
    v15 = (__m128)_mm_load_si128((const __m128i *)&v117);
    v118.m128_u64[0] = 0xC5BBA33E04E7D808ui64;
    v118.m128_u64[1] = 0x1CC64997304B2120i64;
    v116 = _mm_xor_ps(v13, v70);                // Decrypted UTF-8: 
    v81.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v92.m128_u64[1] = 0x1CC64997304B2120i64;
    v92.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v118 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v118), v92);// Decrypted UTF-8: 
    v117 = _mm_xor_ps(v15, v81);                // Decrypted UTF-8: 
    memset(v150, 0, sizeof(v150));
    do
      ++v14;
    while ( v116.m128_i16[v14] );
    std_vector_push_back(v150, &v116, v14);
    v82.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v119.m128_u64[0] = 0x7220C9ABC5990DF5i64;
    v71.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v119.m128_u64[1] = 0xC1D7A6CC7F7ACCD7ui64;
    v16 = (__m128)_mm_load_si128((const __m128i *)&v119);
    v120.m128_u64[0] = 0x5770B442C6497BD4i64;
    v17 = -1i64;
    v71.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v120.m128_u64[1] = 0x9A7E0147572CA126ui64;
    v18 = (__m128)_mm_load_si128((const __m128i *)&v120);
    v121.m128_u64[0] = 0xC5BBA33E0494D802ui64;
    v121.m128_u64[1] = 0x1CC64997304B2120i64;
    v119 = _mm_xor_ps(v16, v71);                // Decrypted Raw (unprintable): 62 00 6c 00 61 00 63 00 c2 4b 6c 21 99 8a 0e 5a
    v82.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v93.m128_u64[1] = 0x1CC64997304B2120i64;
    v93.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v121 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v121), v93);// Decrypted Raw (unprintable): 79 00 73 00 00 00 00 00 09 80 78 67 8d 48 b2 86
    v120 = _mm_xor_ps(v18, v82);                // Decrypted Raw (unprintable): 65 00 64 00 72 00 76 00 f1 6d 49 28 d6 a7 a3 5b
    memset(v151, 0, sizeof(v151));
    do
      ++v17;
    while ( v119.m128_i16[v17] );
    std_vector_push_back(v151, &v119, v17);
    v83.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v122.m128_u64[0] = 0x7220C9ABC5990DF5i64;
    v72.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v122.m128_u64[1] = 0xC1D7A6CC7F7ACCD7ui64;
    v19 = (__m128)_mm_load_si128((const __m128i *)&v122);
    v123.m128_u64[0] = 0x5770B442C6497BD4i64;
    v20 = -1i64;
    v72.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v123.m128_u64[1] = 0x9A7E0147572DA12Fui64;
    v21 = (__m128)_mm_load_si128((const __m128i *)&v123);
    v124.m128_u64[0] = 0xC5BBA33E0494D802ui64;
    v124.m128_u64[1] = 0x1CC64997304B2120i64;
    v122 = _mm_xor_ps(v19, v72);                // Decrypted UTF-16: blackbon
    v83.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v94.m128_u64[1] = 0x1CC64997304B2120i64;
    v94.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v124 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v124), v94);// Decrypted UTF-16: ys
    v123 = _mm_xor_ps(v21, v83);                // Decrypted UTF-16: edrv10.s
    memset(v152, 0, sizeof(v152));
    do
      ++v20;
    while ( v122.m128_i16[v20] );
    std_vector_push_back(v152, &v122, v20);
    v109.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v108.m128_u64[0] = 0x7220C9BAC5940DF4i64;
    v22 = -1i64;
    v104.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v108.m128_u64[1] = 0xC1CAA68D7F75CCD3ui64;
    v23 = (__m128)_mm_load_si128((const __m128i *)&v108);
    v109.m128_u64[0] = 0x5706B430C65E7BC8i64;
    v24 = (__m128)_mm_load_si128((const __m128i *)&v109);
    v103.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v103.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v104.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v109 = _mm_xor_ps(v24, v104);               // Decrypted Raw (unprintable): ca a3 ca c2 0e 17 bd 92 37 00 2e 00 73 00 79 00
    v108 = _mm_xor_ps(v23, v103);               // Decrypted Raw (unprintable): 20 76 dd 03 f8 7d 50 25 27 11 29 e0 1d fd 1b 32
    memset(v153, 0, sizeof(v153));
    do
      ++v22;
    while ( v108.m128_i16[v22] );
    std_vector_push_back(v153, &v108, v22);
    v111.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v110.m128_u64[0] = 0x723BC9A5C5970DE1i64;
    v25 = -1i64;
    v104.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v110.m128_u64[1] = 0xC197A6D57F6ACCD8ui64;
    v26 = (__m128)_mm_load_si128((const __m128i *)&v110);
    v111.m128_u64[0] = 0x5706B443C6547BC2i64;
    v27 = (__m128)_mm_load_si128((const __m128i *)&v111);
    v103.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v103.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v104.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v111 = _mm_xor_ps(v27, v104);               // Decrypted UTF-16: sys
    v110 = _mm_xor_ps(v26, v103);               // Decrypted Raw (unprintable): 76 00 62 00 6f 00 78 00 fe 6d 46 28 92 a7 e9 5b
    memset(v154, 0, sizeof(v154));
    do
      ++v25;
    while ( v110.m128_i16[v25] );
    std_vector_push_back(v154, &v110, v25);
    v84.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v125.m128_u64[0] = 0x722DC9B8C5900DFCi64;
    v73.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v125.m128_u64[1] = 0xC1DBA68E7F74CCD9ui64;
    v28 = (__m128)_mm_load_si128((const __m128i *)&v125);
    v126.m128_u64[0] = 0x5761B454C6447BC3i64;
    v29 = -1i64;
    v73.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v126.m128_u64[1] = 0x9A74011A5733A17Bui64;
    v30 = (__m128)_mm_load_si128((const __m128i *)&v126);
    v127.m128_u64[0] = 0xC5BBA33E04E7D808ui64;
    v127.m128_u64[1] = 0x1CC64997304B2120i64;
    v125 = _mm_xor_ps(v28, v73);                // Decrypted UTF-16: kernel-b
    v84.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v95.m128_u64[1] = 0x1CC64997304B2120i64;
    v95.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v127 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v127), v95);// Decrypted UTF-8: s
    v126 = _mm_xor_ps(v30, v84);                // Decrypted UTF-16: ridge.sy
    memset(v155, 0, sizeof(v155));
    do
      ++v29;
    while ( v125.m128_i16[v29] );
    std_vector_push_back(v155, &v125, v29);
    v85.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v128.m128_u64[0] = 0x722CC9B8C5850DFCi64;
    v74.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v128.m128_u64[1] = 0xC1CAA6D07F7DCCDFui64;
    v31 = (__m128)_mm_load_si128((const __m128i *)&v128);
    v129.m128_u64[0] = 0x576DB453C64C7BD9i64;
    v32 = -1i64;
    v74.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v129.m128_u64[1] = 0x9A7E0147576FA17Bui64;
    v33 = (__m128)_mm_load_si128((const __m128i *)&v129);
    v130.m128_u64[0] = 0xC5BBA33E0494D802ui64;
    v130.m128_u64[1] = 0x1CC64997304B2120i64;
    v128 = _mm_xor_ps(v31, v74);                // Decrypted UTF-16: kprocess
    v85.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v96.m128_u64[1] = 0x1CC64997304B2120i64;
    v96.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v130 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v130), v96);// Decrypted UTF-16: ys
    v129 = _mm_xor_ps(v33, v85);                // Decrypted UTF-16: hacker.s
    memset(v156, 0, sizeof(v156));
    do
      ++v32;
    while ( v128.m128_i16[v32] );
    std_vector_push_back(v156, &v128, v32);
    v86.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v143.m128_u64[0] = 0x7227C9A4C59C0DE0i64;
    v146.m128_u64[1] = 0x19B6D61DEFFD1342i64;
    v143.m128_u64[1] = 0xC1D2A6D07F6FCCD3ui64;
    v34 = -1i64;
    v35 = (__m128)_mm_load_si128((const __m128i *)&v143);
    v144.m128_u64[0] = 0x5763B45EC65F7BD4i64;
    v144.m128_u64[1] = 0x9A7D01115778A172ui64;
    v36 = (__m128)_mm_load_si128((const __m128i *)&v144);
    v145.m128i_i64[0] = 0xC5DEA34C0488D817ui64;
    v145.m128i_i64[1] = 0x1CBF49E430652152i64;
    v146.m128_u64[0] = 0x8E0084248AA6B7A6ui64;
    v75.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v75.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v86.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v97.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v97.m128_u64[1] = 0x1CC64997304B2120i64;
    v143 = _mm_xor_ps(v35, v75);                // Decrypted UTF-16: windowsk
    v37 = _mm_xor_ps((__m128)_mm_load_si128(&v145), v97);
    v144 = _mm_xor_ps(v36, v86);                // Decrypted UTF-16: ernelexp
    v102.m128_u64[0] = 0x8E0084248AA6B7D5ui64;
    v102.m128_u64[1] = 0x19B6D61DEFFD1342i64;
    v146 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v146), v102);// Decrypted Raw (unprintable): 53 ba 3f 4f 8f 4d 20 fc 3c 94 89 b1 27 fa 01 82
    v145 = (__m128i)v37;                        // Decrypted UTF-16: lorer.sy
    memset(v157, 0, sizeof(v157));
    do
      ++v34;
    while ( v143.m128_i16[v34] );
    std_vector_push_back(v157, &v143, v34);
    v87.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v131.m128_u64[0] = 0x722EC9A3C5850DF6i64;
    v38 = -1i64;
    v131.m128_u64[1] = 0xC1CDA6CA7F76CCD3ui64;
    v39 = (__m128)_mm_load_si128((const __m128i *)&v131);
    v132.m128_u64[0] = 0x5762B41DC65F7BDEi64;
    v132.m128_u64[1] = 0x9A750144576BA16Cui64;
    v40 = (__m128)_mm_load_si128((const __m128i *)&v132);
    v133.m128_u64[0] = 0xC5C8A31004D3D84Dui64;
    v133.m128_u64[1] = 0x1CC6499730382159i64;
    v76.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v76.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v87.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v98.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v131 = _mm_xor_ps(v39, v76);                // Decrypted UTF-16: apimonit
    v98.m128_u64[1] = 0x1CC64997304B2120i64;
    v133 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v133), v98);// Decrypted UTF-16: 64.sys
    v132 = _mm_xor_ps(v40, v87);                // Decrypted UTF-16: or-drv-x
    memset(v158, 0, sizeof(v158));
    do
      ++v38;
    while ( v131.m128_i16[v38] );
    std_vector_push_back(v158, &v131, v38);
    v88.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v134.m128_u64[0] = 0x722EC9A3C5850DF6i64;
    v41 = -1i64;
    v134.m128_u64[1] = 0xC1CDA6CA7F76CCD3ui64;
    v42 = (__m128)_mm_load_si128((const __m128i *)&v134);
    v135.m128_u64[0] = 0x5762B41DC65F7BDEi64;
    v135.m128_u64[1] = 0x9A750144576BA16Cui64;
    v43 = (__m128)_mm_load_si128((const __m128i *)&v135);
    v136.m128_u64[0] = 0xC5C8A31004D1D843ui64;
    v136.m128_u64[1] = 0x1CC6499730382159i64;
    v77.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v77.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v88.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v99.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v134 = _mm_xor_ps(v42, v77);                // Decrypted UTF-16: apimonit
    v99.m128_u64[1] = 0x1CC64997304B2120i64;
    v136 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v136), v99);// Decrypted UTF-16: 86.sys
    v135 = _mm_xor_ps(v43, v88);                // Decrypted UTF-16: or-drv-x
    memset(v159, 0, sizeof(v159));
    do
      ++v41;
    while ( v134.m128_i16[v41] );
    std_vector_push_back(v159, &v134, v41);
    v89.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v137.m128_u64[0] = 0x722EC9A3C5850DF6i64;
    v44 = -1i64;
    v137.m128_u64[1] = 0xC1CDA6CA7F76CCD3ui64;
    v45 = (__m128)_mm_load_si128((const __m128i *)&v137);
    v138.m128_u64[0] = 0x5776B41DC65F7BDEi64;
    v138.m128_u64[1] = 0x9A7501445773A16Dui64;
    v46 = (__m128)_mm_load_si128((const __m128i *)&v138);
    v139.m128_u64[0] = 0xC5C8A31004D3D84Dui64;
    v139.m128_u64[1] = 0x1CC6499730382159i64;
    v78.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v78.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v89.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v100.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v137 = _mm_xor_ps(v45, v78);                // Decrypted UTF-16: apimonit
    v100.m128_u64[1] = 0x1CC64997304B2120i64;
    v139 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v139), v100);// Decrypted UTF-16: 64.sys
    v138 = _mm_xor_ps(v46, v89);                // Decrypted UTF-16: or-psn-x
    memset(v160, 0, sizeof(v160));
    do
      ++v44;
    while ( v137.m128_i16[v44] );
    std_vector_push_back(v160, &v137, v44);
    v90.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v140.m128_u64[0] = 0x722EC9A3C5850DF6i64;
    v47 = -1i64;
    v140.m128_u64[1] = 0xC1CDA6CA7F76CCD3ui64;
    v48 = (__m128)_mm_load_si128((const __m128i *)&v140);
    v141.m128_u64[0] = 0x5776B41DC65F7BDEi64;
    v141.m128_u64[1] = 0x9A7501445773A16Dui64;
    v49 = (__m128)_mm_load_si128((const __m128i *)&v141);
    v142.m128_u64[0] = 0xC5C8A31004D1D843ui64;
    v142.m128_u64[1] = 0x1CC6499730382159i64;
    v79.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v79.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v90.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v101.m128_u64[0] = 0xC5BBA33E04E7D87Bui64;
    v140 = _mm_xor_ps(v48, v79);                // Decrypted UTF-16: apimonit
    v101.m128_u64[1] = 0x1CC64997304B2120i64;
    v142 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v142), v101);// Decrypted UTF-16: 86.sys
    v141 = _mm_xor_ps(v49, v90);                // Decrypted UTF-16: or-psn-x
    memset(v161, 0, sizeof(v161));
    do
      ++v47;
    while ( v140.m128_i16[v47] );
    std_vector_push_back(v161, &v140, v47);
    v113.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v112.m128_u64[0] = 0x7235C9ADC5970DF3i64;
    v103.m128_u64[0] = 0x7243C9CAC5F50D97i64;
    v112.m128_u64[1] = 0xC1CAA6DA7F6BCC92ui64;
    v50 = (__m128)_mm_load_si128((const __m128i *)&v112);
    v113.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v51 = (__m128)_mm_load_si128((const __m128i *)&v113);
    v104.m128_u64[0] = 0x5706B430C62D7BB1i64;
    v103.m128_u64[1] = 0xC1B9A6A37F18CCBCui64;
    v104.m128_u64[1] = 0x9A0D0169571DA11Eui64;
    v113 = _mm_xor_ps(v51, v104);               // Decrypted UTF-8: 
    v112 = _mm_xor_ps(v50, v103);               // Decrypted Raw (unprintable): 64 00 62 00 67 00 76 00 84 59 a4 ee a3 21 b3 b5
    memset(v162, 0, sizeof(v162));
    do
      ++v10;
    while ( v112.m128_i16[v10] );
    std_vector_push_back(v162, &v112, v10);
    v115 = 0i64;
    v106 = v163;
    v52 = 14i64;
    v107 = v149;
    v114 = 0i64;
    std_vector_alloc_3((unsigned __int64 *)&v114, 14ui64, &v107, &v106);
    v53 = (__int64 *)v163;
    do
    {
      v53 -= 4;
      sub_FFFFF801BCEF4B20(v53);
      --v52;
    }
    while ( v52 );
    *((_QWORD *)Dest + 75) = 0i64;
    memset(Dest, 0, 0x258ui64);
    MmUnloadedDrivers = (_MM_UNLOADED_DRIVER *)FindNtMmUnloadedDrivers();
    PsLoadedModuleResource = FindNtPsLoadedModuleResource();
    v107 = (__int128 *)PsLoadedModuleResource;
    if ( MmUnloadedDrivers && PsLoadedModuleResource )
    {
      ExAcquireResourceExclusiveLiteFn = (void (__fastcall *)(__int64, BOOLEAN))(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
      ExReleaseResourceLiteFn = (void (__fastcall *)(__int64))(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
      KeLeaveCriticalRegionFn = (void (*)(void))(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
      ((void (*)(void))(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
      LOBYTE(v57) = 1;
      ExAcquireResourceExclusiveLiteFn(PsLoadedModuleResource, v57);
      v58 = *(_QWORD *)&MmUnloadedDrivers->Name.Length;
      if ( *(_QWORD *)&MmUnloadedDrivers->Name.Length )
      {
        v59 = 0;
        LODWORD(v106) = 0;
        v60 = 0;
        v61 = v58 + 8;
        do
        {
          if ( v59 )
            break;
          if ( *(_QWORD *)v61 )
          {
            if ( *(_WORD *)(v61 - 8) )
            {
              if ( *(_WORD *)(v61 - 6) )
              {
                v62 = 0i64;
                v63 = (__int64)(*((_QWORD *)&v114 + 1) - v114) >> 5;
                if ( v63 )
                {
                  v64 = v114;
                  do
                  {
                    if ( v59 )
                      break;
                    v65 = (wchar_t *)v64;
                    if ( *(_QWORD *)(v64 + 24) > 7ui64 )
                      v65 = *(wchar_t **)v64;
                    if ( wcsistr(v65, *(wchar_t **)v61) )// Compare vector element with unloaded driver name
                    {
                      *((_QWORD *)Dest + 75) = *(_QWORD *)(v61 + 0x18);
                      v59 = 1;
                      if ( (*(_WORD *)(v61 - 8) & 0xFFFEu) >= 0x256 )
                        v66 = 299i64;
                      else
                        v66 = (unsigned __int64)*(unsigned __int16 *)(v61 - 8) >> 1;
                      wcsncpy(Dest, *(const wchar_t **)v61, v66);
                    }
                    ++v62;
                    v64 += 32i64;
                  }
                  while ( v62 < v63 );
                  v60 = (unsigned int)v106;
                }
              }
            }
          }
          ++v60;
          v61 += sizeof(_MM_UNLOADED_DRIVER);
          LODWORD(v106) = v60;
        }
        while ( v60 < 50 );                     // MM_UNLOADED_DRIVERS_SIZE
        v6 = a2;
        PsLoadedModuleResource = (__int64)v107;
        v4 = a4;
        v5 = a3;
      }
      ExReleaseResourceLiteFn(PsLoadedModuleResource);
      KeLeaveCriticalRegionFn();
    }
    if ( v5 < 0x260 )
    {
      *(_QWORD *)(v4 + 0x38) = 0i64;
      *(_DWORD *)(v4 + 0x30) = 0xC0000004;
    }
    else
    {
      *(_DWORD *)(v4 + 0x30) = 0;
      v67 = 4i64;
      *(_QWORD *)(v4 + 0x38) = 0x260i64;
      do
      {
        *v6 = *(_OWORD *)Dest;
        v6[1] = *((_OWORD *)Dest + 1);
        v6[2] = *((_OWORD *)Dest + 2);
        v6[3] = *((_OWORD *)Dest + 3);
        v6[4] = *((_OWORD *)Dest + 4);
        v6[5] = *((_OWORD *)Dest + 5);
        v6[6] = *((_OWORD *)Dest + 6);
        v6 += 8;
        v68 = *((_OWORD *)Dest + 7);
        Dest += 64;
        *(v6 - 1) = v68;
        --v67;
      }
      while ( v67 );
      *v6 = *(_OWORD *)Dest;
      v6[1] = *((_OWORD *)Dest + 1);
      v6[2] = *((_OWORD *)Dest + 2);
      v6[3] = *((_OWORD *)Dest + 3);
      v6[4] = *((_OWORD *)Dest + 4);
      v6[5] = *((_OWORD *)Dest + 5);
    }
    return sub_FFFFF801BCEF4A94((__int64)&v114);
  }
  return result;
}

__int64 __fastcall EmacVerifyPhysicalMemoryHandles(char *Dest, __int64 a2, unsigned int a3, __int64 a4)
{
  unsigned int v5; // r15d
  char *v7; // rbx
  __int64 result; // rax
  void (__fastcall *ExFreePoolWithTagFn)(BOOLEAN (__stdcall *)(HANDLE), _QWORD); // r13
  __int64 v11; // r12
  SYSTEM_HANDLE_INFORMATION *SystemHandleInformation; // rax MAPDST
  __int64 i; // r15
  __int64 UniqueProcessId; // rcx
  __int128 v17; // xmm1
  PVOID PhysicalMemoryObject; // [rsp+20h] [rbp-48h] MAPDST
  BOOLEAN (__stdcall *ObIsKernelHandleFn)(HANDLE); // [rsp+28h] [rbp-40h] BYREF
  void (__fastcall *ObfDereferenceObjectFn)(PVOID); // [rsp+30h] [rbp-38h]

  v5 = a3;
  v7 = Dest;
  result = KeGetCurrentIrql();
  if ( (_BYTE)result )
  {
    *(_QWORD *)(a4 + 56) = 0i64;
    *(_DWORD *)(a4 + 48) = 0xC0000148;
  }
  else
  {
    *((_DWORD *)Dest + 150) = 0;
    memset(Dest, 0, 0x258ui64);
    ExFreePoolWithTagFn = (void (__fastcall *)(BOOLEAN (__stdcall *)(HANDLE), _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ObfDereferenceObjectFn = (void (__fastcall *)(PVOID))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    ObIsKernelHandleFn = (BOOLEAN (__stdcall *)(HANDLE))(((unsigned __int64)ObIsKernelHandle ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ObIsKernelHandle ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
    PhysicalMemoryObject = EmacGetPhysicalMemoryObject();
    v11 = 4i64;
    if ( PhysicalMemoryObject )
    {
      SystemHandleInformation = (SYSTEM_HANDLE_INFORMATION *)EmacQuerySystemHandleInformation();
      if ( SystemHandleInformation )
      {
        i = 0i64;
        if ( SystemHandleInformation->NumberOfHandles )
        {
          while ( SystemHandleInformation->Handles[i].Object != PhysicalMemoryObject
               || SystemHandleInformation->Handles[i].UniqueProcessId == 4
               || ObIsKernelHandleFn((HANDLE)SystemHandleInformation->Handles[i].HandleValue) )
          {
            i = (unsigned int)(i + 1);
            if ( (unsigned int)i >= SystemHandleInformation->NumberOfHandles )
              goto LABEL_12;
          }
          *((_DWORD *)v7 + 0x96) = SystemHandleInformation->Handles[i].UniqueProcessId;
          UniqueProcessId = SystemHandleInformation->Handles[i].UniqueProcessId;
          ObIsKernelHandleFn = 0i64;
          if ( EmacGetSectionMappedFileName(UniqueProcessId, (PUNICODE_STRING *)&ObIsKernelHandleFn, 0i64) )
          {
            wcsncpy(
              (wchar_t *)v7,
              *((const wchar_t **)ObIsKernelHandleFn + 1),
              (unsigned __int64)*(unsigned __int16 *)ObIsKernelHandleFn >> 1);
            ExFreePoolWithTagFn(ObIsKernelHandleFn, 'CAME');
          }
        }
LABEL_12:
        ExFreePoolWithTagFn((BOOLEAN (__stdcall *)(HANDLE))SystemHandleInformation, 'CAME');
        v5 = a3;
      }
      ObfDereferenceObjectFn(PhysicalMemoryObject);
    }
    result = 0x25Ci64;
    if ( v5 < 0x25C )
    {
      *(_QWORD *)(a4 + 56) = 0i64;
      *(_DWORD *)(a4 + 48) = 0xC0000004;
    }
    else
    {
      *(_DWORD *)(a4 + 48) = 0;
      *(_QWORD *)(a4 + 56) = 0x25Ci64;
      do
      {
        *(_OWORD *)a2 = *(_OWORD *)v7;
        *(_OWORD *)(a2 + 16) = *((_OWORD *)v7 + 1);
        *(_OWORD *)(a2 + 32) = *((_OWORD *)v7 + 2);
        *(_OWORD *)(a2 + 48) = *((_OWORD *)v7 + 3);
        *(_OWORD *)(a2 + 64) = *((_OWORD *)v7 + 4);
        *(_OWORD *)(a2 + 80) = *((_OWORD *)v7 + 5);
        *(_OWORD *)(a2 + 96) = *((_OWORD *)v7 + 6);
        a2 += 0x80i64;
        v17 = *((_OWORD *)v7 + 7);
        v7 += 0x80;
        *(_OWORD *)(a2 - 16) = v17;
        --v11;
      }
      while ( v11 );
      *(_OWORD *)a2 = *(_OWORD *)v7;
      *(_OWORD *)(a2 + 16) = *((_OWORD *)v7 + 1);
      *(_OWORD *)(a2 + 32) = *((_OWORD *)v7 + 2);
      *(_OWORD *)(a2 + 48) = *((_OWORD *)v7 + 3);
      *(_OWORD *)(a2 + 64) = *((_OWORD *)v7 + 4);
      *(_QWORD *)(a2 + 80) = *((_QWORD *)v7 + 10);
      result = *((unsigned int *)v7 + 22);
      *(_DWORD *)(a2 + 88) = result;
    }
  }
  return result;
}

__int64 __fastcall EmacVerifyPiDDBCacheTable(wchar_t *Dest, _OWORD *a2, unsigned int a3, __int64 a4)
{
  __int64 v4; // r13
  _OWORD *v5; // r15
  wchar_t *v6; // r14
  __int64 result; // rax
  void (__fastcall *ExAcquireResourceExclusiveLiteFn)(__int64, __int64); // rdi
  __int64 v9; // rsi
  bool RtlIsGenericTableFn; // bl
  __int64 v11; // rdx
  __int64 v12; // rdi
  char v13; // si
  __int64 *v14; // rbx
  int v15; // eax
  __m128 *p_src; // rdx
  size_t v17; // r8
  __m128 v18; // xmm0
  __m128 v19; // xmm0
  __m128 si128; // xmm0
  __int128 v21; // xmm1
  __m128 v22; // [rsp+20h] [rbp-79h] BYREF
  __int64 PiDDBLock; // [rsp+30h] [rbp-69h]
  __m128 v24; // [rsp+40h] [rbp-59h] BYREF
  __m128 v25; // [rsp+50h] [rbp-49h] BYREF
  __m128 src; // [rsp+60h] [rbp-39h] BYREF
  void (__fastcall *ExReleaseResourceLiteFn)(__int64); // [rsp+70h] [rbp-29h]
  void (*KeLeaveCriticalRegionFn)(void); // [rsp+78h] [rbp-21h]
  __m128 v29; // [rsp+80h] [rbp-19h]
  __m128i v30; // [rsp+90h] [rbp-9h] BYREF
  __m128 v31; // [rsp+A0h] [rbp+7h]
  __m128 v32; // [rsp+B0h] [rbp+17h]

  v4 = a4;
  v5 = a2;
  v6 = Dest;
  result = KeGetCurrentIrql();
  if ( (_BYTE)result )
  {
    *(_QWORD *)(a4 + 56) = 0i64;
    *(_DWORD *)(a4 + 48) = -1073741496;
    return result;
  }
  memset(Dest, 0, 0x258ui64);
  memset(v6 + 300, 0, 0x12Cui64);
  *((_DWORD *)v6 + 225) = 0;
  v22.m128_u64[0] = FindNtPiDDBCacheTable();
  PiDDBLock = FindNtPiDDBLock();
  result = 7i64;
  if ( !v22.m128_u64[0] || !PiDDBLock )
    goto LABEL_20;
  KeLeaveCriticalRegionFn = (void (*)(void))(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExAcquireResourceExclusiveLiteFn = (void (__fastcall *)(__int64, __int64))(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  v9 = RtlIsGenericTable ^ qword_FFFFF801BCFACC40;
  ExReleaseResourceLiteFn = (void (__fastcall *)(__int64))(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  RtlIsGenericTableFn = (RtlIsGenericTable ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38;
  ((void (*)(void))(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))();
  LOBYTE(v11) = 1;
  ExAcquireResourceExclusiveLiteFn(PiDDBLock, v11);
  if ( ((unsigned __int8 (__fastcall *)(unsigned __int64))(v9 & -(__int64)RtlIsGenericTableFn))(v22.m128_u64[0]) )// PiDDBCacheTable
    goto LABEL_19;
  v12 = *(_QWORD *)(v22.m128_u64[0] + 16);
  v13 = 0;
  v14 = *(__int64 **)(v12 + 32);
  if ( v14 == *(__int64 **)(v12 + 40) )
    goto LABEL_18;
  while ( !v13 )
  {
    v15 = *((_DWORD *)v14 + 8);
    switch ( v15 )
    {
      case 0x4840B58D:                          // vboxdrv.sys
        *((_DWORD *)v6 + 225) = 0x4840B58D;
        v13 = 1;
        wcsncpy(v6, (const wchar_t *)v14[3], (unsigned __int64)*((unsigned __int16 *)v14 + 8) >> 1);
        src.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        p_src = &src;
        v32.m128_u64[0] = 0x98464433949F8655ui64;
        src.m128_u64[0] = 0x98464433ECF0C403ui64;
        v17 = 5i64;
        si128 = (__m128)_mm_load_si128((const __m128i *)&src);
        v32.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        src = _mm_xor_ps(si128, v32);           // Decrypted UTF-8: VBox
        goto LABEL_15;
      case 0x48760777:                          // gdrv.sys
        *((_DWORD *)v6 + 225) = 1215694711;
        v13 = 1;
        wcsncpy(v6, (const wchar_t *)v14[3], (unsigned __int64)*((unsigned __int16 *)v14 + 8) >> 1);
        v25.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        p_src = &v25;
        v31.m128_u64[0] = 0x98464433949F8655ui64;
        v25.m128_u64[0] = 0xDD121D71D5D8CF12ui64;
        v17 = 9i64;
        v19 = (__m128)_mm_load_si128((const __m128i *)&v25);
        v31.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        v25 = _mm_xor_ps(v19, v31);             // Decrypted UTF-8: GIGABYTE
        goto LABEL_15;
      case 0x5284EAC3:                          // iqvw64e.sys
        *((_DWORD *)v6 + 225) = 1384442563;
        v13 = 1;
        wcsncpy(v6, (const wchar_t *)v14[3], (unsigned __int64)*((unsigned __int16 *)v14 + 8) >> 1);
        v24.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        p_src = &v24;
        v30.m128i_i64[0] = 0x98464433949F8655ui64;
        v24.m128_u64[0] = 0x9846445FF1EBE81Cui64;
        v17 = 6i64;
        v30.m128i_i64[1] = 0x9BB72C3A5E74877Eui64;
        v24 = _mm_xor_ps((__m128)_mm_load_si128(&v30), v24);// Decrypted UTF-8: Intel
        goto LABEL_15;
      case 0x57CD1415:                          // Capcom.sys
        *((_DWORD *)v6 + 225) = 1473057813;
        v13 = 1;
        wcsncpy(v6, (const wchar_t *)v14[3], (unsigned __int64)*((unsigned __int16 *)v14 + 8) >> 1);
        v22.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        p_src = &v22;
        v29.m128_u64[0] = 0x98464433949F8655ui64;
        v22.m128_u64[0] = 0x9846295CF7EFE716ui64;
        v17 = 7i64;
        v18 = (__m128)_mm_load_si128((const __m128i *)&v22);
        v29.m128_u64[1] = 0x9BB72C3A5E74877Eui64;
        v22 = _mm_xor_ps(v18, v29);             // Decrypted UTF-8: Capcom
LABEL_15:
        strcpy_and_zero((char *)v6 + 600, (const char *)p_src, v17);
        break;
    }
    v14 = (__int64 *)*v14;
    if ( v14 == *(__int64 **)(v12 + 40) )
      break;
  }
  v5 = a2;
  v4 = a4;
LABEL_18:
  ExReleaseResourceLiteFn(PiDDBLock);
  KeLeaveCriticalRegionFn();
LABEL_19:
  result = 7i64;
LABEL_20:
  if ( a3 < 0x388 )
  {
    *(_QWORD *)(v4 + 56) = 0i64;
    *(_DWORD *)(v4 + 48) = -1073741820;
  }
  else
  {
    *(_DWORD *)(v4 + 48) = 0;
    *(_QWORD *)(v4 + 56) = 904i64;
    do
    {
      *v5 = *(_OWORD *)v6;
      v5[1] = *((_OWORD *)v6 + 1);
      v5[2] = *((_OWORD *)v6 + 2);
      v5[3] = *((_OWORD *)v6 + 3);
      v5[4] = *((_OWORD *)v6 + 4);
      v5[5] = *((_OWORD *)v6 + 5);
      v5[6] = *((_OWORD *)v6 + 6);
      v5 += 8;
      v21 = *((_OWORD *)v6 + 7);
      v6 += 64;
      *(v5 - 1) = v21;
      --result;
    }
    while ( result );
    result = *(_QWORD *)v6;
    *(_QWORD *)v5 = *(_QWORD *)v6;
  }
  return result;
}

__int64 __fastcall EmacVerifySystemImagesPte(ULONG64 a1)
{
  void (__fastcall *KeEnterCriticalRegionFn)(); // r15
  void (__fastcall *KeStackAttachProcessFn)(PEPROCESS, __int64 *); // r14
  void (__fastcall *ExAcquireResourceExclusiveLiteFn)(void *, __int64); // r12
  __int64 (__fastcall *IoGetCurrentProcessFn)(); // rsi
  unsigned __int8 (__fastcall *MmIsAddressValidFn)(void *); // r13 MAPDST
  struct _KPROCESS *Process; // rax
  __int64 v9; // rdx
  _KLDR_DATA_TABLE_ENTRY *i; // rbx
  wchar_t *FullDllName_Buffer; // rdx
  unsigned int FullDllName_Length; // ecx
  unsigned __int16 FullDllName_MaxLength; // ax
  unsigned __int64 v14; // r8
  void *fileBuffer; // rax MAPDST
  _IMAGE_NT_HEADERS64 *v17; // rax
  _IMAGE_NT_HEADERS64 *v18; // r14
  IMAGE_SECTION_HEADER *section; // rsi
  char *sectionAddress; // r15 MAPDST
  __int64 *PDE; // rax MAPDST
  __int64 PDEEntry; // rcx
  __int64 *PTE; // rax
  __int64 *PTEEntry; // r15
  void (__fastcall *ExFreePoolWithTagFn)(void *, _QWORD); // [rsp+20h] [rbp-E0h]
  void *NtPsLoadedModuleResource; // [rsp+28h] [rbp-D8h]
  void (__fastcall *ExReleaseResourceLiteFn)(void *); // [rsp+30h] [rbp-D0h]
  void (*KeLeaveCriticalRegionFn)(void); // [rsp+38h] [rbp-C8h]
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+40h] [rbp-C0h]
  __int64 ApcState; // [rsp+48h] [rbp-B8h] BYREF
  __int128 v32; // [rsp+50h] [rbp-B0h]
  __int128 v33; // [rsp+60h] [rbp-A0h]
  __int64 v34; // [rsp+70h] [rbp-90h]
  wchar_t FileName[336]; // [rsp+80h] [rbp-80h] BYREF
  bool IsAttached; // [rsp+330h] [rbp+230h]
  USHORT y; // [rsp+338h] [rbp+238h]

  ApcState = 0i64;
  v32 = 0i64;
  v34 = 0i64;
  v33 = 0i64;
  NtPsLoadedModuleResource = (void *)FindNtPsLoadedModuleResource();
  memset(FileName, 0, 0x258ui64);
  ExFreePoolWithTagFn = (void (__fastcall *)(void *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeEnterCriticalRegionFn = (void (__fastcall *)())(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeEnterCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeLeaveCriticalRegionFn = (void (*)(void))(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeLeaveCriticalRegion ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeStackAttachProcessFn = (void (__fastcall *)(PEPROCESS, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExAcquireResourceExclusiveLiteFn = (void (__fastcall *)(void *, __int64))(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAcquireResourceExclusiveLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExReleaseResourceLiteFn = (void (__fastcall *)(void *))(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExReleaseResourceLite ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  IoGetCurrentProcessFn = (__int64 (__fastcall *)())(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetCurrentProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  MmIsAddressValidFn = (unsigned __int8 (__fastcall *)(void *))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( !a1 )
    return 0xC000000Di64;
  memset((void *)a1, 0, 0x280ui64);
  if ( !g_AttachedProcess || !PsLoadedModuleList || !NtPsLoadedModuleResource )
    return 0xC0000138i64;
  if ( !MmIsAddressValidFn(PsLoadedModuleList) || !MmIsAddressValidFn(NtPsLoadedModuleResource) )
    return 0xC0000005i64;
  if ( PsLoadedModuleList->Flink == PsLoadedModuleList )
    return 0xC0000001i64;
  Process = (struct _KPROCESS *)IoGetCurrentProcessFn();
  IsAttached = Process != g_AttachedProcess;
  if ( Process != g_AttachedProcess )
    KeStackAttachProcessFn(g_AttachedProcess, &ApcState);
  KeEnterCriticalRegionFn();
  LOBYTE(v9) = 1;
  ExAcquireResourceExclusiveLiteFn(NtPsLoadedModuleResource, v9);
  for ( i = (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList->Flink;
        i != (_KLDR_DATA_TABLE_ENTRY *)PsLoadedModuleList;
        i = (_KLDR_DATA_TABLE_ENTRY *)i->InLoadOrderLinks.Flink )
  {
    memset(FileName, 0, 0x258ui64);
    FullDllName_Buffer = i->FullDllName.Buffer;
    if ( FullDllName_Buffer )
    {
      FullDllName_Length = i->FullDllName.Length;
      if ( FullDllName_Length > 2 )
      {
        FullDllName_MaxLength = i->FullDllName.MaximumLength;
        if ( FullDllName_MaxLength > 2u && (unsigned __int16)FullDllName_Length <= FullDllName_MaxLength )
        {
          if ( (FullDllName_Length & 0xFFFE) >= 0x256 )
            v14 = 299i64;
          else
            v14 = (unsigned __int64)i->FullDllName.Length >> 1;
          wcsncpy(FileName, FullDllName_Buffer, v14);
          fileBuffer = ReadFileToBuffer(FileName, 0i64);
          if ( fileBuffer )
          {
            v17 = RtlImageNtHeader((_IMAGE_DOS_HEADER *)fileBuffer);
            v18 = v17;
            if ( v17 )
            {
              if ( v17->Signature == 0x4550 && v17->OptionalHeader.Magic == 0x20B )
              {
                section = (IMAGE_SECTION_HEADER *)&v17[1];
                y = 0;
                if ( v17->FileHeader.NumberOfSections )
                {
                  do
                  {
                    if ( (section->Characteristics & 0x2000000) != 0 )// IMAGE_SCN_MEM_EXECUTE
                    {
                      sectionAddress = (char *)i->DllBase + section->VirtualAddress;
                      if ( MmIsAddressValidFn(sectionAddress) )
                      {
                        PDE = (__int64 *)EmacGetPDE((ULONG *)&sectionAddress, 0i64);
                        if ( PDE )
                        {
                          if ( MmIsAddressValidFn(PDE) )
                          {
                            PDEEntry = *PDE;
                            if ( (*PDE & 1) != 0 )// Present
                            {
                              if ( (PDEEntry & 0x80u) == 0i64 )// Not large page
                              {
                                PTE = (__int64 *)EmacGetPTE((ULONG *)&sectionAddress, 0i64);
                                PTEEntry = PTE;
                                if ( PTE && MmIsAddressValidFn(PTE) && (*PTEEntry & 3) == 3 && *PTEEntry >= 0 )// Page present and writable
                                {
LABEL_39:
                                  *(_QWORD *)a1 = i->DllBase;
                                  *(_QWORD *)(a1 + 16) = EmacGetHeaderImageSize((ULONG64)fileBuffer);
                                  *(_QWORD *)(a1 + 8) = i->SizeOfImage;
                                  *(_QWORD *)(a1 + 24) = section->Misc.PhysicalAddress;
                                  wcscpy((wchar_t *)(a1 + 32), FileName);
                                  strcpy_and_zero((char *)(a1 + 0x278), (const char *)section, 8ui64);// section name
                                  break;
                                }
                              }
                              else if ( (PDEEntry & 3) == 3 && PDEEntry >= 0 )
                              {
                                goto LABEL_39;
                              }
                            }
                          }
                        }
                      }
                    }
                    ++section;
                    ++y;
                  }
                  while ( y < v18->FileHeader.NumberOfSections );
                }
              }
            }
            ExFreePoolWithTagFn(fileBuffer, 'CAME');
          }
          if ( *(_QWORD *)a1 )
            break;
        }
      }
    }
  }
  ExReleaseResourceLiteFn(NtPsLoadedModuleResource);
  KeLeaveCriticalRegionFn();
  if ( IsAttached )
    KeUnstackDetachProcessFn(&ApcState);
  return 0i64;
}

__int64 __fastcall EmacVerifyWin32kBase_gDxgkInterfaceTable(__int64 a1, _OWORD *a2, unsigned int a3, __int64 a4)
{
  __int64 v4; // rbx
  unsigned int v5; // r12d
  __int64 fileBuffer; // rax
  void (__fastcall *ExFreePoolWithTagFn)(_QWORD, _QWORD); // r14
  void (__fastcall *KeStackAttachProcessFn)(_QWORD, _QWORD); // r13
  __m128 si128; // xmm0
  __m128 v12; // xmm1
  __m128 v13; // xmm0
  __m128 v14; // xmm0
  __m128 v15; // xmm1
  __m128 v16; // xmm0
  __m128 v17; // xmm1
  __int64 v18; // r15
  SYSTEM_PROCESS_INFORMATION *SystemProcessInformation; // rax MAPDST
  void (__fastcall *v21)(KAPC_STATE *); // rbx
  wchar_t *Buffer; // rcx
  __m128 v23; // xmm0
  ULONG_PTR UniqueProcessId; // rcx
  unsigned __int16 *Win32kbase_gDxgkInterface; // rax
  unsigned __int64 v26; // r13
  unsigned __int64 v27; // r14
  unsigned __int64 *v28; // r12
  unsigned __int64 v29; // r15
  NTSTATUS PoolTagFromBaseAddress; // eax
  unsigned __int64 KeUnstackDetachProcessFn; // [rsp+20h] [rbp-E0h] BYREF
  void (__fastcall *v32)(_QWORD, _QWORD); // [rsp+28h] [rbp-D8h]
  wchar_t moduleName[8]; // [rsp+30h] [rbp-D0h] BYREF
  __m128 v34; // [rsp+40h] [rbp-C0h] BYREF
  KAPC_STATE ApcState; // [rsp+50h] [rbp-B0h] BYREF
  __m128 v36; // [rsp+80h] [rbp-80h]
  __m128 v37; // [rsp+90h] [rbp-70h]
  __m128 v38; // [rsp+A0h] [rbp-60h]
  wchar_t fileName[8]; // [rsp+B0h] [rbp-50h] BYREF
  __m128 v40; // [rsp+C0h] [rbp-40h] BYREF
  __m128i v41; // [rsp+D0h] [rbp-30h] BYREF
  __m128 v42; // [rsp+E0h] [rbp-20h] BYREF
  __m128 v43; // [rsp+F0h] [rbp-10h] BYREF
  __m128 v44; // [rsp+100h] [rbp+0h] BYREF
  int (__fastcall *PsLookupProcessByProcessIdFn)(ULONG_PTR, unsigned __int64 *); // [rsp+110h] [rbp+10h]
  _IMAGE_NT_HEADERS64 *imageNtHeaders; // [rsp+118h] [rbp+18h]
  _IMAGE_DOS_HEADER *imageBase; // [rsp+120h] [rbp+20h]
  void (__fastcall *ObfDereferenceObjectFn)(unsigned __int64); // [rsp+128h] [rbp+28h]
  void (__fastcall *v50)(_QWORD, _QWORD); // [rsp+138h] [rbp+38h]
  __int64 v51; // [rsp+140h] [rbp+40h]

  v4 = a4;
  v5 = a3;
  fileBuffer = KeGetCurrentIrql();
  if ( (_BYTE)fileBuffer )
  {
    *(_QWORD *)(a4 + 56) = 0i64;
    *(_DWORD *)(a4 + 48) = -1073741496;
  }
  else
  {
    *(_OWORD *)a1 = 0i64;
    v34.m128_u64[1] = 0x740A870091BC9538i64;
    *(_OWORD *)(a1 + 16) = 0i64;
    *(_DWORD *)(a1 + 24) = -1;
    ApcState.ApcListHead[1].Blink = (struct _LIST_ENTRY *)0x740A870091BC9538i64;
    ExFreePoolWithTagFn = (void (__fastcall *)(_QWORD, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40)));
    v50 = ExFreePoolWithTagFn;
    PsLookupProcessByProcessIdFn = (int (__fastcall *)(ULONG_PTR, unsigned __int64 *))(((unsigned __int64)PsLookupProcessByProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)PsLookupProcessByProcessId ^ qword_FFFFF801BCFACC40)));
    KeStackAttachProcessFn = (void (__fastcall *)(_QWORD, _QWORD))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40)));
    v32 = KeStackAttachProcessFn;
    KeUnstackDetachProcessFn = ((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40));
    ObfDereferenceObjectFn = (void (__fastcall *)(unsigned __int64))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40)));
    wmemcpy(moduleName, L"蘱铧䑔頭蜌帚ⱖ鮙쁤垭⻪紉", 12);
    si128 = (__m128)_mm_load_si128((const __m128i *)moduleName);
    ApcState.ApcListHead[0].Flink = (struct _LIST_ENTRY *)0x98464433949F8655i64;
    ApcState.ApcListHead[0].Blink = (struct _LIST_ENTRY *)0x9BB72C3A5E74877Ei64;
    ApcState.ApcListHead[1].Flink = (struct _LIST_ENTRY *)0x7D092E9957D4C017i64;
    v34 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&ApcState.ApcListHead[1]), v34);// Decrypted UTF-16: sys
    *(__m128 *)moduleName = _mm_xor_ps(si128, (__m128)ApcState.ApcListHead[0]);
    fileBuffer = (__int64)EmacFindKernelModule(moduleName, 0i64);
    imageBase = (_IMAGE_DOS_HEADER *)fileBuffer;
    if ( fileBuffer )
    {
      ApcState.ApcListHead[1].Blink = (struct _LIST_ENTRY *)0x740A870091BC9538i64;
      wmemcpy(fileName, L"蘉铌䑊頵蜊帑ⱗ鯥쁸垻⻭絕镫釅蝳瑾陜倛ᶔ㺾콜힍﻿둱", 28);
      v44.m128_u64[0] = 0xDD8C2401DB38A1FFui64;
      v44.m128_u64[1] = 0xD698B0285FC85F20ui64;
      v12 = (__m128)_mm_load_si128((const __m128i *)&v40);
      v42.m128_u64[1] = 0xF3D35BCC9F19DDC0ui64;
      v43.m128_u64[0] = 0xDA7101D529359936ui64;
      v43.m128_u64[1] = 0x1728923B297AC1E8i64;
      ApcState.ApcListHead[0].Flink = (struct _LIST_ENTRY *)0x98464433949F8655i64;
      ApcState.ApcListHead[0].Blink = (struct _LIST_ENTRY *)0x9BB72C3A5E74877Ei64;
      v13 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&ApcState), *(__m128 *)fileName);
      ApcState.ApcListHead[1].Flink = (struct _LIST_ENTRY *)0x7D092E9957D4C017i64;
      ApcState.Process = (struct _KPROCESS *)0xEBBE1DA750769639i64;
      *(_QWORD *)&ApcState.InProgressFlags = 0xF6C3CF2EF7923EE2ui64;
      v36.m128_u64[0] = 0xB402FE8DE95AD7FBui64;
      *(__m128 *)fileName = v13;                // Decrypted UTF-16: \Sys
      v14 = _mm_xor_ps((__m128)_mm_load_si128(&v41), *(__m128 *)&ApcState.Process);
      v40 = _mm_xor_ps(v12, (__m128)ApcState.ApcListHead[1]);// Decrypted Raw (unprintable): 6f 00 6f 00 74 00 5c 00 46 12 c8 cf 3a ab bd ef
      v15 = (__m128)_mm_load_si128((const __m128i *)&v42);
      v36.m128_u64[1] = 0xF3B45BB49F7DDD9Cui64;
      v37.m128_u64[0] = 0xDA1D01BB2947995Dui64;
      v41 = (__m128i)v14;                       // Decrypted Raw (unprintable): 65 00 6d 00 33 00 32 00 da ab 2e 66 2e 48 c9 82
      v16 = (__m128)_mm_load_si128((const __m128i *)&v43);
      v42 = _mm_xor_ps(v15, v36);               // Decrypted Raw (unprintable): 76 00 65 00 72 00 73 00 96 3f 4d a8 fd 07 62 1c
      v17 = (__m128)_mm_load_si128((const __m128i *)&v44);
      v38.m128_u64[0] = 0xDD8C2401DB38A1FFui64;
      v38.m128_u64[1] = 0xD698B0285FC85F20ui64;
      v37.m128_u64[1] = 0x175B92422909C1C6i64;
      v43 = _mm_xor_ps(v16, v37);               // Decrypted Raw (unprintable): 6b 00 72 00 6e 00 6c 00 fe 54 b5 b8 42 15 51 63
      v44 = _mm_xor_ps(v17, v38);
      fileBuffer = (__int64)ReadFileToBuffer(fileName, 0i64);
      v51 = fileBuffer;
      v18 = fileBuffer;
      if ( fileBuffer )
      {
        imageNtHeaders = RtlImageNtHeader((_IMAGE_DOS_HEADER *)fileBuffer);
        SystemProcessInformation = EmacQuerySystemProcessInformation();
        if ( SystemProcessInformation )
        {
          if ( SystemProcessInformation->NextEntryOffset )
          {
            v21 = (void (__fastcall *)(KAPC_STATE *))KeUnstackDetachProcessFn;
            do
            {
              Buffer = SystemProcessInformation->ImageName.Buffer;
              if ( Buffer )
              {
                wmemcpy(
                  moduleName,
                  L"蘶铬䑁頵蜍幚ⱟ鯏쁲埔⺙紉锸醼蜀琊處钟䐳顆蝾年ⰺ鮷쀗埔⺙紉锸醼蜀琊",
                  32);
                v23 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)moduleName), (__m128)ApcState.ApcListHead[0]);
                v34 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v34), (__m128)ApcState.ApcListHead[1]);// Decrypted UTF-8: e
                *(__m128 *)moduleName = v23;    // Decrypted UTF-16: csrsrnl.
                if ( wcsstr(Buffer, moduleName) )// csrss.exe
                {
                  if ( SystemProcessInformation->SessionId )
                  {
                    UniqueProcessId = SystemProcessInformation->UniqueProcessId;
                    KeUnstackDetachProcessFn = 0i64;
                    memset(&ApcState, 0, sizeof(ApcState));
                    if ( PsLookupProcessByProcessIdFn(UniqueProcessId, &KeUnstackDetachProcessFn) >= 0 )
                    {
                      KeStackAttachProcessFn(KeUnstackDetachProcessFn, &ApcState);
                      Win32kbase_gDxgkInterface = (unsigned __int16 *)FindWin32kbase_gDxgkInterface();
                      if ( Win32kbase_gDxgkInterface )
                      {
                        v26 = 0i64;
                        v27 = ((unsigned __int64)*Win32kbase_gDxgkInterface - 16) >> 3;
                        if ( v27 )
                        {
                          v28 = (unsigned __int64 *)(Win32kbase_gDxgkInterface + 8);
                          while ( 1 )
                          {
                            v29 = *v28;
                            if ( *v28 )
                            {
                              if ( !EmacIsAddressInCodeSectionRange(*v28, imageBase, imageNtHeaders) )
                                break;
                            }
                            ++v26;
                            ++v28;
                            if ( v26 >= v27 )
                              goto LABEL_17;
                          }
                          *(_BYTE *)a1 = 1;
                          *(_DWORD *)(a1 + 4) = v26;
                          *(_QWORD *)(a1 + 16) = v29;
                          *(_QWORD *)(a1 + 8) = v28;
                          PoolTagFromBaseAddress = EmacGetPoolTagFromBaseAddress(v29, (_DWORD *)(a1 + 24));
                          KeStackAttachProcessFn = v32;
                          if ( (PoolTagFromBaseAddress & 0xC0000000) == 0xC0000000 )
                            *(_DWORD *)(a1 + 24) = -1;
                        }
                        else
                        {
LABEL_17:
                          KeStackAttachProcessFn = v32;
                        }
                      }
                      v21(&ApcState);
                      ObfDereferenceObjectFn(KeUnstackDetachProcessFn);
                    }
                  }
                }
              }
              SystemProcessInformation = (SYSTEM_PROCESS_INFORMATION *)((char *)SystemProcessInformation
                                                                      + SystemProcessInformation->NextEntryOffset);
            }
            while ( SystemProcessInformation->NextEntryOffset );
            v4 = a4;
            ExFreePoolWithTagFn = v50;
            v18 = v51;
            v5 = a3;
          }
          ExFreePoolWithTagFn(SystemProcessInformation, 'CAME');
        }
        fileBuffer = ((__int64 (__fastcall *)(__int64, __int64))ExFreePoolWithTagFn)(v18, 0x43414D45i64);
      }
    }
    if ( v5 < 32 )
    {
      *(_QWORD *)(v4 + 0x38) = 0i64;
      *(_DWORD *)(v4 + 0x30) = 0xC0000004;
    }
    else
    {
      *(_DWORD *)(v4 + 0x30) = 0;
      *(_QWORD *)(v4 + 0x38) = 0x20i64;
      *a2 = *(_OWORD *)a1;
      a2[1] = *(_OWORD *)(a1 + 16);
    }
  }
  return fileBuffer;
}