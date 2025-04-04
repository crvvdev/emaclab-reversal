/*
.text:FFFFF801BCEEB1DD                               ; bool __fastcall EmacAntiHypervisorCallVmfunc()
.text:FFFFF801BCEEB1DD                               EmacAntiHypervisorCallVmfunc proc near  ; CODE XREF: EmacAntiHypervisorAdditionalChecks+A1↓p
.text:FFFFF801BCEEB1DD 8B C1                                         mov     eax, ecx
.text:FFFFF801BCEEB1DF 8B CA                                         mov     ecx, edx
.text:FFFFF801BCEEB1E1 0F 01 D4                                      vmfunc
.text:FFFFF801BCEEB1E4 0F 97 C0                                      setnbe  al
.text:FFFFF801BCEEB1E7 C3                                            retn
.text:FFFFF801BCEEB1E7                               EmacAntiHypervisorCallVmfunc endp
*/

bool EmacAntiHypervisorCheckName()
{
  __m128 si128; // xmm0
  wchar_t Str1[2]; // [rsp+20h] [rbp-30h] BYREF
  int v8; // [rsp+24h] [rbp-2Ch]
  int v9; // [rsp+28h] [rbp-28h]
  char v10; // [rsp+2Ch] [rbp-24h]
  wchar_t Str2[8]; // [rsp+30h] [rbp-20h] BYREF
  __m128 v12; // [rsp+40h] [rbp-10h]

  _RAX = 0i64;
  v10 = 0;
  __asm { cpuid }
  v12 = 0i64;
  v12.m128_i32[0] = _RAX;
  *(_QWORD *)Str2 = 0xBC569349D062DCD2ui64;
  *(_QWORD *)&Str2[4] = 0x29AFBCFFCCDD4DF0i64;
  si128 = (__m128)_mm_load_si128((const __m128i *)Str2);
  v12.m128_u64[0] = 0xDA39E026A201B59Fui64;
  v12.m128_u64[1] = 0x29AFBCFFBA956D84i64;
  v8 = _RDX;
  v9 = _RCX;
  *(__m128 *)Str2 = _mm_xor_ps(si128, v12);
  *(_DWORD *)Str1 = _RBX;
  return strcmp((const char *)Str1, (const char *)Str2) == 0;// "Microsoft Hv"
}

/*
.text:FFFFF801BCEEB1E8                               EmacSingleStepHandler proc near         ; DATA XREF: EmacAntiHypervisorChecks+41↓o
.text:FFFFF801BCEEB1E8
.text:FFFFF801BCEEB1E8                               arg_8           = dword ptr  10h
.text:FFFFF801BCEEB1E8
.text:FFFFF801BCEEB1E8 48 87 0C 24                                   xchg    rcx, [rsp]      ; Swap return address with RCX
.text:FFFFF801BCEEB1EC 81 64 24 10 FF FE FF FF                       and     dword ptr [rsp+10h], 0FFFFFEFFh ; Clear Trap Flag (TF)
.text:FFFFF801BCEEB1F4 48 CF                                         iretq                   ; Return from interrupt
.text:FFFFF801BCEEB1F4                               EmacSingleStepHandler endp

.text:FFFFF801BCEEB1F6                               EmacPageFaultHandler proc near          ; DATA XREF: EmacAntiHypervisorChecks+5C↓o
.text:FFFFF801BCEEB1F6
.text:FFFFF801BCEEB1F6                               arg_0           = qword ptr  8
.text:FFFFF801BCEEB1F6
.text:FFFFF801BCEEB1F6 48 83 C4 08                                   add     rsp, 8          ; Skip fault code on stack
.text:FFFFF801BCEEB1FA 48 87 0C 24                                   xchg    rcx, [rsp]      ; xchg trap frame RIP with syscall return address in RCX
.text:FFFFF801BCEEB1FE 48 CF                                         iretq                   ; Return from interrupt
.text:FFFFF801BCEEB1FE                               EmacPageFaultHandler endp ; sp-analysis failed

.text:FFFFF801BCEEB237                               ; __int64 KiErrata1337Present()
.text:FFFFF801BCEEB237                               KiErrata1337Present proc near           ; CODE XREF: EmacAntiHypervisorChecks+74↓p
.text:FFFFF801BCEEB237 41 52                                         push    r10
.text:FFFFF801BCEEB239 B9 01 01 00 C0                                mov     ecx, 0C0000101h ; IA32_GS_BASE
.text:FFFFF801BCEEB23E 0F 32                                         rdmsr
.text:FFFFF801BCEEB240 52                                            push    rdx
.text:FFFFF801BCEEB241 50                                            push    rax
.text:FFFFF801BCEEB242 B9 02 01 00 C0                                mov     ecx, 0C0000102h ; IA32_KERNEL_GS_BASE
.text:FFFFF801BCEEB247 0F 32                                         rdmsr
.text:FFFFF801BCEEB249 52                                            push    rdx             ; Backup original KERNEL_GS_BASE MSR
.text:FFFFF801BCEEB24A 50                                            push    rax
.text:FFFFF801BCEEB24B 0F 01 F8                                      swapgs                  ; Exchanges current GS base register (IA32_GS_BASE) with value at IA32_KERNEL_GS_BASE
.text:FFFFF801BCEEB24E 33 D2                                         xor     edx, edx
.text:FFFFF801BCEEB250 33 C0                                         xor     eax, eax        ; Set KERNEL_GS_BASE MSR to zero
.text:FFFFF801BCEEB252 0F 30                                         wrmsr
.text:FFFFF801BCEEB254 0F 05                                         syscall                 ; Execute the syscall instruction to trigger fault
.text:FFFFF801BCEEB256 4C 8B D1                                      mov     r10, rcx
.text:FFFFF801BCEEB259 B9 02 01 00 C0                                mov     ecx, 0C0000102h
.text:FFFFF801BCEEB25E 58                                            pop     rax
.text:FFFFF801BCEEB25F 5A                                            pop     rdx
.text:FFFFF801BCEEB260 0F 30                                         wrmsr                   ; Restore original KERNEL_GS_BASE MSR
.text:FFFFF801BCEEB262 B9 01 01 00 C0                                mov     ecx, 0C0000101h
.text:FFFFF801BCEEB267 58                                            pop     rax
.text:FFFFF801BCEEB268 5A                                            pop     rdx
.text:FFFFF801BCEEB269 0F 30                                         wrmsr                   ; Restore original GS_BASE MSR
.text:FFFFF801BCEEB26B 49 8B C2                                      mov     rax, r10
.text:FFFFF801BCEEB26E 48 83 E8 03                                   sub     rax, 3
.text:FFFFF801BCEEB272 41 5A                                         pop     r10
.text:FFFFF801BCEEB274 C3                                            retn
.text:FFFFF801BCEEB274                               KiErrata1337Present endp

.text:FFFFF801BCEEB200                               ; __int64 KiErrata704Present()
.text:FFFFF801BCEEB200                               KiErrata704Present proc near            ; CODE XREF: EmacAntiHypervisorChecks+9A↓p
.text:FFFFF801BCEEB200
.text:FFFFF801BCEEB200                               var_20          = qword ptr -20h
.text:FFFFF801BCEEB200                               anonymous_0     = dword ptr -10h
.text:FFFFF801BCEEB200
.text:FFFFF801BCEEB200 41 52                                         push    r10
.text:FFFFF801BCEEB202 B9 84 00 00 C0                                mov     ecx, 0C0000084h ; (IA32_SFMASK) Any bit set here when a system call is executed will be cleared from EFLAGS.
.text:FFFFF801BCEEB207 0F 32                                         rdmsr
.text:FFFFF801BCEEB209 52                                            push    rdx
.text:FFFFF801BCEEB20A 50                                            push    rax
.text:FFFFF801BCEEB20B 25 FF FE FF FF                                and     eax, 0FFFFFEFFh ; Trap flag will be cleared during syscall
.text:FFFFF801BCEEB210 0F 30                                         wrmsr
.text:FFFFF801BCEEB212 9C                                            pushfq
.text:FFFFF801BCEEB213 81 0C 24 00 01 00 00                          or      dword ptr [rsp], 100h ; Set Trap Flag (TF) in EFLAGS
.text:FFFFF801BCEEB21A 9D                                            popfq
.text:FFFFF801BCEEB21B 0F 05                                         syscall                 ; Executing system call will generate single step exception
.text:FFFFF801BCEEB21D 4C 8B D1                                      mov     r10, rcx
.text:FFFFF801BCEEB220 B9 84 00 00 C0                                mov     ecx, 0C0000084h
.text:FFFFF801BCEEB225 58                                            pop     rax
.text:FFFFF801BCEEB226 5A                                            pop     rdx
.text:FFFFF801BCEEB227 0F 30                                         wrmsr                   ; Restore IA32_SFMASK to original value
.text:FFFFF801BCEEB229 49 8B C2                                      mov     rax, r10
.text:FFFFF801BCEEB22C 41 5A                                         pop     r10
.text:FFFFF801BCEEB22E C3                                            retn
.text:FFFFF801BCEEB22E                               KiErrata704Present endp

.text:FFFFF801BCEEB22F                               ; __int64 __fastcall KiErrataSkx55Present(__int64)
.text:FFFFF801BCEEB22F                               KiErrataSkx55Present proc near          ; CODE XREF: EmacAntiHypervisorChecks+A6↓p
.text:FFFFF801BCEEB22F 8E 11                                         mov     ss, word ptr [rcx]
.text:FFFFF801BCEEB231 0F 05                                         syscall                 ; Low latency system call
.text:FFFFF801BCEEB233 48 8B C1                                      mov     rax, rcx
.text:FFFFF801BCEEB236 C3                                            retn
.text:FFFFF801BCEEB236                               KiErrataSkx55Present endp
*/
bool __fastcall EmacHypervisorChecks(void *originalIdt)
{
  USHORT Limit; // bx
  char v3; // r14
  __int64 syscallHandler; // rsi
  unsigned __int64 v5; // rdi
  unsigned __int64 v6; // rbx
  __int64 syscallHandler_1; // r15
  __int64 syscallHandler_2; // r8
  unsigned __int64 v9; // rax
  IDTR idt; // [rsp+20h] [rbp-20h] BYREF
  __int16 v12[8]; // [rsp+30h] [rbp-10h] BYREF
  __int16 StackSegmentReg; // [rsp+60h] [rbp+20h] BYREF

  *(_QWORD *)&idt.Limit = 0i64;
  LOWORD(idt.Base) = 0;
  __sidt(&idt);
  Limit = idt.Limit;
  v3 = 1;
  memmove_2(originalIdt, *(const void **)(&idt.Limit + 1), idt.Limit + 1i64);// Make copy of IDT table
  v12[0] = Limit;
  *(_QWORD *)&v12[1] = originalIdt;
  EmacModifyIDTEntry((unsigned __int16 *)v12, 1u, (__int64)EmacSingleStepHandler);
  EmacModifyIDTEntry((unsigned __int16 *)v12, 14u, (__int64)EmacPageFaultHandler);
  __lidt(v12);
  syscallHandler = KiErrata1337Present();
  StackSegmentReg = GetStackSegmentReg();
  v5 = __readdr(0);
  v6 = __readdr(7u);
  __writedr(0, (unsigned __int64)&StackSegmentReg);// Enable breakpoint 0, any access size = 1 byte
  __writedr(7u, 0x70001ui64);
  syscallHandler_1 = KiErrata704Present();
  syscallHandler_2 = KiErrataSkx55Present((__int64)&StackSegmentReg);
  __writedr(7u, v6);
  __writedr(0, v5);
  __lidt(&idt);                                 // Restore IDT
  v9 = __readmsr(0xC0000082);
  if ( v9 == syscallHandler && v9 == syscallHandler_1 )
    return v9 != syscallHandler_2;
  return v3;
}

bool EmacAntiHypervisorLBR()
{
  unsigned __int64 v0; // r8
  unsigned __int64 v1; // rax
  bool v2; // r9
  __int64 _RAX; // rax
  unsigned __int64 v8; // rax

  v0 = __readmsr(0x1D9u);                       // IA32_DEBUGCTL
  __writemsr(0x1D9u, v0 | 1);                   // Enable LBR logging
  v1 = __readmsr(0x1D9u);
  v2 = (v1 & 1) == 0;
  if ( (v1 & 1) != 0 )
  {
    _RAX = 0i64;
    __asm { cpuid }
    v8 = __readmsr(0x1D9u);
    v2 = (v8 & 1) == 0;
  }
  __writemsr(0x1D9u, v0);
  return v2;
}

__int64 HypervisorTimingChecks()
{
  __int64 v16; // rdi
  unsigned __int8 CurrentIrql; // r10

  KeGetCurrentIrql();
  _RAX = 0i64;
  __asm
  {
    cpuid
    rdtscp
  }
  _RAX = 0i64;
  __asm { cpuid }
  _RAX = 0i64;
  __asm
  {
    cpuid
    rdtscp
  }
  _RAX = 0i64;
  v16 = 1000000i64;
  __asm { cpuid }
  do
  {
    CurrentIrql = KeGetCurrentIrql();
    __writecr8(2ui64);
    _RAX = 0i64;
    __asm
    {
      cpuid
      rdtscp
    }
    __rdtsc();
    _RAX = 0i64;
    __asm { cpuid }
    KeGetCurrentIrql();
    __writecr8(CurrentIrql);
    --v16;
  }
  while ( v16 );
  return 0i64;
}

char EmacAntiHypervisorTrashMsr()
{
  __writemsr(0xDEADBEEF, __readmsr(0xDEADBEEF) & 0xDEADBEEF);
  return 1;
}

/*
.text:FFFFF801BCF13D4C                               ; char EmacAntiHypervisorXsetbv()
.text:FFFFF801BCF13D4C                               EmacAntiHypervisorXsetbv proc near      ; DATA XREF: sub_FFFFF801BCEEB078+7A↑o
.text:FFFFF801BCF13D4C
.text:FFFFF801BCF13D4C                               var_18          = byte ptr -18h
.text:FFFFF801BCF13D4C
.text:FFFFF801BCF13D4C 48 83 EC 18                                   sub     rsp, 18h
.text:FFFFF801BCF13D50 33 C9                                         xor     ecx, ecx
.text:FFFFF801BCF13D52 0F 01 D0                                      xgetbv
.text:FFFFF801BCF13D55 48 C1 E2 20                                   shl     rdx, 20h
.text:FFFFF801BCF13D59 48 0B D0                                      or      rdx, rax
.text:FFFFF801BCF13D5C 48 83 E2 FD                                   and     rdx, 0FFFFFFFFFFFFFFFDh
.text:FFFFF801BCF13D60 48 83 CA 04                                   or      rdx, 4
.text:FFFFF801BCF13D64 48 8B C2                                      mov     rax, rdx
.text:FFFFF801BCF13D67 48 C1 EA 20                                   shr     rdx, 20h
.text:FFFFF801BCF13D6B 0F 01 D1                                      xsetbv                  ; Clear the bit 0 of XCR0 to cause a #GP(0)
.text:FFFFF801BCF13D6E B0 01                                         mov     al, 1
.text:FFFFF801BCF13D70 88 04 24                                      mov     [rsp], al
.text:FFFFF801BCF13D73 EB 05                                         jmp     short loc_FFFFF801BCF13D7A
.text:FFFFF801BCF13D75                               ; ---------------------------------------------------------------------------
.text:FFFFF801BCF13D75 32 C0                                         xor     al, al
.text:FFFFF801BCF13D77 88 04 24                                      mov     [rsp], al
.text:FFFFF801BCF13D7A
.text:FFFFF801BCF13D7A                               loc_FFFFF801BCF13D7A:                   ; CODE XREF: EmacAntiHypervisorXsetbv+27↑j
.text:FFFFF801BCF13D7A 48 83 C4 18                                   add     rsp, 18h
.text:FFFFF801BCF13D7E C3                                            retn
.text:FFFFF801BCF13D7E                               EmacAntiHypervisorXsetbv endp
 */

bool __stdcall EmacAntiHypervisorAdditionalChecks()
{
  __int16 v6; // ax
  int v7[3]; // [rsp+28h] [rbp-40h] BYREF
  char v8; // [rsp+34h] [rbp-34h]
  __m128 v9; // [rsp+40h] [rbp-28h] BYREF
  __m128 v10; // [rsp+50h] [rbp-18h]

  _RAX = 0i64;
  __asm { cpuid }
  v8 = 0;
  v7[0] = _RBX;
  v7[1] = _RDX;
  v7[2] = _RCX;
  v9.m128_u64[0] = 0x935C8E4FD76FD0D8ui64;
  v9.m128_u64[1] = 0x29AFBCFFD6F019EAi64;
  v10.m128_u64[0] = 0xDA39E026A201B59Fui64;
  v10.m128_u64[1] = 0x29AFBCFFBA956D84i64;
  v9 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v9), v10);// "GenuineIntel"
  if ( strcmp((const char *)v7, (const char *)&v9) )// Check if CPUID vendor matches
    return 0;
  v6 = __readcr4();
  if ( (v6 & 0x2000) == 0 )                     // Check Virtual Machine Extensions Enable 
    EmacAntiHypervisorCallVmfunc();

  /*
    ************* THE FOLLOWING CODE DOES NOT APPEARS ON IDA PSEUDOCODE BUT IT'S A PART OF THIS FUNCTION ************************

    .text:FFFFF801BCF13CF9                               loc_FFFFF801BCF13CF9:                   ; CODE XREF: EmacAntiHypervisorAdditionalChecks+97↑j
    .text:FFFFF801BCF13CF9 33 D2                                         xor     edx, edx
    .text:FFFFF801BCF13CFB 33 C9                                         xor     ecx, ecx
    .text:FFFFF801BCF13CFD E8 DB 74 FD FF                                call    EmacAntiHypervisorCallVmfunc
    .text:FFFFF801BCF13D02 B0 01                                         mov     al, 1
    .text:FFFFF801BCF13D04 88 44 24 20                                   mov     [rsp+68h+var_48], al
    .text:FFFFF801BCF13D08 EB 0E                                         jmp     short loc_FFFFF801BCF13D18
    .text:FFFFF801BCF13D0A                               ; ---------------------------------------------------------------------------
    .text:FFFFF801BCF13D0A 3D 1D 00 00 C0                                cmp     eax, 0C000001Dh ; Non-virtualized environment will generate #UD exception
    .text:FFFFF801BCF13D0F 0F 95 C0                                      setnz   al              ; If EAX is not #UD exception code then set AL to 1
    .text:FFFFF801BCF13D12 88 44 24 20                                   mov     [rsp+68h+var_48], al
    .text:FFFFF801BCF13D16 33 FF                                         xor     edi, edi
    .text:FFFFF801BCF13D18
    .text:FFFFF801BCF13D18                               loc_FFFFF801BCF13D18:                   ; CODE XREF: EmacAntiHypervisorAdditionalChecks+AC↑j
    .text:FFFFF801BCF13D18 84 C0                                         test    al, al
    .text:FFFFF801BCF13D1A 75 24                                         jnz     short loc_FFFFF801BCF13D40
    .text:FFFFF801BCF13D1C 48 89 BC 24 80 00 00 00                       mov     [rsp+68h+arg_10], rdi
    .text:FFFFF801BCF13D24 0F 78 BC 24 80 00 00 00                       vmread  [rsp+68h+arg_10], rdi ; Call __vmread
    .text:FFFFF801BCF13D2C B0 01                                         mov     al, 1
    .text:FFFFF801BCF13D2E 88 44 24 20                                   mov     [rsp+68h+var_48], al
    .text:FFFFF801BCF13D32 EB 0C                                         jmp     short loc_FFFFF801BCF13D40
    .text:FFFFF801BCF13D34                               ; ---------------------------------------------------------------------------
    .text:FFFFF801BCF13D34 3D 1D 00 00 C0                                cmp     eax, 0C000001Dh ; Non-virtualized environment will generate #UD exception
    .text:FFFFF801BCF13D39 0F 95 C0                                      setnz   al              ; If EAX is not #UD exception code then set AL to 1
    .text:FFFFF801BCF13D3C 88 44 24 20                                   mov     [rsp+68h+var_48], al
    .text:FFFFF801BCF13D40
    .text:FFFFF801BCF13D40                               loc_FFFFF801BCF13D40:                   ; CODE XREF: EmacAntiHypervisorAdditionalChecks+8D↑j
    .text:FFFFF801BCF13D40                                                                       ; EmacAntiHypervisorAdditionalChecks+9B↑j ...
    .text:FFFFF801BCF13D40 48 8B 5C 24 70                                mov     rbx, [rsp+68h+arg_0]
    .text:FFFFF801BCF13D45 48 83 C4 60                                   add     rsp, 60h
    .text:FFFFF801BCF13D49 5F                                            pop     rdi
    .text:FFFFF801BCF13D4A C3                                            retn
  */
  return 1;
}

char EmacHypervisorCheck()
{
  char v0; // r10
  unsigned __int64 v1; // r9
  unsigned __int64 v2; // rax
  char v3; // r8
  unsigned __int64 v4; // rax
  bool v6; // [rsp+0h] [rbp-18h]

  _disable();
  v0 = 1;
  v1 = __readmsr(0x1D9u) | 1;
  __writemsr(0x1D9u, v1);
  v2 = __readmsr(0x1D9u);
  v3 = v2 & 1;
  __writemsr(0x1D9u, v1 & 0xFFFFFFFFFFFFFFFEui64);
  v4 = __readmsr(0x1D9u);
  v6 = (v4 & 1) == 0;
  _enable();
  if ( !v6 || !v3 )
    return 0;
  return v0;
}