; https://rstforums.com/forum/topic/34018-masm-iat-hook/
; IAT Hook
; steve10120@ic0de.org

; #########################################################################

      .586
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################
      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\comdlg32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib

; #########################################################################  
.data
    szDLL db "user32.dll",0
    szAPI db "MessageBoxA",0
    szHooked db "API Hooked",0
    szText db "Hello World!",0
    szCaption db "http://ic0de.org",0

.data?
    dwOldProtect dd ?
    pMessageBoxA dd ?

.code

HookIAT proc inModule:DWORD, inHookProc:DWORD, inOriginalFunction:DWORD

    PUSH ESI
    PUSH EDI
    MOV EDI, inModule
    ASSUME EDI:PTR IMAGE_DOS_HEADER
    CMP [EDI].e_magic, IMAGE_DOS_SIGNATURE
    JNE CodeFail
    ADD EDI, DWORD PTR[EDI+03Ch]
    ASSUME EDI:PTR IMAGE_NT_HEADERS
    CMP [EDI].Signature, IMAGE_NT_SIGNATURE
    JNE CodeFail
    MOV EDI, [EDI].OptionalHeader.DataDirectory[8].VirtualAddress
    ADD EDI, inModule
    ASSUME EDI:PTR IMAGE_IMPORT_DESCRIPTOR

ImportLoop:
    CMP [EDI].FirstThunk, 0
    Je OriginalThunk
    MOV ESI, [EDI].FirstThunk
    JMP ContinueMain
OriginalThunk:
    MOV ESI, [EDI].OriginalFirstThunk
ContinueMain:
    ADD ESI, inModule

ThunkLoop:
    MOV EAX, [inOriginalFunction]
    MOV [pMessageBoxA], EAX
    CMP DWORD PTR[ESI], EAX
    JNE ContinueThunks    
    MOV EBX, [inHookProc]
    invoke VirtualProtect, ESI, 4, PAGE_EXECUTE_READWRITE, OFFSET dwOldProtect
    MOV DWORD PTR[ESI], EBX
    XOR EAX, EAX
    INC EAX

ContinueThunks:
    ADD ESI, 4
    CMP DWORD PTR[ESI], 0
    JNE ThunkLoop


    ADD EDI, sizeof(IMAGE_IMPORT_DESCRIPTOR)
    CMP [EDI].Name1, 0
    JNE ImportLoop


CodeFail:   
    XOR EAX, EAX
HookEnd:
    POP EDI
    POP ESI
    MOV ESP, EBP
    POP EBP
    RETN 0Ch

HookIAT endp

MessageBoxAHookProc proc hWindow:DWORD, lpszText:DWORD, lpszCaption:DWORD, uStyle:DWORD

    PUSH 0
    PUSH OFFSET szCaption
    PUSH OFFSET szHooked
    PUSH 0
    CALL [pMessageBoxA]

    MOV ESP, EBP
    POP EBP
    RETN 010h   
MessageBoxAHookProc endp

start:
    invoke LoadLibraryA, OFFSET szDLL
    TEST EAX, EAX
    JE EndMain
    invoke GetProcAddress, EAX, OFFSET szAPI
    TEST EAX, EAX
    JE EndMain
    MOV EBX, EAX
    invoke GetModuleHandleA, NULL
    TEST EAX, EAX
    JE EndMain
    invoke HookIAT, EAX, OFFSET MessageBoxAHookProc, EBX

    invoke MessageBoxA, 0, OFFSET szText, OFFSET szAPI, 0

EndMain:
    RETN
end start
