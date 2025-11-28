.code

extern handle_callback: proc

instrumentation_callback proc
    pushfq
    
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    sub rsp, 80h
    movdqu xmmword ptr [rsp + 00h], xmm0
    movdqu xmmword ptr [rsp + 10h], xmm1
    movdqu xmmword ptr [rsp + 20h], xmm2
    movdqu xmmword ptr [rsp + 30h], xmm3
    movdqu xmmword ptr [rsp + 40h], xmm4
    movdqu xmmword ptr [rsp + 50h], xmm5
    
    ; Current stack: 8 (rflags) + 56 (gprs) + 128 (xmm) = 192 bytes.
    ; Need shadow space (32 bytes) + alignment (8).
    ;
    sub rsp, 28h
    
    ; RDX = pointer to saved context (RSP + 0x28 + 0x80 to skip XMM and shadow space)
    ;
    mov rcx, r10
    lea rdx, [rsp + 28h + 80h]
    call handle_callback
    
    add rsp, 28h
    
    movdqu xmm0, xmmword ptr [rsp + 00h]
    movdqu xmm1, xmmword ptr [rsp + 10h]
    movdqu xmm2, xmmword ptr [rsp + 20h]
    movdqu xmm3, xmmword ptr [rsp + 30h]
    movdqu xmm4, xmmword ptr [rsp + 40h]
    movdqu xmm5, xmmword ptr [rsp + 50h]
    add rsp, 80h

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    
    popfq

    jmp r10
instrumentation_callback endp

end