#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

namespace instr {
    // Constants.
    //
    static constexpr uint32_t proc_instr_cb = 40;
    static constexpr uint32_t max_modules = 128;
    static constexpr uint32_t max_log_buf = 512;
    static constexpr uint32_t module_name_len = 32;

    // Stack layout offsets.
    //
    static constexpr size_t ctx_size = 0x4f0;
    static constexpr size_t ex_record_off = 0x4f0;

    // Undocumented structures.
    //
    struct s_proc_instr_cb_info {
        uint32_t m_version;
        uint32_t m_reserved;
        void* m_callback;
    };

    struct s_io_status_block {
        union {
            NTSTATUS m_status;
            void* m_pointer;
        };
        ULONG_PTR m_information;
    };

    // Stack context matching ASM push order.
    //
    struct s_stack_context {
        uint64_t m_r11;
        uint64_t m_r10;
        uint64_t m_r9;
        uint64_t m_r8;
        uint64_t m_rdx;
        uint64_t m_rcx;
        uint64_t m_rax;
        uint64_t m_rflags;
    };

    // Module cache.
    //
    struct s_module_info {
        uint64_t m_base;
        uint64_t m_end;
        char m_name[module_name_len];
    };

    // Function types.
    //
    using fn_nt_write_file = NTSTATUS (NTAPI*)(
        HANDLE file_handle,
        HANDLE event,
        void* apc_routine,
        void* apc_context,
        s_io_status_block* io_status_block,
        void* buffer,
        ULONG length,
        LARGE_INTEGER* byte_offset,
        ULONG* key
        );

    using fn_nt_set_info_proc = NTSTATUS (NTAPI*)(HANDLE, UINT, PVOID, ULONG);
    using fn_nt_queue_apc = NTSTATUS (NTAPI*)(HANDLE, void*, ULONG_PTR, ULONG_PTR, ULONG_PTR);
}

// Public API (C linkage for export).
//
extern "C" {
    bool instr_init ();
    void instr_shutdown ();
    uint32_t instr_get_module_count ();
}