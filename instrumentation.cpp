#include "instrumentation.hpp"
#include <psapi.h>
#include <stdio.h>

extern "C" void instrumentation_callback ();

namespace instr {
    // Globals.
    //
    static uint32_t g_tls_idx = TLS_OUT_OF_INDEXES;
    static HANDLE g_console = INVALID_HANDLE_VALUE;

    static s_module_info g_modules[max_modules] = {};
    static uint32_t g_module_count = 0;

    static uint64_t g_ntdll_start = 0;
    static uint64_t g_ntdll_end = 0;
    static uint64_t g_win32u_start = 0;
    static uint64_t g_win32u_end = 0;

    static fn_nt_write_file g_nt_write_file = nullptr;

    static void* g_apc_dispatcher = nullptr;
    static void* g_exception_dispatcher = nullptr;
    static void* g_ldr_init_thunk = nullptr;

    // String builder.
    //
    class c_log_builder {
        char* m_ptr;
        char* m_end;
        char* m_start;

        friend void safe_log (c_log_builder& log);

    public:
        c_log_builder (char* buf, size_t size) : m_ptr (buf), m_end (buf + size), m_start (buf) {}

        c_log_builder& hex (uint64_t val, int digits = 16) {
            for (int i = digits - 1; i >= 0 && m_ptr < m_end; --i) {
                const auto nibble = (val >> (i * 4)) & 0xf;
                *m_ptr++ = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            return *this;
        }

        c_log_builder& str (const char* s) {
            while (*s && m_ptr < m_end)
                *m_ptr++ = *s++;
            return *this;
        }

        c_log_builder& ch (char c) {
            if (m_ptr < m_end)
                *m_ptr++ = c;
            return *this;
        }

        c_log_builder& ptr (const void* p, const char* mod = nullptr) {
            str ("0x").hex (reinterpret_cast<uint64_t> (p));
            if (mod)
                str (" (").str (mod).ch (')');
            return *this;
        }

        c_log_builder& line () {
            return str ("\r\n");
        }

        c_log_builder& indent () {
            return str ("  ");
        }

        size_t size () const {
            return m_ptr - m_start;
        }

        void term () {
            if (m_ptr < m_end)
                *m_ptr = '\0';
        }
    };

    // Cache all loaded modules.
    //
    static void cache_modules () {
        HMODULE mods[256] = {};
        DWORD needed = 0;

        if (!EnumProcessModules (GetCurrentProcess (), mods, sizeof (mods), &needed))
            return;

        const auto count = needed / sizeof (HMODULE);
        g_module_count = 0;

        for (size_t i = 0; i < count && g_module_count < max_modules; ++i) {
            MODULEINFO mi = {};
            if (!GetModuleInformation (GetCurrentProcess (), mods[i], &mi, sizeof (mi)))
                continue;

            auto& mod = g_modules[g_module_count];
            mod.m_base = reinterpret_cast<uint64_t> (mi.lpBaseOfDll);
            mod.m_end = mod.m_base + mi.SizeOfImage;

            GetModuleBaseNameA (GetCurrentProcess (), mods[i], mod.m_name, sizeof (mod.m_name));

            if (_stricmp (mod.m_name, "ntdll.dll") == 0) {
                g_ntdll_start = mod.m_base;
                g_ntdll_end = mod.m_end;

                const auto ntdll_module = reinterpret_cast<HMODULE>(mod.m_base);
                g_nt_write_file = reinterpret_cast<fn_nt_write_file>(
                    GetProcAddress (ntdll_module, "NtWriteFile")
                    );
            } else if (_stricmp (mod.m_name, "win32u.dll") == 0) {
                g_win32u_start = mod.m_base;
                g_win32u_end = mod.m_end;
            }

            ++g_module_count;
        }
    }

    // Find module by address.
    //
    static const char* find_module (const void* addr) {
        const auto rip = reinterpret_cast<uint64_t>(addr);

        for (uint32_t i = 0; i < g_module_count; ++i) {
            if (rip >= g_modules[i].m_base && rip < g_modules[i].m_end)
                return g_modules[i].m_name;
        }

        return "unknown";
    }

    static void safe_log (c_log_builder& log) {
        if (!g_nt_write_file)
            return;

        s_io_status_block iosb = {};
        g_nt_write_file (g_console, nullptr, nullptr, nullptr, &iosb,
            log.m_start, static_cast<ULONG>(log.size ()), nullptr, nullptr);
    }

    // Check if syscall.
    //
    static bool is_syscall (void* addr) {
        const auto rip = reinterpret_cast<uint64_t>(addr);

        if ((rip >= g_ntdll_start && rip < g_ntdll_end) ||
            (rip >= g_win32u_start && rip < g_win32u_end)) {

            const auto* bytes = reinterpret_cast<const uint8_t*> (rip - 2);

            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery (bytes, &mbi, sizeof (mbi)) == 0)
                return false;

            if (mbi.State != MEM_COMMIT)
                return false;

            return bytes[0] == 0x0f && bytes[1] == 0x05;
        }

        return false;
    }

    // Exception handler.
    // [RSP + 0x000] = CONTEXT (0x4F0 with CONTEXT_EX + alignment)
    // [RSP + 0x4F0] = EXCEPTION_RECORD (0x98)
    //
    static void handle_exception (void* ret_addr, s_stack_context* ctx) {
        const auto module = find_module (ret_addr);
        auto* stack_ptr = reinterpret_cast<uint8_t*>(ctx + 1);

        auto* context = reinterpret_cast<CONTEXT*>(stack_ptr);
        auto* ex_record = reinterpret_cast<EXCEPTION_RECORD*>(stack_ptr + ex_record_off);

        char buf[max_log_buf];
        c_log_builder log (buf, sizeof (buf));

        log.line ()
            .str ("[exception]").line ()
            .indent ().str ("return address: ").ptr (ret_addr, module).line ()
            .indent ().str ("exception code: ").ptr (reinterpret_cast<void*>(static_cast<uint64_t>(ex_record->ExceptionCode))).line ()
            .indent ().str ("exception addr: ").ptr (ex_record->ExceptionAddress, find_module (ex_record->ExceptionAddress)).line ()
            .indent ().str ("context rip:    ").ptr (reinterpret_cast<void*>(context->Rip), find_module (reinterpret_cast<void*>(context->Rip))).line ()
            .indent ().str ("context rax:    ").ptr (reinterpret_cast<void*>(context->Rax)).line ()
            .term ();

        safe_log (log);
    }

    // APC handler.
    // [RSP + 0x18] = NormalRoutine
    //
    static void handle_apc (void* ret_addr, s_stack_context* ctx) {
        const auto module = find_module (ret_addr);
        const auto* stack = reinterpret_cast<const uint64_t*>(ctx + 1);

        const auto normal_routine = reinterpret_cast<void*>(stack[3]);
        const auto normal_context = stack[1];
        const auto system_arg1 = stack[2];
        const auto system_arg2 = stack[0];

        char buf[max_log_buf];
        c_log_builder log (buf, sizeof (buf));

        log.line ()
            .str ("[apc]").line ()
            .indent ().str ("return address:   ").ptr (ret_addr, module).line ()
            .indent ().str ("normal routine:   ").ptr (normal_routine, find_module (normal_routine)).line ()
            .indent ().str ("normal context:   ").ptr (reinterpret_cast<void*>(normal_context)).line ()
            .indent ().str ("system argument1: ").ptr (reinterpret_cast<void*>(system_arg1)).line ()
            .indent ().str ("system argument2: ").ptr (reinterpret_cast<void*>(system_arg2)).line ()
            .term ();

        safe_log (log);
    }

    // Thread initialization handler.
    // LdrInitializeThunk signature:
    // void LdrInitializeThunk(
    //     PCONTEXT NormalContext,      // RCX
    //     PVOID SystemArgument1,       // RDX  
    //     PVOID SystemArgument2        // R8
    // )
    //
    static void handle_thread (void* ret_addr, s_stack_context* ctx) {
        const auto module = find_module (ret_addr);

        const auto* context = reinterpret_cast<CONTEXT*>(ctx->m_rcx);

        char buf[max_log_buf];
        c_log_builder log (buf, sizeof (buf));

        log.line ()
            .str ("[thread_init]").line ()
            .indent ().str ("return address: ").ptr (ret_addr, module).line ()
            .indent ().str ("context ptr:    ").ptr (context).line ()
            .indent ().str ("start address:  ").ptr (reinterpret_cast<void*>(context->Rip), find_module (reinterpret_cast<void*>(context->Rip))).line ()
            .indent ().str ("thread param:   ").ptr (reinterpret_cast<void*>(context->Rcx), find_module (reinterpret_cast<void*>(context->Rcx))).line ()
            .term ();

        safe_log (log);
    }

    // Syscall handler.
    //
    static void handle_syscall (void* ret_addr, s_stack_context*) {
        char buf[max_log_buf];
        c_log_builder log (buf, sizeof (buf));

        log.line ()
            .str ("[syscall]").line ()
            .indent ().str ("return address: ").ptr (ret_addr, find_module (ret_addr)).line ()
            .term ();

        safe_log (log);
    }

    // Install callback.
    //
    static bool install_callback () {
        const auto ntdll = GetModuleHandleA ("ntdll.dll");
        if (!ntdll)
            return false;

        const auto nt_set = reinterpret_cast<fn_nt_set_info_proc>(
            GetProcAddress (ntdll, "NtSetInformationProcess")
            );

        if (!nt_set)
            return false;

        g_apc_dispatcher = GetProcAddress (ntdll, "KiUserApcDispatcher");
        g_exception_dispatcher = GetProcAddress (ntdll, "KiUserExceptionDispatcher");
        g_ldr_init_thunk = GetProcAddress (ntdll, "LdrInitializeThunk");

        s_proc_instr_cb_info info = {};
        info.m_version = 0;
        info.m_reserved = 0;
        info.m_callback = reinterpret_cast<void*>(&instrumentation_callback);

        const auto status = nt_set (
            GetCurrentProcess (),
            proc_instr_cb,
            &info,
            sizeof (info)
        );

        return status == 0;
    }
}

// Main callback dispatcher.
//
extern "C" void handle_callback (void* ret_addr, instr::s_stack_context* ctx) {
    using namespace instr;

    if (g_tls_idx == TLS_OUT_OF_INDEXES)
        return;

    if (TlsGetValue (g_tls_idx))
        return;

    TlsSetValue (g_tls_idx, reinterpret_cast<void*>(1));

    if (ret_addr == g_exception_dispatcher) {
        handle_exception (ret_addr, ctx);
    } else if (ret_addr == g_apc_dispatcher) {
        handle_apc (ret_addr, ctx);
    } else if (ret_addr == g_ldr_init_thunk) {
        handle_thread (ret_addr, ctx);
    } else if (is_syscall (ret_addr)) {
        handle_syscall (ret_addr, ctx);
    } else {
        char buf[max_log_buf];
        c_log_builder log (buf, sizeof (buf));

        log.line ()
            .str ("[unknown]").line ()
            .indent ().str ("return address: ").ptr (ret_addr, find_module (ret_addr)).line ()
            .term ();

        safe_log (log);
    }

    TlsSetValue (g_tls_idx, nullptr);
}

// Public API (C linkage).
//
extern "C" bool instr_init () {
    using namespace instr;

    g_console = GetStdHandle (STD_OUTPUT_HANDLE);

    g_tls_idx = TlsAlloc ();
    if (g_tls_idx == TLS_OUT_OF_INDEXES)
        return false;

    cache_modules ();

    if (!g_nt_write_file) {
        TlsFree (g_tls_idx);
        return false;
    }

    if (!install_callback ()) {
        TlsFree (g_tls_idx);
        return false;
    }

    return true;
}

extern "C" void instr_shutdown () {
    using namespace instr;

    if (g_tls_idx != TLS_OUT_OF_INDEXES)
        TlsFree (g_tls_idx);
}

extern "C" uint32_t instr_get_module_count () {
    return instr::g_module_count;
}