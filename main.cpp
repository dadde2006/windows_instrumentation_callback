#include "instrumentation.hpp"
#include <stdio.h>
#include <process.h>

static unsigned __stdcall thread_func (void*) {
    return 0;
}

static void test_thread_creation () {
    const auto handle = CreateThread (nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(thread_func), nullptr, 0, nullptr);

    if (handle) {
        WaitForSingleObject (handle, INFINITE);
        CloseHandle (handle);
    }
}

static void test_exception () {
    __try {
        auto* ptr = reinterpret_cast<volatile uint64_t*>(0x4141414141414141);
        *ptr = 0xDEADBEEF;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void NTAPI apc_routine (ULONG_PTR) {}

static void test_apc () {
    const auto ntdll = GetModuleHandleA ("ntdll.dll");
    if (!ntdll)
        return;

    const auto queue_apc = reinterpret_cast<instr::fn_nt_queue_apc>(
        GetProcAddress (ntdll, "NtQueueApcThread")
        );

    if (!queue_apc)
        return;

    queue_apc (GetCurrentThread (), reinterpret_cast<void*>(apc_routine), 0, 0, 0);

    SleepEx (0, TRUE);
}

static void test_syscall_stress () {
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery (nullptr, &mbi, sizeof (mbi));
    VirtualAlloc (nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void test_win32u_syscall () {
    FindWindow (L"1", L"2");
}

int main () {
    LoadLibrary (L"win32u.dll");

    if (!instr_init ()) {
        printf ("[-] init failed\n");
        return 1;
    }

    test_thread_creation ();
    test_exception ();
    test_apc ();
    test_syscall_stress ();
    test_win32u_syscall ();

    getchar ();

    instr_shutdown ();
    return 0;
}