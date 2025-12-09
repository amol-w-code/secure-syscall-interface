// monitor_core.cpp
#include <windows.h>
#include <iostream>
#include <string>

// --- NEW: Authentication Check ---
// Checks if the process token has elevated privileges (Admin)
bool IsAppRunningAsAdmin() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    
    // Open the Access Token of the current process
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        
        // Query the Token for "Elevation" status
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
    }
    
    if (hToken) {
        CloseHandle(hToken);
    }
    return fIsElevated;
}

// Helper to determine threat level
std::string get_severity(DWORD eventCode) {
    if (eventCode == CREATE_PROCESS_DEBUG_EVENT) return "HIGH";
    if (eventCode == LOAD_DLL_DEBUG_EVENT) return "MEDIUM";
    if (eventCode == CREATE_THREAD_DEBUG_EVENT) return "LOW";
    if (eventCode == EXIT_PROCESS_DEBUG_EVENT) return "HIGH";
    return "LOW";
}

// Helper to name the event
std::string get_event_name(DWORD eventCode) {
    switch(eventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: return "PROCESS_CREATE";
        case CREATE_THREAD_DEBUG_EVENT:  return "THREAD_CREATE";
        case EXIT_THREAD_DEBUG_EVENT:    return "THREAD_EXIT";
        case EXIT_PROCESS_DEBUG_EVENT:   return "PROCESS_EXIT";
        case LOAD_DLL_DEBUG_EVENT:       return "LOAD_LIBRARY_DLL";
        case UNLOAD_DLL_DEBUG_EVENT:     return "UNLOAD_LIBRARY";
        case OUTPUT_DEBUG_STRING_EVENT:  return "DEBUG_OUTPUT";
        case EXCEPTION_DEBUG_EVENT:      return "EXCEPTION_THROWN";
        default: return "UNKNOWN_EVENT";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: monitor_core.exe <program_path>" << std::endl;
        return 1;
    }

    // --- NEW: Broadcast Authentication Level ---
    if (IsAppRunningAsAdmin()) {
        std::cout << "AUTH_LEVEL|ADMIN|System has granted full kernel access." << std::endl;
    } else {
        std::cout << "AUTH_LEVEL|USER|Limited rights. Sandboxed mode." << std::endl;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::string cmd = argv[1];
    
    // 1. Launch the target process in DEBUG mode
    if (!CreateProcessA(
            NULL, 
            (LPSTR)cmd.c_str(), 
            NULL, NULL, FALSE, 
            DEBUG_ONLY_THIS_PROCESS, 
            NULL, NULL, &si, &pi)
    ) {
        std::cerr << "CreateProcess failed (" << GetLastError() << ")." << std::endl;
        return 1;
    }

    // 2. The Loop: Wait for events
    DEBUG_EVENT debugEvent = {0};
    bool isRunning = true;

    while (isRunning) {
        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            break;

        std::string name = get_event_name(debugEvent.dwDebugEventCode);
        std::string severity = get_severity(debugEvent.dwDebugEventCode);
        
        // Print in format: NAME|SEVERITY|ID
        std::cout << name << "|" << severity << "|" << debugEvent.dwProcessId << std::endl;

        if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            isRunning = false;
        }

        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}