// monitor_core.cpp
#include <windows.h>
#include <iostream>
#include <string>

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

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::string cmd = argv[1];
    
    // 1. Launch the target process in DEBUG mode
    if (!CreateProcessA(
            NULL, 
            (LPSTR)cmd.c_str(), // Command line
            NULL, NULL, FALSE, 
            DEBUG_ONLY_THIS_PROCESS, // <--- The Magic Flag
            NULL, NULL, &si, &pi)
    ) {
        std::cerr << "CreateProcess failed (" << GetLastError() << ")." << std::endl;
        return 1;
    }

    // 2. The Loop: Wait for events from the Operating System
    DEBUG_EVENT debugEvent = {0};
    bool isRunning = true;

    while (isRunning) {
        // Wait for a debug event
        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            break;

        std::string name = get_event_name(debugEvent.dwDebugEventCode);
        std::string severity = get_severity(debugEvent.dwDebugEventCode);
        
        // Print in format: NAME|SEVERITY|ID
        std::cout << name << "|" << severity << "|" << debugEvent.dwProcessId << std::endl;

        // Check if the process exited
        if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            isRunning = false;
        }

        // Resume the process
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}