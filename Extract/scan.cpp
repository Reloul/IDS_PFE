#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <cstdlib>
#include <sstream>


std::vector<std::wstring> dirsToWatch = {
    L"C:\\Windows\\System32",
    L"C:\\Windows\\SysWOW64",
    L"C:\\Windows",
    L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    L"C:\\Windows\\Temp",
    L"C:\\Program Files",
    L"C:\\Program Files (x86)",
    L"C:\\Users"
    // Ajoutez d'autres chemins selon vos besoins
};

std::mutex coutMutex;

void AnalyzeFileWithPython(const std::wstring& filePath) {
    std::wstringstream command;
    command << L"python detect.py \"" << filePath << L"\"";
    
    int result = _wsystem(command.str().c_str());
    
    if (result == 1) { // Si le script retourne 1 → Malware détecté
        std::wcerr << L"[DETECTION MALWARE] Le fichier " << filePath << L" est potentiellement un malware !" << std::endl;
    }
}

void WatchDirectory(const std::wstring& path) {
    HANDLE hDir = CreateFileW(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::wcerr << L"Erreur lors de l'ouverture du répertoire : " << path << std::endl;
        return;
    }

     {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::wcout << L"[OK] Surveillance activée : " << path << std::endl;
    }


    char buffer[1024];
    DWORD bytesReturned;

    while (true) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL
        )) {
            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
            do {
                // Récupérer le nom du fichier modifié
                std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                 // Analyse immédiate du fichier détecté
                std::wstring fullPath = path + L"\\" + fileName;
                AnalyzeFileWithPython(fullPath);
                // Passer au prochain événement (si présent)
                fni = fni->NextEntryOffset ? reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset) : nullptr;
            } while (fni);
        } else {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::wcerr << L"[ERREUR] Problème lors de la surveillance de : " << path << std::endl;
            break;
        }
    }

    CloseHandle(hDir);
}

int main() {
    std::vector<std::thread> watchThreads;
    bool atLeastOneSuccess = false;

    for (const auto& dir : dirsToWatch) {
        HANDLE hDir = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hDir != INVALID_HANDLE_VALUE) {
            CloseHandle(hDir);  // Vérification réussie, on peut surveiller ce dossier
            watchThreads.emplace_back(WatchDirectory, dir);
            atLeastOneSuccess = true;
        } else {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::wcerr << L"[ERREUR] Accès refusé ou problème avec : " << dir << std::endl;
        }
    }

    if (!atLeastOneSuccess) {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::wcerr << L"[FATAL] Aucun répertoire surveillé ! Vérifiez les permissions administratives." << std::endl;
        system("pause");
        return 1;
    }

    for (auto& thread : watchThreads) {
        thread.join();
    }

    system("pause"); // Pour garder la fenêtre ouverte sur Windows
    return 0;
}
