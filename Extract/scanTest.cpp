#include <windows.h>
#include <iostream>
#include <string>

void WatchDirectory(const std::wstring& path) {
    HANDLE hDir = CreateFileW(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Erreur lors de l'ouverture du répertoire" << std::endl;
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;

    while (true) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE, // Surveiller récursivement
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL
        )) {
            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
            do {
                // Récupérer le nom du fichier modifié
                std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                std::wcout << L"Fichier modifié ou créé : " << fileName << std::endl;

                // Passer au prochain événement (si présent)
                fni = fni->NextEntryOffset ? reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset) : nullptr;
            } while (fni);
        } else {
            std::wcerr << L"Erreur lors de la lecture des changements dans le répertoire" << std::endl;
            break;
        }
    }

    CloseHandle(hDir);
}

int main() {
    std::wstring directoryToWatch = L"C:\\Users\\valentin\\Desktop\\code"; // Changez ce chemin selon vos besoins
    std::wcout << L"Surveillance du répertoire : " << directoryToWatch << std::endl;
    WatchDirectory(directoryToWatch);
    return 0;
}
