import sys
import joblib
import pefile
import numpy as np
import pickle
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Chemin du dossier contenant le script

# Charger les modèles et les features attendues
clf_PE_path = os.path.join(BASE_DIR, "..", "Classifier", "classifier.pkl")
features_PE_path = os.path.join(BASE_DIR, "..", "Classifier", "features.pkl")

clf_IAT_path = os.path.join(BASE_DIR, "..", "Classifier", "classifier_IAT.pkl")
features_IAT_path = os.path.join(BASE_DIR, "..", "Classifier", "features_IAT.pkl")

clf_PE = joblib.load(clf_PE_path)
features_PE = pickle.loads(open(features_PE_path, "rb").read())

clf_IAT = joblib.load(clf_IAT_path)
features_IAT = pickle.loads(open(features_IAT_path, "rb").read())

def is_pe_file(file_path):
    if not os.path.isfile(file_path):
        return False
    try:
        pefile.PE(file_path)
        return True
    except Exception:
        return False

def extract_pe_features(file_path):
    """ Extrait les features de l'en-tête PE. """
    if not is_pe_file(file_path):
        return None
    try:
        pe = pefile.PE(file_path)
        pe_features = [
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.SizeOfOptionalHeader,
            pe.FILE_HEADER.Characteristics,
            pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.BaseOfCode
        ]
        
        # Compléter avec des 0 si nécessaire
        while len(pe_features) < len(features_PE):
            pe_features.append(0)

        return np.array(pe_features[:len(features_PE)]).reshape(1, -1)
    except Exception as e:
        print(f"Erreur extraction PE : {e}")
        return None

def extract_iat_features(file_path):
    """ Extrait les features de l'IAT (Import Address Table). """
    if not is_pe_file(file_path):
        return None
    try:
        pe = pefile.PE(file_path)
        dll_features = {dll: 0 for dll in features_IAT}  # Initialise toutes les valeurs à 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8').lower()
                if dll_name in dll_features:
                    dll_features[dll_name] = 1  # Marquer la présence de la DLL

        return np.array(list(dll_features.values())).reshape(1, -1)
    except Exception as e:
        print(f"Erreur extraction IAT : {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect.py <fichier>")
        sys.exit(0)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Erreur : Le fichier {file_path} n'existe pas.")
        sys.exit(0)

    # Extraire les features PE et IAT
    features_PE = extract_pe_features(file_path)
    features_IAT = extract_iat_features(file_path)

    # Vérifier si l'extraction a réussi
    if features_PE is not None and features_IAT is not None:
        pred_PE = clf_PE.predict(features_PE)[0]
        pred_IAT = clf_IAT.predict(features_IAT)[0]

        # Combiner les prédictions (ex: une détection suffit pour alerter)
        if pred_PE == 1 or pred_IAT == 1:
            sys.exit(1)  # Malware détecté
        else:
            sys.exit(0)  # Fichier légitime
    else:
        print("Erreur lors de l'extraction des features.")
        sys.exit(0)
