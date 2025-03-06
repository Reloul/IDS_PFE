import sys
import joblib
import pefile
import numpy as np
import pickle
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Récupère le chemin du dossier contenant le script
clf_path = os.path.join(BASE_DIR, "..", "Classifier", "classifier.pkl")
features_path = os.path.join(BASE_DIR, "..", "Classifier", "features.pkl")

# Charger le modèle et les features
clf = joblib.load(clf_path)
features = pickle.loads(open(features_path, "rb").read())

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        pe_features = []

        # Extraction de quelques features PE (tu peux en ajouter d'autres si besoin)
        pe_features.append(pe.FILE_HEADER.Machine)
        pe_features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
        pe_features.append(pe.FILE_HEADER.Characteristics)
        pe_features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        pe_features.append(pe.OPTIONAL_HEADER.SizeOfCode)
        pe_features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
        pe_features.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
        pe_features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_features.append(pe.OPTIONAL_HEADER.BaseOfCode)

        # Compléter avec des 0 si la taille est inférieure au nombre de features attendues
        while len(pe_features) < len(features):
            pe_features.append(0)

        return np.array(pe_features[:len(features)]).reshape(1, -1)

    except Exception as e:
        print(f"Erreur lors de l'extraction des features : {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect.py <fichier>")
        sys.exit(0)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Erreur : Le fichier {file_path} n'existe pas.")
        sys.exit(0)

    features = extract_pe_features(file_path)
    
    if features is not None:
        prediction = clf.predict(features)
        if prediction[0] == 1:
            sys.exit(1)  # Malware détecté
        else:
            sys.exit(0)  # Fichier légitime
