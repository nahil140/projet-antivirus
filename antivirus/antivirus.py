from pathlib import Path
import hashlib
import json
import shutil
from datetime import datetime
import os
import sys

# ============================================================
# CONFIGURATION
# ============================================================

# Dossier où se trouve le programme
BASE_DIR = Path(__file__).resolve().parent

# Dossiers/fichiers du programme
QUARANTINE_DIR = BASE_DIR / "quarantine"
LOG_FILE = BASE_DIR / "antivirus.log"
REPORT_FILE = BASE_DIR / "scan_report.json"

# Extensions considérées comme potentiellement suspectes
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".scr",
    ".vbs",
    ".js",
    ".ps1",
    ".msi",
    ".com",
    ".hta",
    ".jar",
}

# Dossiers Windows qu'on peut ignorer pour éviter
# certains scans inutiles ou problématiques
IGNORED_DIRECTORIES = {
    "$recycle.bin",
    "system volume information",
}

# ============================================================
# JOURNALISATION
# ============================================================

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"

    print(line)

    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ============================================================
# SHA-256
# ============================================================

def sha256_file(path):
    path = Path(path)
    sha256 = hashlib.sha256()

    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError) as e:
        log(f"Impossible de lire {path}: {e}")
        return None


# ============================================================
# SCAN D'UN FICHIER
# ============================================================

def scan_file(path):
    path = Path(path)

    if not path.is_file():
        return None

    try:
        extension = path.suffix.lower()
        file_hash = sha256_file(path)

        if file_hash is None:
            return None

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        suspicious = extension in SUSPICIOUS_EXTENSIONS

        result = {
            "path": str(path.resolve()),
            "name": path.name,
            "extension": extension,
            "size": size,
            "sha256": file_hash,
            "suspicious": suspicious,
            "scan_time": datetime.now().isoformat()
        }

        if suspicious:
            log(
                f"[SUSPECT] {path} "
                f"(extension : {extension})"
            )

        return result

    except (OSError, PermissionError) as e:
        log(f"Erreur avec {path}: {e}")
        return None


# ============================================================
# VÉRIFIER SI UN DOSSIER DOIT ÊTRE IGNORÉ
# ============================================================

def should_ignore_directory(path):
    try:
        name = path.name.lower()

        if name in IGNORED_DIRECTORIES:
            return True

        # Ne jamais scanner notre propre quarantaine
        quarantine = QUARANTINE_DIR.resolve()

        try:
            path.resolve().relative_to(quarantine)
            return True
        except ValueError:
            pass

        return False

    except OSError:
        return False


# ============================================================
# SCAN D'UN DOSSIER
# ============================================================

def scan_directory(directory):
    directory = Path(directory)

    if not directory.exists():
        log(f"Dossier introuvable : {directory}")
        return []

    if not directory.is_dir():
        log(f"Ce chemin n'est pas un dossier : {directory}")
        return []

    results = []

    print()
    print("=" * 70)
    print("SCAN DU DOSSIER")
    print("=" * 70)
    print(f"Dossier : {directory}")
    print()

    scanned = 0
    errors = 0

    try:
        for root, dirs, files in os.walk(
            directory,
            topdown=True,
            onerror=lambda error: log(
                f"Accès refusé : {error}"
            )
        ):

            root_path = Path(root)

            # Supprimer de la recherche les dossiers interdits
            dirs[:] = [
                d for d in dirs
                if not should_ignore_directory(
                    root_path / d
                )
            ]

            for filename in files:

                file_path = root_path / filename

                result = scan_file(file_path)

                if result:
                    results.append(result)
                    scanned += 1

                    print(
                        f"\rFichiers analysés : {scanned}",
                        end="",
                        flush=True
                    )
                else:
                    errors += 1

    except PermissionError as e:
        print()
        log(f"Accès refusé : {e}")

    except OSError as e:
        print()
        log(f"Erreur pendant le scan : {e}")

    print()
    print()

    log(
        f"Scan terminé : {scanned} fichier(s), "
        f"{errors} erreur(s)"
    )

    return results


# ============================================================
# SCANNER FICHIER OU DOSSIER
# ============================================================

def scan_path(path):
    path = str(path).strip().strip('"')

    if not path:
        return []

    path = Path(path).expanduser()

    try:
        path = path.resolve()
    except OSError:
        pass

    print()
    print(f"Chemin utilisé : {path}")

    if not path.exists():

        print()
        print("ERREUR : ce chemin n'existe pas.")
        print()

        return []

    if path.is_file():

        result = scan_file(path)

        if result:
            return [result]

        return []

    if path.is_dir():
        return scan_directory(path)

    print("Ce chemin n'est ni un fichier ni un dossier.")

    return []


# ============================================================
# SÉLECTION WINDOWS
# ============================================================

def select_file_or_folder():
    """
    Ouvre une interface Windows permettant de choisir
    un fichier ou un dossier.
    """

    try:
        import tkinter as tk
        from tkinter import filedialog

    except ImportError:
        print(
            "Tkinter n'est pas disponible sur cette installation Python."
        )
        return None

    root = tk.Tk()
    root.withdraw()

    print()
    print("Sélectionnez un fichier ou un dossier...")
    print()

    # Choix du dossier
    folder = filedialog.askdirectory(
        title="Sélectionner un dossier à scanner"
    )

    if folder:
        root.destroy()
        return folder

    # Si aucun dossier n'est sélectionné,
    # proposer un fichier
    file = filedialog.askopenfilename(
        title="Sélectionner un fichier à scanner"
    )

    root.destroy()

    if file:
        return file

    return None


# ============================================================
# DOSSIERS COURANTS
# ============================================================

def show_common_paths():

    home = Path.home()

    print()
    print("=" * 70)
    print("DOSSIERS DISPONIBLES")
    print("=" * 70)

    print()
    print(f"[1] Dossier utilisateur")
    print(f"    {home}")

    desktop = home / "Desktop"

    if desktop.exists():
        print()
        print("[2] Bureau")
        print(f"    {desktop}")

    downloads = home / "Downloads"

    if downloads.exists():
        print()
        print("[3] Téléchargements")
        print(f"    {downloads}")

    documents = home / "Documents"

    if documents.exists():
        print()
        print("[4] Documents")
        print(f"    {documents}")

    pictures = home / "Pictures"

    if pictures.exists():
        print()
        print("[5] Images")
        print(f"    {pictures}")

    videos = home / "Videos"

    if videos.exists():
        print()
        print("[6] Vidéos")
        print(f"    {videos}")

    if os.name == "nt":

        users_folder = Path("C:/Users")

        if users_folder.exists():

            print()
            print("[7] Utilisateurs Windows")

            try:

                for folder in users_folder.iterdir():

                    if folder.is_dir():
                        print(f"    {folder}")

            except PermissionError:
                print("    Accès refusé.")

    print()
    print("=" * 70)


# ============================================================
# QUARANTAINE
# ============================================================

def quarantine_file(path):

    path = Path(path)

    if not path.is_file():

        log(
            f"Fichier introuvable : {path}"
        )

        return False

    try:
        path = path.resolve()
    except OSError:
        pass

    # Ne jamais mettre un fichier déjà dans la quarantaine
    try:
        path.relative_to(
            QUARANTINE_DIR.resolve()
        )

        log(
            f"Fichier déjà en quarantaine : {path}"
        )

        return False

    except ValueError:
        pass

    try:
        QUARANTINE_DIR.mkdir(
            parents=True,
            exist_ok=True
        )
    except OSError as e:

        log(
            f"Impossible de créer la quarantaine : {e}"
        )

        return False

    destination = QUARANTINE_DIR / path.name

    counter = 1

    while destination.exists():

        destination = (
            QUARANTINE_DIR /
            f"{path.stem}_{counter}{path.suffix}"
        )

        counter += 1

    try:

        shutil.move(
            str(path),
            str(destination)
        )

        log(
            f"[QUARANTAINE] "
            f"{path} -> {destination}"
        )

        return True

    except (OSError, PermissionError) as e:

        log(
            f"Erreur de quarantaine : {e}"
        )

        return False


# ============================================================
# QUARANTAINE DES FICHIERS SUSPECTS
# ============================================================

def quarantine_suspicious_files(results):

    suspicious = [
        result
        for result in results
        if result["suspicious"]
    ]

    if not suspicious:

        print()
        print("Aucun fichier suspect.")

        return

    print()
    print("=" * 70)
    print("FICHIERS POTENTIELLEMENT SUSPECTS")
    print("=" * 70)

    for index, result in enumerate(
        suspicious,
        start=1
    ):

        print()
        print(f"[{index}] {result['path']}")
        print(
            f"    Extension : "
            f"{result['extension']}"
        )
        print(
            f"    Taille    : "
            f"{result['size']} octets"
        )
        print(
            f"    SHA-256   : "
            f"{result['sha256']}"
        )

    print()

    choice = input(
        "Mettre TOUS ces fichiers en quarantaine ? (o/n) > "
    ).strip().lower()

    if choice not in (
        "o",
        "oui",
        "y",
        "yes"
    ):

        print()
        print("Aucun fichier déplacé.")

        return

    success = 0
    failed = 0

    for result in suspicious:

        if quarantine_file(
            result["path"]
        ):
            success += 1
        else:
            failed += 1

    print()
    print(
        f"Quarantaine terminée : "
        f"{success} déplacé(s), "
        f"{failed} échec(s)."
    )


# ============================================================
# RAPPORT JSON
# ============================================================

def save_report(results):

    suspicious_count = sum(
        1
        for result in results
        if result["suspicious"]
    )

    report = {
        "scan_time": datetime.now().isoformat(),
        "scanner": "Antivirus Local Python",
        "base_directory": str(BASE_DIR),
        "files_scanned": len(results),
        "suspicious_files": suspicious_count,
        "results": results
    }

    try:

        with REPORT_FILE.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                report,
                f,
                indent=4,
                ensure_ascii=False
            )

        log(
            f"Rapport sauvegardé : "
            f"{REPORT_FILE.resolve()}"
        )

    except OSError as e:

        log(
            f"Impossible de sauvegarder "
            f"le rapport : {e}"
        )


# ============================================================
# AFFICHAGE DES RÉSULTATS
# ============================================================

def display_results(results):

    print()
    print("=" * 70)
    print("RÉSULTAT DU SCAN")
    print("=" * 70)

    print()
    print(
        f"Fichiers analysés : "
        f"{len(results)}"
    )

    suspicious = [
        result
        for result in results
        if result["suspicious"]
    ]

    print(
        f"Fichiers potentiellement suspects : "
        f"{len(suspicious)}"
    )

    if suspicious:

        print()
        print("Fichiers suspects :")

        for result in suspicious:

            print()
            print(
                f"- {result['path']}"
            )

            print(
                f"  Extension : "
                f"{result['extension']}"
            )

            print(
                f"  Taille : "
                f"{result['size']} octets"
            )

            print(
                f"  SHA-256 : "
                f"{result['sha256']}"
            )

    else:

        print()
        print(
            "Aucun fichier correspondant "
            "aux extensions suspectes."
        )

    print()


# ============================================================
# SHA-256 MANUEL
# ============================================================

def manual_sha256():

    filename = input(
        "\nFichier > "
    ).strip().strip('"')

    path = Path(
        filename
    ).expanduser()

    if not path.is_file():

        print(
            "Fichier introuvable."
        )

        return

    file_hash = sha256_file(path)

    if file_hash:

        print()
        print("SHA-256 :")
        print(file_hash)


# ============================================================
# QUARANTAINE MANUELLE
# ============================================================

def manual_quarantine():

    filename = input(
        "\nFichier à isoler > "
    ).strip().strip('"')

    path = Path(
        filename
    ).expanduser()

    if not path.is_file():

        print(
            "Fichier introuvable."
        )

        return

    confirmation = input(
        f"\nMettre '{path}' "
        "en quarantaine ? (o/n) > "
    ).strip().lower()

    if confirmation in (
        "o",
        "oui",
        "y",
        "yes"
    ):

        quarantine_file(path)

    else:

        print(
            "Opération annulée."
        )


# ============================================================
# MENU
# ============================================================

def main():

    print("=" * 80)
    print(
        "             ANTIVIRUS LOCAL PYTHON"
    )
    print(
        "          Scanner de fichiers Windows"
    )
    print("=" * 80)

    print()
    print(f"Programme : {BASE_DIR}")
    print(f"Quarantaine : {QUARANTINE_DIR}")
    print(f"Rapport : {REPORT_FILE}")
    print()

    while True:

        print()
        print("=" * 60)
        print("MENU")
        print("=" * 60)

        print()
        print("1. Sélectionner un fichier/dossier")
        print("2. Entrer manuellement un chemin")
        print("3. Calculer le SHA-256")
        print("4. Mettre un fichier en quarantaine")
        print("5. Afficher les dossiers disponibles")
        print("6. Quitter")

        choice = input(
            "\nChoix > "
        ).strip()

        # ====================================================
        # SÉLECTION WINDOWS
        # ====================================================

        if choice == "1":

            target = select_file_or_folder()

            if not target:

                print()
                print(
                    "Aucune sélection."
                )

                continue

            results = scan_path(target)

            display_results(results)

            if results:

                save_report(results)

                suspicious = [
                    result
                    for result in results
                    if result["suspicious"]
                ]

                if suspicious:

                    quarantine_suspicious_files(
                        results
                    )

        # ====================================================
        # CHEMIN MANUEL
        # ====================================================

        elif choice == "2":

            target = input(
                "\nFichier ou dossier à scanner > "
            ).strip()

            if not target:

                print(
                    "Aucun chemin fourni."
                )

                continue

            results = scan_path(target)

            display_results(results)

            if results:

                save_report(results)

                suspicious = [
                    result
                    for result in results
                    if result["suspicious"]
                ]

                if suspicious:

                    quarantine_suspicious_files(
                        results
                    )

        # ====================================================
        # SHA-256
        # ====================================================

        elif choice == "3":

            manual_sha256()

        # ====================================================
        # QUARANTAINE
        # ====================================================

        elif choice == "4":

            manual_quarantine()

        # ====================================================
        # CHEMINS DISPONIBLES
        # ====================================================

        elif choice == "5":

            show_common_paths()

        # ====================================================
        # QUITTER
        # ====================================================

        elif choice == "6":

            print()
            print(
                "Fermeture de l'antivirus."
            )

            break

        else:

            print()
            print(
                "Choix invalide."
            )


# ============================================================
# LANCEMENT
# ============================================================

if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        print()
        print()
        print(
            "Programme interrompu."
        )

    except Exception as e:

        print()
        print(
            f"Erreur inattendue : {e}"
        )

