from pathlib import Path
from datetime import datetime
import hashlib
import json
import os
import shutil
import struct
import time


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

QUARANTINE_DIR = BASE_DIR / "quarantine"
LOG_FILE = BASE_DIR / "antivirus.log"
REPORT_FILE = BASE_DIR / "scan_report.json"

# Fichiers de signatures SHA-256.
# Ajoute ici les SHA-256 de fichiers malveillants connus.
KNOWN_MALWARE_HASHES = {
    # "sha256_du_malware": "NomDuMalware",
}

# Motifs simples recherchés dans les fichiers.
# Ils ne constituent PAS à eux seuls une preuve de malware.
SUSPICIOUS_STRINGS = [
    b"powershell -enc",
    b"powershell.exe -enc",
    b"cmd.exe /c",
    b"rundll32.exe",
    b"regsvr32.exe",
    b"mshta.exe",
    b"certutil.exe -decode",
    b"bitsadmin.exe",
    b"wscript.exe",
    b"cscript.exe",
    b"CreateRemoteThread",
    b"VirtualAlloc",
    b"WriteProcessMemory",
    b"WinExec",
    b"ShellExecute",
    b"URLDownloadToFile",
]

# Extensions exécutables utilisées uniquement pour
# orienter l'analyse heuristique.
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".sys",
    ".ocx",
    ".cpl",
}

# Taille maximale lue pour la recherche de chaînes.
# Le fichier complet est toujours utilisé pour SHA-256.
MAX_CONTENT_SCAN = 50 * 1024 * 1024

# Score à partir duquel le fichier est considéré
# comme fortement suspect.
QUARANTINE_SCORE = 80


# ============================================================
# OUTILS
# ============================================================

def separator():
    print("=" * 75)


def log(message):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = f"[{timestamp}] {message}"

    print(line)

    try:
        with LOG_FILE.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(line + "\n")

    except OSError:
        pass


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(path):
    """
    Calcule le SHA-256 complet du fichier.
    """

    sha256 = hashlib.sha256()

    try:

        with path.open("rb") as file:

            while True:

                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError) as error:

        log(
            f"Impossible de calculer SHA-256 "
            f"pour {path}: {error}"
        )

        return None


# ============================================================
# LECTURE PARTIELLE DU CONTENU
# ============================================================

def read_content(path):
    """
    Lit une partie du fichier pour l'analyse heuristique.
    """

    try:

        size = path.stat().st_size

        amount = min(
            size,
            MAX_CONTENT_SCAN
        )

        with path.open("rb") as file:

            return file.read(amount)

    except (OSError, PermissionError) as error:

        log(
            f"Impossible de lire {path}: {error}"
        )

        return b""


# ============================================================
# DÉTECTION PE WINDOWS
# ============================================================

def is_pe_file(path):
    """
    Vérifie si le fichier possède une structure PE Windows.

    Un fichier PE commence généralement par:
    MZ

    Puis l'en-tête PE est référencé depuis le header DOS.
    """

    try:

        with path.open("rb") as file:

            dos_header = file.read(64)

            if len(dos_header) < 64:
                return False

            if dos_header[:2] != b"MZ":
                return False

            pe_offset = struct.unpack_from(
                "<I",
                dos_header,
                60
            )[0]

            if pe_offset > 10 * 1024 * 1024:
                return False

            file.seek(pe_offset)

            signature = file.read(4)

            return signature == b"PE\x00\x00"

    except (OSError, PermissionError, struct.error):

        return False


# ============================================================
# ANALYSE DES CHAÎNES
# ============================================================

def find_suspicious_strings(content):
    """
    Recherche des chaînes potentiellement suspectes.
    """

    findings = []

    lower_content = content.lower()

    for pattern in SUSPICIOUS_STRINGS:

        if pattern.lower() in lower_content:

            try:
                name = pattern.decode(
                    "ascii",
                    errors="replace"
                )

            except Exception:

                name = repr(pattern)

            findings.append(name)

    return findings


# ============================================================
# ENTROPie
# ============================================================

def calculate_entropy(data):
    """
    Calcule une estimation de l'entropie.

    Une entropie élevée peut être observée dans des
    données compressées ou chiffrées, mais n'indique
    PAS automatiquement un malware.
    """

    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)

    entropy = 0.0

    import math

    for count in counts:

        if count == 0:
            continue

        probability = count / length

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


# ============================================================
# ANALYSE HEURISTIQUE
# ============================================================

def heuristic_analysis(path, content):
    """
    Retourne un score et les raisons de ce score.
    """

    score = 0

    reasons = []

    extension = path.suffix.lower()

    # --------------------------------------------------------
    # PE
    # --------------------------------------------------------

    pe = is_pe_file(path)

    if pe:

        score += 5

        reasons.append(
            "Fichier PE Windows détecté"
        )

    # --------------------------------------------------------
    # STRINGS SUSPECTES
    # --------------------------------------------------------

    strings = find_suspicious_strings(
        content
    )

    if strings:

        score += min(
            len(strings) * 15,
            60
        )

        reasons.append(
            "Chaînes potentiellement suspectes : "
            + ", ".join(strings[:5])
        )

    # --------------------------------------------------------
    # ENTROPIE
    # --------------------------------------------------------

    entropy = calculate_entropy(
        content[:1024 * 1024]
    )

    if entropy >= 7.5:

        score += 15

        reasons.append(
            f"Entropie élevée ({entropy:.2f})"
        )

    # --------------------------------------------------------
    # EXTENSION EXÉCUTABLE
    # --------------------------------------------------------

    if extension in EXECUTABLE_EXTENSIONS:

        if pe:

            score += 5

            reasons.append(
                "Fichier exécutable Windows"
            )

    # --------------------------------------------------------
    # FICHIER TRÈS PETIT MAIS EXÉCUTABLE
    # --------------------------------------------------------

    try:

        size = path.stat().st_size

        if pe and size < 10 * 1024:

            score += 10

            reasons.append(
                "Exécutable PE inhabituellement petit"
            )

    except OSError:
        pass

    return score, reasons, entropy


# ============================================================
# SCAN D'UN FICHIER
# ============================================================

def scan_file(path):

    path = Path(path)

    if not path.is_file():
        return None

    try:
        path = path.resolve()
    except OSError:
        pass

    print()
    print(
        f"Analyse : {path}"
    )

    # --------------------------------------------------------
    # TAILLE
    # --------------------------------------------------------

    try:

        size = path.stat().st_size

    except OSError:

        return None

    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    file_hash = calculate_sha256(path)

    if file_hash is None:
        return None

    # --------------------------------------------------------
    # SIGNATURE SHA-256
    # --------------------------------------------------------

    known_malware = (
        file_hash.lower()
        in {
            value.lower()
            for value in KNOWN_MALWARE_HASHES
        }
    )

    malware_name = None

    if known_malware:

        malware_name = (
            KNOWN_MALWARE_HASHES[
                file_hash
            ]
        )

    # --------------------------------------------------------
    # CONTENU
    # --------------------------------------------------------

    content = read_content(path)

    # --------------------------------------------------------
    # HEURISTIQUE
    # --------------------------------------------------------

    score, reasons, entropy = (
        heuristic_analysis(
            path,
            content
        )
    )

    # --------------------------------------------------------
    # SIGNATURE CONNUE
    # --------------------------------------------------------

    if known_malware:

        score = 100

        reasons.insert(
            0,
            f"Signature connue : {malware_name}"
        )

    # --------------------------------------------------------
    # NIVEAU
    # --------------------------------------------------------

    if known_malware:

        status = "MALWARE_CONFIRME"

    elif score >= QUARANTINE_SCORE:

        status = "TRES_SUSPECT"

    elif score >= 40:

        status = "SUSPECT"

    else:

        status = "NORMAL"

    result = {
        "path": str(path),
        "name": path.name,
        "extension": path.suffix.lower(),
        "size": size,
        "sha256": file_hash,
        "pe_file": is_pe_file(path),
        "entropy": round(entropy, 3),
        "score": score,
        "status": status,
        "malware_name": malware_name,
        "reasons": reasons,
        "scan_time": datetime.now().isoformat(),
    }

    # --------------------------------------------------------
    # AFFICHAGE
    # --------------------------------------------------------

    if status == "MALWARE_CONFIRME":

        log(
            f"[MALWARE] {path} "
            f"-> {malware_name}"
        )

    elif status == "TRES_SUSPECT":

        log(
            f"[ALERTE] {path} "
            f"(score {score})"
        )

    elif status == "SUSPECT":

        log(
            f"[SUSPECT] {path} "
            f"(score {score})"
        )

    else:

        print(
            f"  -> Normal "
            f"(score {score})"
        )

    return result


# ============================================================
# DOSSIERS IGNORÉS
# ============================================================

def should_ignore_directory(path):

    try:

        return (
            path.name.lower()
            in {
                "$recycle.bin",
                "system volume information",
                "quarantine",
            }
        )

    except OSError:

        return False


# ============================================================
# SCAN D'UN DOSSIER
# ============================================================

def scan_directory(directory):

    directory = Path(directory)

    results = []

    scanned = 0
    errors = 0

    separator()

    print("SCAN DU DOSSIER")

    separator()

    print()
    print(
        f"Dossier : {directory}"
    )

    print()

    def on_error(error):

        nonlocal errors

        errors += 1

        log(
            f"Erreur d'accès : {error}"
        )

    try:

        for root, directories, files in os.walk(
            directory,
            topdown=True,
            onerror=on_error
        ):

            root_path = Path(root)

            directories[:] = [
                name
                for name in directories
                if not should_ignore_directory(
                    root_path / name
                )
            ]

            for filename in files:

                file_path = (
                    root_path / filename
                )

                result = scan_file(
                    file_path
                )

                if result:

                    results.append(result)

                    scanned += 1

                    print(
                        f"\rFichiers analysés : "
                        f"{scanned}",
                        end="",
                        flush=True
                    )

                else:

                    errors += 1

    except KeyboardInterrupt:

        print()

        log(
            "Scan interrompu."
        )

    print()
    print()

    log(
        f"Scan terminé : "
        f"{scanned} fichier(s), "
        f"{errors} erreur(s)"
    )

    return results


# ============================================================
# SCAN D'UN CHEMIN
# ============================================================

def scan_path(path):

    path = str(path).strip().strip('"')

    if not path:
        return []

    target = Path(path).expanduser()

    try:
        target = target.resolve()
    except OSError:
        pass

    if not target.exists():

        print()
        print(
            "ERREUR : le chemin n'existe pas."
        )

        return []

    if target.is_file():

        result = scan_file(target)

        return [result] if result else []

    if target.is_dir():

        return scan_directory(
            target
        )

    return []


# ============================================================
# RAPPORT
# ============================================================

def save_report(results):

    malware = [
        result
        for result in results
        if result["status"]
        == "MALWARE_CONFIRME"
    ]

    very_suspicious = [
        result
        for result in results
        if result["status"]
        == "TRES_SUSPECT"
    ]

    suspicious = [
        result
        for result in results
        if result["status"]
        == "SUSPECT"
    ]

    report = {
        "scanner": "Python Autonomous Antivirus",
        "scan_time": datetime.now().isoformat(),
        "files_scanned": len(results),
        "confirmed_malware": len(malware),
        "very_suspicious": len(very_suspicious),
        "suspicious": len(suspicious),
        "results": results,
    }

    try:

        with REPORT_FILE.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print()
        print(
            f"Rapport : {REPORT_FILE}"
        )

    except OSError as error:

        log(
            f"Erreur rapport : {error}"
        )


# ============================================================
# AFFICHAGE FINAL
# ============================================================

def display_results(results):

    malware = [
        r for r in results
        if r["status"]
        == "MALWARE_CONFIRME"
    ]

    very_suspicious = [
        r for r in results
        if r["status"]
        == "TRES_SUSPECT"
    ]

    suspicious = [
        r for r in results
        if r["status"]
        == "SUSPECT"
    ]

    separator()

    print("RÉSULTAT")

    separator()

    print()

    print(
        f"Fichiers analysés : "
        f"{len(results)}"
    )

    print(
        f"Malwares confirmés : "
        f"{len(malware)}"
    )

    print(
        f"Très suspects : "
        f"{len(very_suspicious)}"
    )

    print(
        f"Suspects : "
        f"{len(suspicious)}"
    )

    # --------------------------------------------------------
    # MALWARE
    # --------------------------------------------------------

    if malware:

        print()
        print(
            "!!! MALWARES DÉTECTÉS !!!"
        )

        for result in malware:

            print()
            print(
                f"Fichier : {result['path']}"
            )

            print(
                f"Nom : {result['malware_name']}"
            )

            print(
                f"SHA-256 : {result['sha256']}"
            )

    # --------------------------------------------------------
    # TRÈS SUSPECT
    # --------------------------------------------------------

    if very_suspicious:

        print()
        print(
            "FICHIERS TRÈS SUSPECTS"
        )

        for result in very_suspicious:

            print()
            print(
                f"Fichier : {result['path']}"
            )

            print(
                f"Score : {result['score']}"
            )

            for reason in result["reasons"]:

                print(
                    f"  - {reason}"
                )

    # --------------------------------------------------------
    # SUSPECT
    # --------------------------------------------------------

    if suspicious:

        print()
        print(
            "FICHIERS SUSPECTS"
        )

        for result in suspicious:

            print()
            print(
                f"Fichier : {result['path']}"
            )

            print(
                f"Score : {result['score']}"
            )

            for reason in result["reasons"]:

                print(
                    f"  - {reason}"
                )

    if not malware and not very_suspicious:

        print()
        print(
            "Aucun malware connu ou fichier "
            "fortement suspect détecté."
        )


# ============================================================
# QUARANTAINE
# ============================================================

def quarantine_file(path):

    path = Path(path)

    if not path.is_file():

        return False

    try:

        QUARANTINE_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

    except OSError as error:

        log(
            f"Impossible de créer la quarantaine : "
            f"{error}"
        )

        return False

    destination = (
        QUARANTINE_DIR / path.name
    )

    counter = 1

    while destination.exists():

        destination = (
            QUARANTINE_DIR
            / f"{path.stem}_{counter}"
            f"{path.suffix}"
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

    except (OSError, PermissionError) as error:

        log(
            f"Erreur quarantaine : {error}"
        )

        return False


# ============================================================
# BLOQUER / ISOLER LES MENACES
# ============================================================

def quarantine_threats(results):

    threats = [
        result
        for result in results
        if result["status"]
        in {
            "MALWARE_CONFIRME",
            "TRES_SUSPECT",
        }
    ]

    if not threats:

        return

    print()
    separator()

    print("MENACES À ISOLER")

    separator()

    print()

    for number, result in enumerate(
        threats,
        start=1
    ):

        print(
            f"[{number}] {result['path']}"
        )

        print(
            f"    Score : {result['score']}"
        )

        print(
            f"    État : {result['status']}"
        )

    print()

    answer = input(
        "Isoler ces fichiers ? (o/n) : "
    ).strip().lower()

    if answer not in (
        "o",
        "oui",
        "y",
        "yes"
    ):

        print(
            "Aucun fichier isolé."
        )

        return

    success = 0
    failed = 0

    for result in threats:

        if quarantine_file(
            result["path"]
        ):

            success += 1

        else:

            failed += 1

    print()

    print(
        f"Isolation terminée : "
        f"{success} succès, "
        f"{failed} échec(s)."
    )


# ============================================================
# SCAN MANUEL
# ============================================================

def manual_scan():

    print()
    separator()

    print("SCAN")

    separator()

    print()

    print(
        "Entrez le chemin du fichier "
        "ou du dossier."
    )

    print()
    print(
        r"Exemple : C:\Users\VotreNom\Downloads"
    )

    print()

    path = input(
        "Chemin : "
    ).strip()

    if not path:

        print(
            "Aucun chemin."
        )

        return

    results = scan_path(path)

    if not results:

        print(
            "Aucun fichier analysé."
        )

        return

    display_results(results)

    save_report(results)

    quarantine_threats(results)


# ============================================================
# TEST D'UN FICHIER
# ============================================================

def test_single_file():

    print()
    separator()

    print("ANALYSER UN FICHIER")

    separator()

    print()

    path = input(
        "Fichier : "
    ).strip().strip('"')

    if not path:

        return

    result = scan_file(
        Path(path)
    )

    if not result:

        print(
            "Impossible d'analyser le fichier."
        )

        return

    display_results(
        [result]
    )

    save_report(
        [result]
    )

    quarantine_threats(
        [result]
    )


# ============================================================
# SCAN D'UN DOSSIER COURANT
# ============================================================

def show_common_paths():

    home = Path.home()

    separator()

    print("DOSSIERS COURANTS")

    separator()

    print()

    paths = [
        ("Utilisateur", home),
        ("Bureau", home / "Desktop"),
        ("Téléchargements", home / "Downloads"),
        ("Documents", home / "Documents"),
        ("Images", home / "Pictures"),
        ("Vidéos", home / "Videos"),
    ]

    for name, path in paths:

        if path.exists():

            print(
                f"{name} : {path}"
            )


# ============================================================
# MENU
# ============================================================

def main():

    print()

    separator()

    print(
        "ANTIVIRUS PYTHON AUTONOME"
    )

    separator()

    print()

    print(
        "Analyse de contenu + signatures "
        "+ heuristiques"
    )

    print()

    print(
        f"Quarantaine : {QUARANTINE_DIR}"
    )

    while True:

        print()

        separator()

        print("MENU")

        separator()

        print()

        print(
            "1. Scanner un fichier ou un dossier"
        )

        print(
            "2. Analyser un seul fichier"
        )

        print(
            "3. Afficher les dossiers courants"
        )

        print(
            "4. Quitter"
        )

        print()

        choice = input(
            "Choix : "
        ).strip()

        if choice == "1":

            manual_scan()

        elif choice == "2":

            test_single_file()

        elif choice == "3":

            show_common_paths()

        elif choice == "4":

            print()
            print(
                "Fermeture."
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
            "Scan interrompu."
        )

    except Exception as error:

        print()
        separator()

        print("ERREUR")

        separator()

        print()
        print(error)
        print()

        log(
            f"Erreur inattendue : {error}"
        )

        input(
            "Appuyez sur Entrée pour fermer..."
        )
