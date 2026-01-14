import subprocess
import shlex


blocked_commands = [
    "format",
    "del",
    "rm",
    "shutdown",
    "reg delete",
    "powershell -command Remove-Item"
    "os.remove"
    "os.unlink"
    "os.rmdir"
    "shutil.rmtree"
    "pathlib.Path.unlink"
    "Path.rmdir"
    "os.system"
    "subprocess.run"
    "subprocess.call"
    "subprocess.Popen"
    "commands"
    "eval"
    "exec"
    "compile"
    "pickle.load"
    "pickle.loads"
    "marshal.load"
]

def is_blocked(command):
   
    cmd_lower = command.lower()
    for blocked in blocked_commands:
        if blocked in cmd_lower:
            return True
    return False

def safe_run(command):
    
    if is_blocked(command):
        print(f"[VIRUS] Commande bloquée, tu nous auras pas : {command}")
        return

    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except Exception as e:
        print(f"Erreur lors de l'exécution : {e}")

if __name__ == "__main__":
    while True:
        cmd = input("Commande > ")
        if cmd.lower() in ["exit", "quit"]:
            break
        safe_run(cmd)
