import getpass
import hashlib
import bcrypt

# Fonction pour enregistrer un email et un mot de passe
def enregistrer():
    while True:
        email = input("Entrez votre email : ")
        if email.endswith('@gmail.com'):
            break
        else:
            print("Email invalide, veuillez réessayer.")

    while True:
        password = getpass.getpass("Entrez votre mot de passe : ")
        if (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_-+=<>?;:[]{}" for c in password)
        ):
            break
        else:
            print("Mot de passe invalide, veuillez réessayer.")

    with open("enregistrement.txt", "a") as file:
        file.write(f"{email}:{password}\n")

# Fonction pour authentifier un utilisateur
def authentifier():
    email = input("Entrez votre email : ")
    password = getpass.getpass("Entrez votre mot de passe : ")

    with open("enregistrement.txt", "r") as file:
        for line in file:
            stored_email, stored_password = line.strip().split(":")
            if email == stored_email and password == stored_password:
                return True

    return False

# Fonction pour hacher un mot de passe avec SHA-256
def hacher_sha256(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("sha256.txt", "w") as file:
        file.write(hashed_password)
    print("Hachage par SHA-256 réussi.")

# Fonction pour hacher un mot de passe avec bcrypt
def hacher_bcrypt(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    with open("bcrypt.txt", "wb") as file:
        file.write(hashed_password)
    print("Hachage par bcrypt réussi.")

# Fonction pour effectuer une attaque par dictionnaire
def attaque_par_dictionnaire():
    email = input("Entrez l'email de la cible : ")
    with open("enregistrement.txt", "r") as file:
        for line in file:
            stored_email, stored_password = line.strip().split(":")
            if email == stored_email:
                print(f"Mot de passe trouvé : {stored_password}")
                return
    print("Email non trouvé dans la base de données.")

# Programme principal
while True:
    print("1. Enregistrement")
    print("2. Authentification")
    choice = input("Choisissez une option (1/2) : ")

    if choice == "1":
        enregistrer()
    elif choice == "2":
        if authentifier():
            print("Authentification réussie.")
            while True:
                print("Menu :")
                print("a. Hacher le mot par sha256")
                print("b. Hacher le mot en générant un salt (bcrypt)")
                print("c. Attaquer par dictionnaire le mot inséré.")
                option = input("Choisissez une option (a/b/c) : ")

                if option == "a":
                    password = getpass.getpass("Entrez le mot de passe à hacher : ")
                    hacher_sha256(password)
                elif option == "b":
                    password = getpass.getpass("Entrez le mot de passe à hacher : ")
                    hacher_bcrypt(password)
                elif option == "c":
                    attaque_par_dictionnaire()
                else:
                    print("Option invalide.")
        else:
            print("Authentification échouée. Veuillez réessayer.")
    else:
        print("Option invalide. Veuillez réessayer.")
