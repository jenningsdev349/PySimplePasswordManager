import secrets
import string
from pathlib import Path
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self) -> None:
        self.key = None
        self.password_file = None
        self.password_dictionary = {}

    def create_key(self, path): #creates key using fernet algorithm, saves to file given as parameter
        self.key = Fernet.generate_key()
        print(self.key)
        with open(path, "wb") as f:  
            f.write(self.key)
    
    def load_key(self, path): #loads key from file given as parameter
        with open(path, "rb") as f:  
            self.key = f.read()

    def create_password_file(self, path): #creates empty password document 
        self.password_file = path
        with open (self.password_file, "w") as file:
            pass 

    def load_password_file(self, path): #loads password document from path given as parameter
        self.password_file = path
        with open(self.password_file, "r") as f:  
            for line in f:
                site, encrypted = line.strip().split(": ")
                self.password_dictionary[site] = Fernet(self.key).decrypt(encrypted.encode()).decode()
                
    def read_passwords(self, path): #iterates through the password document and decrypts the passwords, prints to terminal
        self.password_file = path
        with open(path, "r") as file: 
            for line in file:
                site, encrypted = line.strip().split(": ")
                decrypted_password = Fernet(self.key).decrypt(encrypted.encode()).decode()
                self.password_dictionary[site] = decrypted_password
                print(f"{site}: {decrypted_password}")
    
    def add_password(self, site, password): #adds password to document, with the site and password given as parameters
        if self.key is None:
            print("No key loaded. Please load a key first.")
            return
        
        self.password_dictionary[site] = password
        if self.password_file is not None:
            with open(self.password_file, "a+") as f:  
                encrypted_password = Fernet(self.key).encrypt(password.encode()).decode() 
                f.write(site + ": " + encrypted_password + "\n")
        else:
            print("You need to load the password file before you add this password!")

def main():
    pm = PasswordManager()
    key_file = Path("Filekey.key")
    password_file = Path("password.bin")
    
    if not key_file.exists(): #creates key if none exist, or else loads it
        print("Key file does not exist. Creating new key... WARNING: If a password file exists, this new key generated will not be compatible. You will have to recreate your password file.")
        pm.create_key("Filekey.key")
    else:
        print("Key loaded!")
        pm.load_key("Filekey.key")
        
    if not password_file.exists(): #creates password document if none exist, or else loads it
        print("No password file exists. Creating new file...")
        pm.create_password_file("password.bin")
    else: 
        print("Password file loaded!")
        pm.load_password_file("password.bin")
    
    while True:
        try: #users get to choose between adding passwords or reading them
            choice = int(input("Select an option (1: Add Password, 2: Read Passwords, 3: Exit):"))
        except ValueError: #error if users enter values that are not an integer
            print("Invalid input. Please enter a number between 1 and 3.")
            continue
        
        if choice == 1:
            try: #users get to choose between generating a password or entering one manually
                password_choice = int(input("Select an option (1: Generate Password, 2: Enter Password manually)"))
            except ValueError:
                print("Invalid input. Please enter either 1 or 2.")
                continue

            if password_choice == 1: #generating password
                site = input("Enter site: ")
                characters = string.ascii_letters + string.digits #the group of characters that secrets can choose from
                password_length = int(input("How long would you like this password to be? (At least 12 characters recommended)")) 
                password = ''.join(secrets.choice(characters) for i in range(password_length)) #chooses random characters according to password length given by user
                pm.add_password(site, password) #sends to add password function
            elif password_choice == 2: #manually enter password
                site = input("Enter site: ")
                password = input("Enter password: ")
                pm.add_password(site, password)
            else:
                print("Invalid input. Please enter either 1 or 2.")
        elif choice == 2: #reads passwords from password.bin file
            pm.read_passwords("password.bin")
        elif choice == 3: #exit program
            print("Bye!")
            break
        else:
            print("Invalid choice. Please select a number between 1 and 3.")

if __name__ == "__main__":
    main()
