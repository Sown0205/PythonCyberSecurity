# Install pip first to install required libraries
# Install 'cryptography' and 'argparse' libraries
# pip install cryptography argparse
import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Function to generate a random AES-256 key size
def generate_key():
    key = os.urandom(32)  # Randomly generated AES-256 key size
    return key

# Function to encrypt the files by using the AES key
def encrypt_file():
    file_path = input("Enter the file that you want to encrypt: \n")
    
    # Handle unknown files
    if not os.path.exists(file_path):
        print("File not found!")
        return
    
    #Prompt the user if they really want to encrypt the file
    else:
        prompt = input("Do you really want to encrypt this file (yes/no ?): ")
        
        #if no - return
        if prompt == "no" or prompt == "n":
            print("Make sure that you really want to encrypt this file. If the decryption key is lost, decryption will be impossible")
            return
        
        #if yes - continue
        elif prompt == "yes" or prompt == "y": 
            key = generate_key()
            
            # Encrypting
            with open(file_path, "rb") as f:
                data = f.read()

                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                encrypted_file_path = file_path + ".enc"
                with open(encrypted_file_path, "wb") as f:
                    f.write(iv + ciphertext)
                
                os.remove(file_path) # Remove the original file path to delete tracks
                print(f"\nYour file {file_path} has been encrypted and the original content has been deleted")
                print(f"Your encrypted file: {encrypted_file_path}\n")
                print(f"Encryption key (THIS IS IMPORTANT IF YOU WANT TO DECRYPT THE FILE ! SAVE IT): {key.hex()} \n")

                # Save the key into a file if users want to
                # Make a loop to validate user's choices
                while True:
                      save_option = input("Do you want to save the key to a file? (yes/no): ").strip().lower()

                      #If choose 'yes' -> save the key to a file then break the loop
                      if save_option == "yes" or save_option == "y":
                      # Use a loop to make sure the user enter the valid key path
                          while True:
                                key_file = input("Enter the filename to save the key: ").strip()
                                #Check file path valid or not
                                if ".txt" not in key_file:
                                   print("\nInvalid key file path ! The file path should have '.txt' extension")
                                   print("Example: 'key.txt', 'secure.txt', 'lock.txt',...\n")
                                   continue
                                
                                #The key file path should not be the same as the original file path
                                elif key_file == file_path:
                                   print("The file path should not be the same as the original file path. Try a different name")
                                   continue
                                else:
                                   with open(key_file, "w") as f:
                                      f.write(key.hex())
                                   print(f"Key saved to {key_file}")
                                   break
                          break

                      #if choose 'no' -> break the loop (nothing to do more)
                      elif save_option == "no" or save_option == "n":
                          break

                      #Else -> continue the loop to make sure users choose the right command
                      else: 
                          print("\nInvalid command. Choose 'yes' ('y') or 'no' ('n') \n")
                          continue
        # if other inputs are made - display invalid command and return
        else: 
            print("\nInvalid command ! Choose 'yes' ('y') or 'no' ('n')")
            return

# Function to decrypt the file with the provided key
def decrypt_file():
    encrypted_file_path = input("Enter the encrypted file that you want to decrypt: ")

    #Handle unknown file paths
    if not os.path.exists(encrypted_file_path):
        print("File not found!")
        return
    
    # Handle invalid encrypted file
    file_extension = ".enc"
    if not encrypted_file_path.endswith(file_extension):
        print("Error: File is not a valid encrypted file.")
        return
    
    key_hex = input("Enter the decryption key: \n")

    # Key validations
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("Invalid key format!")
        return
    
    with open(encrypted_file_path, "rb") as f:
        data = f.read()
    
    iv = data[:16]
    ciphertext = data[16:]
    
    # Decrypting
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
        
        decrypted_file_path = encrypted_file_path.replace(".enc", "")
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)
        
        os.remove(encrypted_file_path) # Remove the encrypted file path as the file has been decrypted
        print(f"Your file {encrypted_file_path} has been decrypted")
        print(f"Decrypted file: {decrypted_file_path}")

    # Error handling
    except Exception as e:
        print("Decryption failed: Invalid key!")

# Main function - handle arguments
def main():    
    parser = argparse.ArgumentParser(description="AES-256 File Encryption & Decryption")
    parser.add_argument("mode", nargs="?", choices=["encrypt", "decrypt"], help="Mode of operation")
    args = parser.parse_args()
    
    if not args.mode:
        print("Please provide a specified cryptography mode: encrypt or decrypt")
    elif args.mode == "encrypt":
        encrypt_file()
    elif args.mode == "decrypt":
        decrypt_file()
    else:
        print("Invalid argument. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
