################################
# Program name: caesarCipher.py
#  github: https://github.com/taylor-marrion/reclass_samples/blob/main/python/caesarCipher.py
#  Author: Taylor Marrion
#  Course: Python Essentials
#  Date: 2/13/2022
#  Assignment: Module 4 - Caesar Cipher Lab
#  Purpose: This program will perform a Caesar shift using a user-entered key to encrypt a message, and decrypt the message back to its original text. This program will also use the plaintext and ciphertext to determine the encryption key.
#  Notes/thoughts:   Encrypting data involves three elements: plaintext, the encryption key, and ciphertext. If any two of these three are known, the third can be determined. Modern encryption algorithms are vastly more complicated than a Caesar cipher but this exercise highlights the importance of maintaining confidentiality of plaintext and encryption keys, lest your encryption keys be reverse engineered. 
########################################

def caesarShift(message, key):
    """ 
    Perform Caesar shift to encrypt/decrypt message using key across all printable ASCII characters (32 --> 126)
    Parameters:
        message (string): text to encrypt/decrypt
        key (int): value to perform shift by
    Returns:
        result (string): string of shifted characters
   """
    result = ""
    for i in range(len(message)):
        newOrd = (ord(message[i]) + key)
        if (newOrd < 32):       # lowest printable ASCII char
            newOrd += 95        # 31 + 95 = 126
        elif (newOrd > 126):    # highest printable ASCII char
            newOrd -= 95        # 127 - 95 = 32
        newChar = chr(newOrd)
        result += newChar
    return result

def findKey(plaintext, ciphertext):
    """
    Find key used in Caesar shift by comparing ordinal value of characters in plaintext and ciphertext
    Parameters:
        plaintext (string): the unencrypted message
        ciphertext (string): the encrypted message
    Returns:
        hacked_key (int): the key used to encrypt the plaintext into ciphertext
    """
    hacked_key = ord(ciphertext[0]) - ord(plaintext[0])
    return hacked_key

# initialize message
original_message = "The quick brown fox jumps over the lazy dog."
print("Your original message is: ")
print(original_message)
#original_message = input(Enter your string to encrypt: ")
encryption_key = int(input("Enter your encryption key: "))

print()

# encrypt the message
encrypted_message = caesarShift(original_message, encryption_key)
print("Your encrypted message is: ")
print(encrypted_message)

# decrypt the message, knowing the ciphertext and the decryption key
decrypted_message = caesarShift(encrypted_message, (encryption_key*-1))
print("Your decrypted message is: ")
print(decrypted_message)

print()
print("Let's see if we can find the encryption key based on the plaintext and ciphertext!")
print()

# determine the encryption key, knowing the plaintext and ciphertext
found_key = findKey(original_message, encrypted_message)
print("I determined your key to be: " + str(found_key) + ". Let's try using that to decrypt the ciphertext.")
hacked_message = caesarShift(encrypted_message, (found_key*-1))
print("Your hacked message is: ")
print(hacked_message)

# test if the found key is correct
if (original_message == hacked_message):
    print("I was right! Your secrets aren't so safe after all.")
else:
    print("Hmm... I need my rubber ducky to help me on this one.")

print("\nGoodbye!")
# end program
