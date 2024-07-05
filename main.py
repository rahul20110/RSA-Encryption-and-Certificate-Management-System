import random
from math import gcd

def generate_key_pair(prime_num1, prime_num2):
   modulus = prime_num1 * prime_num2
   lambda_modulus = (prime_num1 - 1) * (prime_num2 - 1)
   public_exponent = random.randrange(2, lambda_modulus)
   greatest_common_divisor = gcd(public_exponent, lambda_modulus)
   while greatest_common_divisor != 1:
       public_exponent = random.randrange(2, lambda_modulus)
       greatest_common_divisor = gcd(public_exponent, lambda_modulus)
   private_exponent = modular_inverse(public_exponent, lambda_modulus)
   return ((modulus, public_exponent), (modulus, private_exponent))

def modular_inverse(base, modulus):
   if gcd(base, modulus) != 1:
       return None
   u1, u2, u3 = 1, 0, base
   v1, v2, v3 = 0, 1, modulus
   while v3 != 0:
       quotient = u3 // v3
       v1, v2, v3, u1, u2, u3 = (u1 - quotient * v1), (u2 - quotient * v2), (u3 - quotient * v3), v1, v2, v3
   return u1 % modulus

def encrypt_text(public_key, plaintext):
   modulus, public_exponent = public_key
   ciphertext = [pow(ord(char), public_exponent, modulus) for char in plaintext]
   return ciphertext

def decrypt_text(private_key, ciphertext):
   modulus, private_exponent = private_key
   plaintext = [chr(pow(char, private_exponent, modulus)) for char in ciphertext]
   return ''.join(plaintext)

import time
import hashlib

def hash_function(input_string):  # Hashing function - SHA256
   input_bytes = input_string.encode()
   hash_object = hashlib.sha256()
   hash_object.update(input_bytes)
   hex_hash = hash_object.hexdigest()
   hex_hash = str(hex_hash)
   return hex_hash

class CertificateAuthority:
   def __init__(self, authority_id, prime_num1, prime_num2):
       self.authority_id = authority_id
       self.prime_num1 = prime_num1
       self.prime_num2 = prime_num2
       self.user_public_keys = {}
       self.issued_certificates = {}
       self.public_key, self.private_key = generate_key_pair(prime_num1, prime_num2)

   def set_user_public_keys(self, user_id, public_key):
       self.user_public_keys[user_id] = public_key

   def get_certificate(self, request):
       decrypted_request = decrypt_text(self.private_key, request)
       user_id = int(decrypted_request)
       if user_id in self.issued_certificates.keys():
           return self.issued_certificates[user_id]
       return None

   def issue_certificate(self, request):
       decrypted_request = decrypt_text(self.private_key, request)
       user_id = int(decrypted_request)
       certificate_info = {"ID": user_id, "CA ID": self.authority_id, "PU": self.user_public_keys[user_id], "T": int(time.time()), "DUR": 6000}
       certificate_hash = encrypt_text(self.private_key, hash_function(str(certificate_info)))
       self.issued_certificates[user_id] = {"Certificate": certificate_info, "Hash": certificate_hash}
       print("Certificate issued")
       return {"Certificate": certificate_info, "Hash": certificate_hash}

class User:
   def __init__(self, user_id, prime_num1, prime_num2, ca_public_key):
       self.user_id = user_id
       self.prime_num1 = prime_num1
       self.prime_num2 = prime_num2
       self.ca_public_key = ca_public_key
       self.certificates = {}
       self.received_messages = []
       self.public_key, self.private_key = generate_key_pair(prime_num1, prime_num2)

   def get_request(self, target_id):
       return encrypt_text(self.ca_public_key, str(target_id))

   def get_my_certificate(self, certificate):
       self.my_certificate = certificate
       self.certificates[self.user_id] = certificate

   def add_certificate(self, user_id, certificate):
       self.certificates[user_id] = certificate

   def check_certificate(self, user_id):
    if user_id in self.certificates.keys():
        return True
    else:
        request = self.get_request(user_id)
        certificate = ca.get_certificate(request)
        if certificate is not None and self.verify_certificate(certificate):
            self.add_certificate(user_id, certificate)
            return True
    return False

   def get_certificate(self, user_id):
       return self.certificates[user_id]

   def verify_certificate(self, certificate):
       try:
           return ((hash_function(str(certificate["Certificate"])) == decrypt_text(self.ca_public_key, certificate["Hash"])) and (certificate["Certificate"]["T"] + certificate["Certificate"]["DUR"] > time.time()))
       except TypeError:
           return False

   def show_certificates(self):
       print(self.certificates)

   def encrypt_message(self, key, message):
       return encrypt_text(key, str(message))

   def receive_message(self, encrypted_message):
       self.received_messages.append(eval(decrypt_text(self.private_key, encrypted_message)))

   def show_messages(self):
    senders = set()
    for message in self.received_messages:
        sender_id = message["ID"]
        senders.add(sender_id)
        print(f"Message from User {sender_id}: {message['Message']}")

    for sender_id in senders:
        self.send_acknowledgment(sender_id, self.certificates[sender_id]["Certificate"]["PU"])

   def check_certificate_validity(self):
       if self.my_certificate["Certificate"]["T"] + self.my_certificate["Certificate"]["DUR"] > time.time():
           return "Valid"
       return "Expired"
   def send_acknowledgment(self, sender_id, sender_public_key):
    if sender_id in self.certificates.keys():
        certificate = self.certificates[sender_id]
        if self.verify_certificate(certificate):
            ack_message = {"ID": self.user_id, "Message": f"Acknowledging messages from User {sender_id}"}
            encrypted_ack = self.encrypt_message(certificate["Certificate"]["PU"], str(ack_message))
            users[sender_id].receive_message(encrypted_ack)
        else:
            print(f"Certificate for User {sender_id} is invalid or expired")
    else:
        print(f"Certificate for User {sender_id} not found")


ca = CertificateAuthority(2106, 67, 79)
users = {}
users[1] = User(1, 61, 53, ca.public_key)
users[2] = User(2, 83, 97, ca.public_key)
ca.set_user_public_keys(1, users[1].public_key)
ca.set_user_public_keys(2, users[2].public_key)

while True:
   option = int(input("1. Create new user\n2. User Login\nEnter: "))
   user_id = int(input("ID: "))
   if option == 1:
       prime_num1 = int(input("p: "))
       prime_num2 = int(input("q: "))
       users[user_id] = User(user_id, prime_num1, prime_num2, ca.public_key)
       ca.set_user_public_keys(user_id, users[user_id].public_key)
   else:
       while True:
           option2 = int(input("1. Request CA for certificate\n2. Check available certificates\n3. Make/Update my certificate\n4. Check my certificate validity\n5. Send message\n6. Check messages\n7. Logout\nEnter: "))
           if option2 == 1:
               target_id = int(input("Enter ID of user: "))
               request = users[user_id].get_request(target_id)
               certificate = ca.get_certificate(request)
               print("Certificate of user " + str(target_id) + " received")
               if users[user_id].verify_certificate(certificate):
                   print("Certificate of user " + str(target_id) + " verified")
                   users[user_id].add_certificate(target_id, certificate)
               else:
                   print("Certificate of user " + str(target_id) + " is incorrect")
           if option2 == 2:
               users[user_id].show_certificates()
           if option2 == 3:
               users[user_id].get_my_certificate(ca.issue_certificate(users[user_id].get_request(user_id)))
           if option2 == 4:
               print(users[user_id].check_certificate_validity())
           if option2 == 5:
               target_id = int(input("Enter ID of user: "))
               if users[user_id].check_certificate(target_id):
                   certificate = users[user_id].get_certificate(target_id)
                   if users[user_id].verify_certificate(certificate):
                       message = input("Enter message: ")
                       message_dict = {"ID": user_id, "Message": message}
                       encrypted_message = users[user_id].encrypt_message(certificate["Certificate"]["PU"], str(message_dict))
                       users[target_id].receive_message(encrypted_message)
                   else:
                       print("Certificate of user " + str(target_id) + " is incorrect or has expired")
               else:
                   print("Certificate of user " + str(target_id) + " does not exist")
           if option2 == 6:
               users[user_id].show_messages()
           if option2 == 7:
               break