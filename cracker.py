import sqlite3
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_passwords():
    db_filename = 'db.sqlite3'
    newline_indent = '\n   '

    db=sqlite3.connect(db_filename)
    db.text_factory = str
    cur = db.cursor()

    result = cur.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    table_names = sorted(list(zip(*result))[0])

    for t in table_names:
        result = cur.execute("PRAGMA table_info('%s')" % t).fetchall()
        column_names = list(zip(*result))[1]
        if t == 'auth_user':
            col_data = cur.execute("SELECT password FROM auth_user").fetchall()
            return col_data
    return result






    







def main():
    

    data = get_passwords()
    passwords = []
    for d in data:
        passwords.append(d[0])
        print(d[0])
    
    for p in passwords:
        temp = p

        algo_index = 0
        iteration_index = 0
        salt_index = 0
        hash_index = 0

        algo = ''
        iteration = ''
        salt = ''
        Hash = ''

        curr_index = 0
        for t in range(curr_index, len(temp)):
            if temp[t] != '$':
                algo = algo + temp[t]
            if temp[t] == '$':
                curr_index = t+1
                #print(algo)
                break
        for t in range(curr_index, len(temp)):
            if temp[t] != '$':
                iteration = iteration + temp[t]
            if temp[t] == '$':
                curr_index = t + 1
                #print(iteration)
                break
        for t in range(curr_index, len(temp)):
            if temp[t] != '$':
                salt = salt + temp[t]
            if temp[t] == '$':
                curr_index = t + 1
                #print(salt)
                break
        for t in range(curr_index, len(temp)):
            if temp[t] != '$':
                Hash = Hash + temp[t]
            if t == len(temp) - 1:
                #print(Hash)
                break
    hashing(algo, iteration, salt, Hash)


def hashing(algo, iteration, salt, hash):
    PASSWORDS = [
        "123456",
        "123456789",
        "qwerty",
        "password",
        "1234567",
        "12345678",
        "12345",
        "iloveyou",
        "111111",
        "123123",
        "abc123",
        "qwerty123",
        "1q2w3e4r",
        "admin",
        "qwertyuiop",
        "654321",
        "555555",
        "lovely",
        "7777777",
        "welcome",
        "888888",
        "princess",
        "dragon",
        "password1",
        "123qwe"]
    for p in PASSWORDS:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt= salt.encode(),
            iterations = 216000,
        )
        key = kdf.derive(p.encode())
        print(key)
    
  




if __name__ == '__main__':
    main()