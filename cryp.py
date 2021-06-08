# -*- coding: utf-8 -*-
"""
Created on Sun Oct 11 19:36:14 2020

@author: Kritika Srivastava
"""
from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import time
import csv
import sys
from Crypto.Hash import SHA256
import pandas as pd


def keygen(pa):
    hash_obj = SHA256.new(pa.encode("ascii"))
    key = hash_obj.digest()
    return key


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def encrypt_file(file_name, key):
    with open(file_name, "rb") as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", "wb") as fo:
        fo.write(enc)
    os.remove(file_name)


def decrypt(ciphertext, key):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size :])
    return plaintext.rstrip(b"\0")


def decrypt_file(file_name, key):
    with open(file_name, "rb") as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], "wb") as fo:
        fo.write(dec)
    os.remove(file_name)


def getAllFiles():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    dirs = []
    for dirName, subdirList, fileList in os.walk(dir_path):
        for fname in fileList:
            if (
                fname != "cryp.py"
                and fname != "data.csv.enc"
                and fname != "pwf.txt.enc"
                and fname != "crup.py"
                and fname != "data.csv"
                and fname != "pwf.txt"
            ):
                dirs.append(dirName + "\\" + fname)
        return dirs


def encrypt_all_files(key):
    dirs = getAllFiles()
    for file_name in dirs:
        encrypt_file(file_name, key)


def decrypt_all_files(key):
    dirs = getAllFiles()
    for file_name in dirs:
        decrypt_file(file_name, key)


qi = b"[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e"

if os.path.isfile("data.csv.enc"):

    c = 0
    decrypt_file("data.csv.enc", qi)
    dkp = pd.read_csv("data.csv")

    while True and c < 1:
        c = c + 1
        ind = dkp.loc[(dkp["FileName"] == "pwf.txt")].index
        ki = dkp.at[ind[0], "Password"]
        key = keygen(ki)
        decrypt_file("pwf.txt.enc", key)
        password = input("Enter password: ")
        with open("pwf.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            encrypt_file("pwf.txt", key)
            break
    if c <= 5:

        while True:

            os.system("cls")
            print("1. Press '1' to encrypt file.")
            print("2. Press '2' to decrypt file.")
            print("3. Press '3' to Encrypt all files in the directory.")
            print("4. Press '4' to decrypt all files in the directory.")
            print("5. Press '5' to view all encrypted files and their passwords.")
            print("6. Press '6' to change main password.")
            print("7. Press '7' to exit.")
            choice = int(input())
            os.system("cls")
            df = pd.read_csv("data.csv")

            if choice == 1:
                fil = str(input("Enter name of file to encrypt: "))
                if df.loc[(df["FileName"] == fil)].shape[0] > 0:
                    print("File is already encrypted.")
                else:
                    pas = input("Enter Password for file encryption: ")
                    hkey = keygen(pas)
                    encrypt_file(fil, hkey)
                    with open("data.csv", "a") as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow((fil, hkey, pas))
            elif choice == 2:
                key = qi
                chances = 0
                fil = input(
                    "Enter name of file to decrypt (without the enc extension): "
                )
                if df.loc[(df["FileName"] == fil)].shape[0] == 0:
                    print("File not encrypted.")
                else:
                    ctr = 0
                    poo = ""
                    key = qi
                    while ctr < 5:
                        pw = input("Enter the password: ")
                        ctr = ctr + 1
                        cond = (df["FileName"] == fil) & (df["Password"] == pw)
                        if df.loc[cond].shape[0] > 0:
                            key = keygen(pw)
                            break
                    if ctr <= 5:
                        data = pd.read_csv("data.csv")
                        hkey = data.loc[(data["FileName"] == fil)].index
                        data.drop(hkey, inplace=True)
                        data.to_csv("data.csv", index=False)
                        fil = fil + ".enc"
                        decrypt_file(fil, key)
                    else:
                        print("You've exceeded the number of attempts.")
            elif choice == 3:
                #print(df.shape[0])
                #(Showed up as a 2 in the screenshots.)
                if df.shape[0] > 2:
                    if df.loc[(df["FileName"] == "all")].shape[0] > 0:
                        print("All files already encrypted once.")
                    else:
                        print(
                            "Multiple different encrypted files exist. Decrypt all files individually use this."
                        )
                else:
                    pw = input("Enter a password for encrypting all the files: ")
                    hkey = keygen(pw)
                    encrypt_all_files(hkey)
                    with open("data.csv", "a") as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(("all", hkey, pw))
            elif choice == 4:
                if df.loc[(df["FileName"] == "all")].shape[0] > 0:
                    key = qi
                    ctr = 0
                    while ctr < 5:
                        ctr = ctr + 1
                        ps = input("Enter password used for encrypting all the files: ")
                        cond = (df["FileName"] == "all") & (df["Password"] == ps)
                        if df.loc[cond].shape[0] > 0:
                            key = keygen(ps)
                            decrypt_all_files(key)
                            data = pd.read_csv("data.csv")
                            hkey = data.loc[(data["FileName"] == "all")].index
                            data.drop(hkey, inplace=True)
                            data.to_csv("data.csv", index=False)
                            break
                    if ctr <= 5:
                        continue
                    else:
                        print("You've exceeded the number of attempts.")
                else:
                    print("All files not encrypted.")
            elif choice == 5:
                pw = input("Enter password for viewing all the files:")
                ind = df.loc[(df["FileName"] == "viewer")].index
                ps = df.at[ind[0], "Password"]
                if pw == ps:
                    with open("data.csv", newline="") as File:
                        reader = csv.reader(File)
                        for row in reader:
                            print(row)
                else:
                    print("Access denied.")
            elif choice == 6:
                pw = input("Enter current password: ")
                ind = df.loc[df["FileName"] == "pwf.txt"].index
                pas = df.at[ind[0], "Password"]
                if pas == pw:
                    key = keygen(pw)
                    data = pd.read_csv("data.csv")
                    data.drop(ind, inplace=True)
                    data.to_csv("data.csv", index=False)
                    decrypt_file("pwf.txt.enc", key)
                    pa = input("Enter new password:")
                    newk = keygen(pa)
                    with open("data.csv", "a") as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(("pwf.txt", newk, pa))
                    f = open("pwf.txt", "w+")
                    f.write(pa)
                    f.close()
                    encrypt_file("pwf.txt", newk)
            elif choice == 7:
                encrypt_file("data.csv", qi)
                sys.exit()
            else:
                print("Please select a valid option.")
else:
    while True:
        os.system("cls")
        password = input(
            "Setting up stuff. Enter a password that will be used for entering the decryption range: "
        ) #password for pwf.txt, i.e. to run the code in this directory.
        repassword = input("Confirm password: ")
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")
    with open("data.csv", "w") as f:
        viewall = input("Enter password for viewing all the file lock info: ") #password for all the files is stored in this file.
        #i.e. since we've generated diff key/iv for each file. it's a one time password, code can be tweaked for improvements. 
        writer = csv.writer(f)
        key = keygen(password)
        writer.writerow(("pwf.txt", key, password))
        writer.writerow(("viewer", None, viewall))
    df = pd.read_csv("data.csv", header=None)
    df.to_csv("data.csv", header=["FileName", "Key", "Password"], index=False)
    encrypt_file("data.csv", qi) #data.csv will always be encrypted by qi. can also be encrypted by it's own password.
    f = open("pwf.txt", "w+")
    f.write(password)
    f.close()
    encrypt_file("pwf.txt", key)
    print("Please restart the program to complete the setup")
    time.sleep(0)
