from os import remove
import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
<<<<<<< HEAD
from functools import partial 
#import customtkinter
=======
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
>>>>>>> main

# import customtkinter

backend = default_backend()
salt = b'2345'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database Code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
<<<<<<< HEAD
""") 

#Create the Popup
def popUp(text):
    answer = simpledialog.askstring("input string", text)
    
    return answer

#Initiate Window
=======
""")


# Create the Popup
def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer


# Initiate Window
>>>>>>> main
window = Tk()

window.title("PassCollector")


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x100")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = Entry(window, width=20)
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            passwordVault()
        else:
            lbl2.config(text="Password Do Not Match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=10)


def loginScreen():
    window.geometry("250x100")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)

    def resetPassword():
        resetPasswordScreen()

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=10)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
<<<<<<< HEAD
=======

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website, username, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM VAULT WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("700x350")
>>>>>>> main

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(website, username, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website,username, password)) 
        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM VAULT WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("700x350")
    
    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
<<<<<<< HEAD
    if(cursor.fetchall() != None):
=======
    if (cursor.fetchall() != None):
>>>>>>> main
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
<<<<<<< HEAD
            #website label
            lbl = Label(window, text=(array[i][1]), font=("Helvetica",12))
            lbl.grid(column=0, row=i+3)
            #username label
            lbl = Label(window, text=(array[i][2]), font=("Helvetica",12))
            lbl.grid(column=1, row=i+3)
            #password label
            lbl = Label(window, text=(array[i][3]), font=("Helvetica",12))
            lbl.grid(column=2, row=i+3)

            btn = Button(window, text="Delete", command= partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i+3, pady=10)

            i = i+1

            cursor.execute("SELECT * FROM vault")
            if(len(cursor.fetchall()) <= i):
                break
=======

            if (len(array) == 0):
                break

            # website label
            lbl = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl.grid(column=0, row=i + 3)
            # username label
            lbl = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl.grid(column=1, row=i + 3)
            # password label
            lbl = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl.grid(column=2, row=i + 3)

            btn = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break

>>>>>>> main

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
