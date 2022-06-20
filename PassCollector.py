import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
import tkinter.messagebox
from functools import partial
from turtle import bgcolor
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import customtkinter
from PIL import Image, ImageTk

customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

PATH = os.path.dirname(os.path.realpath(__file__))

backend = default_backend()
salt = b'2444'

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
""")

# Constants
APP_NAME = "PassCollector"
WIDTH = 900
HEIGHT = 600

# Create the Popup
def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer


# Initiate Window
window = customtkinter.CTk()
window.title(APP_NAME)
window.update()
window.geometry(f"{WIDTH}x{HEIGHT}")
window.minsize(WIDTH, HEIGHT)
window.maxsize(WIDTH * 3, HEIGHT * 3)
window.resizable(True, True)

image = Image.open(PATH + "/Images/bg_gradient.jpg").resize((WIDTH*3, HEIGHT*3))    
bg_image = ImageTk.PhotoImage(image)

image = Image.open(PATH + "/Images/title.png")
title_image = ImageTk.PhotoImage(image)

def hashPassword(input):
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()

    return hash1


def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()

    image_label = tkinter.Label(master=window, image=bg_image)
    image_label.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    frame = customtkinter.CTkFrame(master=window,
                                   width=300,
                                   height=HEIGHT,
                                   corner_radius=10)
    frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    image_label_title = tkinter.Label(master=frame, image=title_image, bg="#2a2d2e")
    image_label_title.place(relx=0.5, rely=0.20, anchor=tkinter.CENTER)


    lbl = customtkinter.CTkLabel(master=frame, width=200, height=60, 
                                              fg_color=("gray70", "gray25"), text="Please Create A Master Password")
    lbl.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)



    txt = customtkinter.CTkEntry(master=frame, corner_radius=6, width=200, show="*", placeholder_text="Enter Password")
    txt.place(relx=0.5, rely=0.52, anchor=tkinter.CENTER)

    txt1 = customtkinter.CTkEntry(master=frame, corner_radius=6, width=200, show="*", placeholder_text="Re-Enter Password")
    txt1.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

    # txt = Entry(window, width=20, show="*")
    # txt.pack()
    # txt.focus()

    # lbl1 = Label(window, text="Re-enter Password")
    # lbl1.config(anchor=CENTER)
    # lbl1.pack()

    # txt1 = Entry(window, width=20, show="*")
    # txt1.pack()

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
            lbl.config(text="Password Do Not Match")

    btn = customtkinter.CTkButton(master=frame, text="Create Master Password",
                                                corner_radius=6, command=savePassword, width=200)
    btn.place(relx=0.5, rely=0.7, anchor=tkinter.CENTER)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    image_label = tkinter.Label(master=window, image=bg_image)
    image_label.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    frame = customtkinter.CTkFrame(master=window,
                                   width=300,
                                   height=HEIGHT,
                                   corner_radius=10)
    frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    image_label_title = tkinter.Label(master=frame, image=title_image, bg="#2a2d2e")
    image_label_title.place(relx=0.5, rely=0.20, anchor=tkinter.CENTER)

    lbl = customtkinter.CTkLabel(master=frame, width=200, height=60, 
                                              fg_color=("gray70", "gray25"), text="Please Enter The Master Password")
    lbl.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

    txt = customtkinter.CTkEntry(master=frame, corner_radius=6, width=200, show="*", placeholder_text="Enter Password")
    txt.place(relx=0.5, rely=0.52, anchor=tkinter.CENTER)

    # Please Fix this Section
    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)
    # Please Fix this Section

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

    btn = customtkinter.CTkButton(master=frame, text="Login",
                                                corner_radius=6, command=checkPassword, width=200)
    btn.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

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
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("750x550")
    window.resizable(height=None, width=None)
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
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            # website label
            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i + 3))
            # username label
            lbl2 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i + 3))
            # password label
            lbl3 = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i + 3))

            btn = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i + 3), pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
