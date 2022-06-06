import sqlite3, hashlib
from tkinter import *
import tkinter.messagebox
import customtkinter
from PIL import Image, ImageTk # Pip install Pillow
import os

customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

PATH = os.path.dirname(os.path.realpath(__file__))

#Database Code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""") 

# Constants
APP_NAME = "PassCollector"
WIDTH = 900
HEIGHT = 600

#Initiate Window
window = customtkinter.CTk()
window.title(APP_NAME)
window.geometry(f"{WIDTH}x{HEIGHT}")
window.minsize(WIDTH, HEIGHT)
window.maxsize(WIDTH * 3, HEIGHT * 3)
window.resizable(True, True)

image = Image.open(PATH + "/Images/bg_gradient.jpg").resize((WIDTH*3, HEIGHT*3))    
bg_image = ImageTk.PhotoImage(image)

# image_label = tkinter.Label(master=window, image=bg_image)
# image_label.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

#window.protocol("WM_DELETE_WINDOW", on_closing)

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

def firstScreen():
    #window.geometry(f"{WIDTH}x{HEIGHT}")
    # Load Image With PIL And Convert To PhotoImage
    
    # image = Image.open(PATH + "/Images/bg_gradient.jpg").resize((WIDTH*3, HEIGHT*3))    
    # bg_image = ImageTk.PhotoImage(image)

    image_label = tkinter.Label(master=window, image=bg_image)
    image_label.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    frame = customtkinter.CTkFrame(master=window,
                                   width=300,
                                   height=HEIGHT,
                                   corner_radius=0)
    frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    lbl = customtkinter.CTkLabel(master=frame, width=200, height=60,
                                              fg_color=("gray70", "gray25"), text="Please Create A Master Password")
    lbl.place(relx=0.5, rely=0.3, anchor=tkinter.CENTER)


    txt = customtkinter.CTkEntry(master=frame, corner_radius=6, width=200, show="*", placeholder_text="Enter Password")
    txt.place(relx=0.5, rely=0.52, anchor=tkinter.CENTER)

    txt1 = customtkinter.CTkEntry(master=frame, corner_radius=6, width=200, show="*", placeholder_text="Re-Enter Password")
    txt1.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            
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
    window.geometry("700x350")

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

def passwordVault():                                       
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")

    lbl = Label(window, text="Password Vault")
    lbl.config(anchor=CENTER)
    lbl.pack()

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()