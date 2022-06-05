import sqlite3, hashlib
import tkinter
import tkinter.messagebox
import customtkinter
from PIL import Image, ImageTk
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
#End Database Code

class App(customtkinter.CTk):

    APP_NAME = "PassCollector"
    WIDTH = 900
    HEIGHT = 600

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title(App.APP_NAME)
        self.geometry(f"{App.WIDTH}x{App.HEIGHT}")
        self.minsize(App.WIDTH, App.HEIGHT)
        self.maxsize(App.WIDTH, App.HEIGHT)
        self.resizable(False, False)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

# Pages
    def first_screen(self):
        # Load Image With PIL And Convert To PhotoImage
        image = Image.open(PATH + "/Images/bg_gradient.jpg").resize((self.WIDTH, self.HEIGHT))
        self.bg_image = ImageTk.PhotoImage(image)

        self.image_label = tkinter.Label(master=self, image=self.bg_image)
        self.image_label.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

        self.frame = customtkinter.CTkFrame(master=self,
                                            width=300,
                                            height=App.HEIGHT,
                                            corner_radius=0)
        self.frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

        self.label_1 = customtkinter.CTkLabel(master=self.frame, width=200, height=60,
                                              fg_color=("gray70", "gray25"), text="Please Create A Master Password")
        self.label_1.place(relx=0.5, rely=0.3, anchor=tkinter.CENTER)

        self.entry_1 = customtkinter.CTkEntry(master=self.frame, corner_radius=6, width=200, placeholder_text="Enter Password")
        self.entry_1.place(relx=0.5, rely=0.52, anchor=tkinter.CENTER)

        self.entry_2 = customtkinter.CTkEntry(master=self.frame, corner_radius=6, width=200, show="*", placeholder_text="Re-Enter Password")
        self.entry_2.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

        self.button_2 = customtkinter.CTkButton(master=self.frame, text="Create Master Password",
                                                corner_radius=6, command=self.savePassword, width=200)
        self.button_2.place(relx=0.5, rely=0.7, anchor=tkinter.CENTER)

    def passwordVault():
        for widget in window.winfo_children():
                widget.destroy()
# Functions
    def button_event(self):
        print("Login pressed - username:", self.entry_1.get(), "password:", self.entry_2.get())

    def on_closing(self, event=0):
        self.destroy()

    def hashPassword(self):
        hash = hashlib.md5(self)
        hash = hash.hexdigest()

        return hash

    def savePassword(self):
        if self.entry_1.get() == self.entry_2.get():
            hashedPassword = self.hashPassword(self.entry_1.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            passwordVault()
        else:

            self.label_1.config(text="Password Do Not Match")

    def getMasterPassword(self):
        checkHashedPassword = hashPassword(self.entry_1.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword(self):
        match = self.getMasterPassword()

        if match:
            passwordVault()
        #else:
            #txt.delete(0, 'end')
            #lbl1.config(text="Wrong Password")

# Start the Program
    def start(self):
        self.first_screen()
        self.mainloop()

if __name__ == "__main__":
    app = App()
    app.start()