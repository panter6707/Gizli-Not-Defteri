from tkinter import *
from tkinter import messagebox
import base64

def encode_MKYLisans(key, clear):
    enc=[]
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i])) + ord(key_c) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode_MKYLisans(key, enc):
    dec =[]
    enc= base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c =key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_scret=master_scret_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_scret) == 0:
        messagebox.showerror(title="Hata!!", message="Bütün Bilgileri Girin")
    else:
        #encryption
        message_encrypted = encode_MKYLisans(master_scret, message)
        try:

            with open(f"{title}.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")


        except FileNotFoundError:
            with open(f"{title}.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            master_scret_input.delete(0, END)
            input_text.delete('1.0', END)


def decrypt_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret = master_scret_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Hata !!", message="Lütfen Bütün Bilgileri Giriniz!!")
    else:
        decrypted_message = decode_MKYLisans(master_secret, message_encrypted )
        input_text.delete("1.0", END)
        input_text.insert("1.0",decrypted_message)





#UI

window = Tk()
window.title("Gizli Not Defteri")
window.config(padx=30,pady=30)
Font_MKY=("Times New Roman", 20, "normal")

photo = PhotoImage(file="top-secret.png")
photo_label = Label(image=photo, width=150,height=150)
photo_label.pack()

title_info_label = Label(text="Başlığınızı Giriniz",font=Font_MKY)
title_info_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

input_info_label = Label(text="Lütfen Notunuzu Giriniz",font=Font_MKY)
input_info_label.pack()

input_text = Text(width=50, height=25)
input_text.pack()


master_scret_label = Label(text="Şifrenizi Giriniz", font=Font_MKY)
master_scret_label.pack()

master_scret_input = Entry(width=30)
master_scret_input.pack()

save_button = Button(text="Kaydet & Şifre Çöz", command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = Button(text="Şifre Çöz", command=decrypt_notes)
decrypt_button.pack()













window.mainloop()