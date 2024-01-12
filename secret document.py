from tkinter import *
from tkinter import messagebox
from tkinter.ttk import *
import base64

#write encryption
def save_encrypt_note():
    try:
        title=mytitel_entry.get()
        text=mytext_secret.get("1.0",END)
        master_secret=myentry_masterkey.get()

        if len(title) == 0  or len(text) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="ERROR!!" , message="please enter all the information ")
        else:
            encoded_text =encode(master_secret,text)
            with open(file="secretfile.txt",mode="a") as file:
                file.write(f"Title:{title}\n")
                file.write(f"Secret key:{encoded_text}\n")
            messagebox.showinfo(title="success",message="Note saved and encrypted successfully")
    except Exception as e:
        messagebox.showinfo(title="Error", message=f"An error occurred: {e}")
    finally:
        mytitel_entry.delete(0,END)
        mytext_secret.delete("1.0",END)
        myentry_masterkey.delete(0,END)
def encode(key, msg):
  enc = []
  for i in range(len(msg)):
    list_key = key[i % len(key)]
    list_enc = chr((ord(msg[i]) +
             ord(list_key)) % 256)
    enc.append(list_enc)
  return base64.urlsafe_b64encode("".join(enc).encode()).decode()

#red encryption
def read_decrypt():
    text2=mytext_secret.get("1.0",END)
    master_secret2=myentry_masterkey.get()
    if len(text2) == 0 or len(master_secret2) == 0:
            messagebox.showinfo(title="ERROR!!" , message="please enter all the information ")
    else:
        try:
            uncoded_text =decode(master_secret2,text2)
            mytext_secret.delete("1.0",END)
            mytext_secret.insert("1.0",uncoded_text)
        except:
            messagebox.showinfo(title="ERROR!!", message="Please enter encrypted text")
def decode(key, code):
  dec = []
  enc = base64.urlsafe_b64decode(code).decode()
  for i in range(len(enc)):
   list_key = key[i % len(key)]
   list_dec = chr((256 + ord(enc[i]) - ord(list_key)) % 256)
   dec.append(list_dec)
  return "".join(dec)

#ui
window=Tk()
window.title=("Secret File")
window.minsize(width=400,height=500)
window.config(padx=30,pady=30)
img=PhotoImage(file="SecretPhoto.png")
image_resized = img.subsample(x=3,y=3)
Label(window, image = image_resized,).pack()
mytitel_label=Label(text="Enter your titel",font=("italic",20))
mytitel_label.pack()
mytitel_entry = Entry(width=30)
mytitel_entry.pack()
mylabel_secret = Label(text="Enter your secret",font=("italic",20))
mylabel_secret.pack()
mytext_secret=Text(width=60,height=30)
mytext_secret.pack()
mylabel_masterkey=Label(text="Enter master key")
mylabel_masterkey.pack()
myentry_masterkey = Entry(width=30)
myentry_masterkey.pack()
mybutton_save=Button(width=20,text="Save&Encrypt",command=save_encrypt_note)
mybutton_save.pack()
mybutton_decrypt=Button(width=20,text="Decrypt",command=read_decrypt)
mybutton_decrypt.pack()




mainloop()