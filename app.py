# app.py

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from encrypt import embed_message_aes, extract_message_aes

APP_TITLE = "Image Steganography AES — Chandan"
ROOT = tk.Tk()
ROOT.title(APP_TITLE)
ROOT.geometry("1100x700")
ROOT.minsize(900, 580)


style = ttk.Style(ROOT)
try:
    style.theme_use("clam")
except:
    pass

style.configure("Header.TLabel", font=("Consolas", 18, "bold"))
style.configure("Ascii.TLabel", font=("Courier New", 10, "bold"), foreground="#FF0000")
style.configure("Dev.TLabel", font=("Segoe UI", 10, "italic"), foreground="#ff6f00")
style.configure("TButton", padding=6)

ASCII_ART = '''\
  /$$$$$$   /$$                                                                             /$$    
 /$$__  $$ | $$                                                                            | $$    
| $$  \__//$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$  
|  $$$$$$|_  $$_/   /$$__  $$ /$$__  $$ |____  $$ /$$_____/ /$$__  $$| $$  | $$ /$$__  $$|_  $$_/  
 \____  $$ | $$    | $$$$$$$$| $$  \ $$  /$$$$$$$| $$      | $$  \__/| $$  | $$| $$  \ $$  | $$    
 /$$  \ $$ | $$ /$$| $$_____/| $$  | $$ /$$__  $$| $$      | $$      | $$  | $$| $$  | $$  | $$ /$$
|  $$$$$$/ |  $$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/
 \______/   \___/   \_______/ \____  $$ \_______/ \_______/|__/       \____  $$| $$____/    \___/  
                              /$$  \ $$                               /$$  | $$| $$                
                             |  $$$$$$/                              |  $$$$$$/| $$                
                              \______/                                \______/ |__/             
'''

# Variables
input_image_path = tk.StringVar()
output_image_path = tk.StringVar()
encoded_image_path = tk.StringVar()
password_var = tk.StringVar()
status_var = tk.StringVar(value="Ready")

_preview_photo = None
_preview_image = None

# Helpers
def set_status(msg):
    status_var.set(msg)
    ROOT.update_idletasks()

def choose_file(var, title="Select file", filetypes=(("PNG","*.png"),("All","*.*"))):
    p = filedialog.askopenfilename(title=title, filetypes=filetypes)
    if p:
        var.set(p)
        if var is input_image_path or var is encoded_image_path:
            show_preview(p)

def choose_save_location():
    p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")])
    if p:
        output_image_path.set(p)

def clear_all():
    input_image_path.set("")
    output_image_path.set("")
    encoded_image_path.set("")
    password_var.set("")
    message_text.delete("1.0", "end")
    canvas.delete("all")
    set_status("Cleared")

# Preview
def show_preview(path):
    global _preview_image
    try:
        img = Image.open(path).convert("RGBA")
        _preview_image = img
        redraw_preview()
        set_status(f"Preview loaded: {os.path.basename(path)}")
    except Exception as e:
        messagebox.showerror("Preview error", str(e))

def redraw_preview():
    global _preview_photo, _preview_image
    canvas.delete("all")
    if _preview_image is None:
        return
    cw, ch = canvas.winfo_width(), canvas.winfo_height()
    img = _preview_image.copy()
    img.thumbnail((cw, ch), Image.LANCZOS)
    _preview_photo = ImageTk.PhotoImage(img)
    canvas.create_image(cw//2, ch//2, anchor="center", image=_preview_photo)

def on_canvas_resize(event):
    redraw_preview()

# Actions
def do_embed():
    in_p = input_image_path.get()
    out_p = output_image_path.get()
    pw = password_var.get()
    msg = message_text.get("1.0", "end").strip()

    if not in_p or not out_p or not pw or not msg:
        messagebox.showwarning("Missing fields", "Fill all fields before embedding.")
        return

    try:
        set_status("Encrypting + Embedding...")
        embed_message_aes(in_p, out_p, msg, pw)
        messagebox.showinfo("Success", "Message encrypted & hidden.")
        set_status("Done")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Failed")

def do_extract():
    enc_p = encoded_image_path.get()
    pw = password_var.get()

    if not enc_p or not pw:
        messagebox.showwarning("Missing fields", "Select encoded image and enter password.")
        return

    try:
        set_status("Extracting + Decrypting...")
        msg = extract_message_aes(enc_p, pw)
        message_text.delete("1.0", "end")
        message_text.insert("1.0", msg)
        messagebox.showinfo("Done", "Message extracted successfully.")
        set_status("Done")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Failed")

# Menu
menubar = tk.Menu(ROOT)
filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Open Input Image...", command=lambda: choose_file(input_image_path))
filemenu.add_command(label="Open Encoded Image...", command=lambda: choose_file(encoded_image_path))
filemenu.add_separator()
filemenu.add_command(label="Exit", command=ROOT.quit)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=lambda: messagebox.showinfo("About", f"{APP_TITLE}\nDeveloped by Chandan Agarwal"))
menubar.add_cascade(label="Help", menu=helpmenu)
ROOT.config(menu=menubar)

# HEADER UI
header = ttk.Frame(ROOT, padding=10)
header.pack(fill="x")

ascii_label = ttk.Label(header, text=ASCII_ART, style="Ascii.TLabel", justify="left")
ascii_label.pack(side="left", padx=10)

dev_info = ttk.Frame(header)
dev_info.pack(side="right")
ttk.Label(dev_info, text="Image Steganography AES", style="Header.TLabel").pack(anchor="e")
ttk.Label(dev_info, text="Developed by Chandan Agarwal", style="Dev.TLabel").pack(anchor="e")

# Color stripes
tk.Frame(ROOT, height=5, bg="#2eb8ff").pack(fill="x")
tk.Frame(ROOT, height=4, bg="#df5b8a").pack(fill="x")

# MAIN PANED WINDOW
pw = ttk.PanedWindow(ROOT, orient=tk.HORIZONTAL)
pw.pack(fill="both", expand=True, padx=10, pady=10)

left = ttk.Frame(pw, width=380)
right = ttk.Frame(pw)
pw.add(left, weight=0)
pw.add(right, weight=1)

# LEFT PANEL
ttk.Label(left, text="Controls", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=10)

# Input image
ttk.Label(left, text="Input Image:").pack(anchor="w")
ttk.Entry(left, textvariable=input_image_path, width=42).pack(anchor="w")
ttk.Button(left, text="Browse", command=lambda: choose_file(input_image_path)).pack(anchor="w", pady=4)

# Output image
ttk.Label(left, text="Save As (encoded):").pack(anchor="w", pady=(10,0))
ttk.Entry(left, textvariable=output_image_path, width=42).pack(anchor="w")
ttk.Button(left, text="Choose Location", command=choose_save_location).pack(anchor="w", pady=4)

# Encoded input
ttk.Label(left, text="Encoded Image (for extraction):").pack(anchor="w", pady=(14,0))
ttk.Entry(left, textvariable=encoded_image_path, width=42).pack(anchor="w")
ttk.Button(left, text="Browse", command=lambda: choose_file(encoded_image_path)).pack(anchor="w", pady=4)

# Password
ttk.Label(left, text="Password:").pack(anchor="w", pady=(14,0))
pw_entry = ttk.Entry(left, textvariable=password_var, show="*", width=30)
pw_entry.pack(anchor="w")

# Show password toggle
show_pw = tk.BooleanVar()
def toggle_pw():
    pw_entry.config(show="" if show_pw.get() else "*")
ttk.Checkbutton(left, text="Show", variable=show_pw, command=toggle_pw).pack(anchor="w", pady=4)

# Buttons
ttk.Button(left, text="Encrypt & Hide", command=do_embed).pack(anchor="w", fill="x", pady=(14,6))
ttk.Button(left, text="Extract & Decrypt", command=do_extract).pack(anchor="w", fill="x", pady=4)
ttk.Button(left, text="Clear", command=clear_all).pack(anchor="w", fill="x", pady=4)

# RIGHT PANEL
# Preview area
ttk.Label(right, text="Image Preview", font=("Segoe UI", 12, "bold")).pack(anchor="w")
canvas = tk.Canvas(right, bg="#222", bd=2, relief="sunken")
canvas.pack(fill="both", expand=True, pady=10)
canvas.bind("<Configure>", on_canvas_resize)

# Message box
ttk.Label(right, text="Message (Input / Output)", font=("Segoe UI", 12, "bold")).pack(anchor="w")
message_text = tk.Text(right, height=6, wrap="word")
message_text.pack(fill="x", pady=(4,10))

# STATUS BAR
status_frame = ttk.Frame(ROOT)
status_frame.pack(fill="x", side="bottom")
ttk.Label(status_frame, textvariable=status_var, font=("Segoe UI", 9)).pack(anchor="w", padx=10, pady=6)

ROOT.mainloop()
