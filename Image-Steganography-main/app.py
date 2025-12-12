from tkinter import *
import tkinter.filedialog
from PIL import ImageTk, Image
from tkinter import messagebox
from io import BytesIO
import os
from encrypt import *


class Stegno:

    art = '''\
  SSSS  TTTTT  EEEEE  GGGGG   AAAAAAA  N   N  OOOOO  GGGGG  RRRRR   AAAAA  PPPPP  H   H  Y   Y
 S        T    E      G       A     A  NN  N  O   O  G      R   R  A     A P   P  H   H   Y Y 
  SSS     T    EEEE   G  GG   AAAAAAA  N N N  O   O  G  GG  RRRRR  AAAAAAA PPPPP  HHHHH    Y  
     S    T    E      G   G   A     A  N  NN  O   O  G   G  R  R   A     A P      H   H    Y  
 SSSS     T    EEEEE  GGGGG   A     A  N   N  OOOOO  GGGGG  R   R  A     A P      H   H    Y  
    '''

    art2 = '''\
    Developed by:
    Harshit Tyagi   22103290 (B10)
    '''

    output_image_size = 0

    def main(self, root):
        root.title('Image Steganography')
        root.geometry('800x800')
        root.resizable(width=True, height=True)
        f = Frame(root)

        title = Label(f, text='IS-LAB: Image Steganography Project')
        title.config(font=('Times New Roman', 33))
        title.grid(pady=90)

        b_encode = Button(f, text="Encode Text", command=lambda: self.frame1_encode(
            f), padx=14, bg="green", fg="white")
        b_encode.config(font=('Times New Roman', 16))
        b_decode = Button(f, text="Decode Text", padx=14,
                          command=lambda: self.frame1_decode(f), bg="red", fg="white")
        b_decode.config(font=('Times New Roman', 16))
        b_decode.grid(pady=15)

        ascii_art = Label(f, text=self.art)
        ascii_art.config(font=('Courier', 12), fg="purple")

        ascii_art2 = Label(f, text=self.art2)
        ascii_art2.config(font=('Times New Roman', 16))

        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

        f.grid()
        title.grid(row=1)
        b_encode.grid(row=2)
        b_decode.grid(row=3)
        ascii_art.grid(row=4, pady=10)
        ascii_art2.grid(row=5, pady=5)

    def home(self, frame):
        frame.destroy()
        self.main(root)

    def frame1_decode(self, f):
        f.destroy()
        d_f2 = Frame(root)
        label_art = Label(d_f2, text='🗝')
        label_art.config(font=('Times New Roman', 90))
        label_art.grid(row=1, pady=50)
        l2 = Label(d_f2, text='Enter a key')
        l2.config(font=('Times New Roman', 18))
        l2.grid(pady=15)
        text_area = Text(d_f2, width=25, height=3)
        text_area.grid()
        l1 = Label(d_f2, text='Select the Image with hidden message:')
        l1.config(font=('Times New Roman', 18))
        l1.grid(pady=15)
        bws_button = Button(d_f2, text='Select',
                            command=lambda: self.frame2_decode(d_f2, text_area),
                            padx=14, bg='green', fg='white')
        bws_button.config(font=('Times New Roman', 18))
        bws_button.grid()
        back_button = Button(d_f2, text='Cancel',
                             command=lambda: self.home(d_f2),
                             padx=14, bg='red', fg='white')
        back_button.config(font=('Times New Roman', 18))
        back_button.grid(pady=15)
        d_f2.grid()

    def frame2_decode(self, d_f2, text_area):
        d_f3 = Frame(root)
        key = text_area.get("1.0", "end-1c")
        myfile = tkinter.filedialog.askopenfilename(filetypes=(
            [('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')]))
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing !")
        else:
            myimg = Image.open(myfile, 'r')
            myimage = myimg.resize((300, 200))
            img = ImageTk.PhotoImage(myimage)
            l4 = Label(d_f3, text='Selected Image :')
            l4.config(font=('Times New Roman', 18))
            l4.grid()
            panel = Label(d_f3, image=img)
            panel.image = img
            panel.grid()
            hidden_data = self.decode(myimg, key)
            l2 = Label(d_f3, text='Hidden data is :')
            l2.config(font=('Times New Roman', 18))
            l2.grid(pady=10)
            text_area = Text(d_f3, width=50, height=10)
            text_area.insert(INSERT, hidden_data)
            text_area.configure(state='disabled')
            text_area.grid()
            back_button = Button(d_f3, text='Cancel',
                                 command=lambda: self.page3(d_f3))
            back_button.config(font=('Times New Roman', 11))
            back_button.grid(pady=15)
            d_f3.grid(row=1)
            d_f2.destroy()

    def decode(self, image, key):
        if not key.strip():
            messagebox.showerror("Error", "Decryption key cannot be empty!")
            return ""

        data = ''
        imgdata = iter(image.getdata())

        while True:
            pixels = [value for value in imgdata.__next__()[:3] +
                      imgdata.__next__()[:3] +
                      imgdata.__next__()[:3]]

            binstr = ''.join('0' if i % 2 == 0 else '1' for i in pixels[:8])
            data += chr(int(binstr, 2))

            if pixels[-1] % 2 != 0:
                return decryptMessage(data, key)



    def frame1_encode(self, f):
        f.destroy()
        f2 = Frame(root)
        label_art = Label(f2, text='ꗃ')
        label_art.config(font=('Times New Roman', 90))
        label_art.grid(row=1, pady=50)
        l1 = Label(f2, text='Select the Image\n to hide your message:')
        l1.config(font=('Times New Roman', 18))
        l1.grid(pady=15)

        bws_button = Button(f2, text='Select',
                            command=lambda: self.frame2_encode(f2),padx='14',bg='green',fg='white')
        bws_button.config(font=('Times New Roman', 18))
        bws_button.grid()
        back_button = Button(
            f2, text='Cancel', command=lambda: Stegno.home(self, f2),padx='14',bg='red',fg='white')
        back_button.config(font=('Times New Roman', 18))
        back_button.grid(pady=15)
        back_button.grid()
        f2.grid()

    def frame2_encode(self, f2):
        ep = Frame(root)
        myfile = tkinter.filedialog.askopenfilename(filetypes=(
            [('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')]))
        if not myfile:
            messagebox.showerror("Error", "Image not selected!")
        else:
            myimg = Image.open(myfile)
            myimage = myimg.resize((300, 200))
            img = ImageTk.PhotoImage(myimage)

            l3 = Label(ep, text='Selected Image')
            l3.config(font=('Times New Roman', 18))
            l3.grid()
            panel = Label(ep, image=img)
            panel.image = img
            self.output_image_size = os.stat(myfile)
            self.o_image_w, self.o_image_h = myimg.size
            panel.grid()
            l2 = Label(ep, text='Enter the message')
            l2.config(font=('Times New Roman', 18))
            l2.grid(pady=15)
            text_area = Text(ep, width=50, height=10)
            text_area.grid()
            l3 = Label(ep, text='Enter the key')
            l3.config(font=('Times New Roman', 18))
            l3.grid(pady=15)
            text_area_key = Text(ep, width=20, height=5)
            text_area_key.grid()
            encode_button = Button(
                ep, text='Cancel', command=lambda: Stegno.home(self, ep))
            encode_button.config(font=('Times New Roman', 11))
            data = text_area.get("1.0", "end-1c")

            back_button = Button(ep, text='Encode', command=lambda: [self.enc_fun(
            text_area, myimg, text_area_key), Stegno.home(self, ep)])
            back_button.config(font=('Times New Roman', 11))
            back_button.grid(pady=15)
            encode_button.grid()
            ep.grid(row=1)
            f2.destroy()

    def info(self):
        try:
            str = 'original image:-\nsize of original image:{}mb\nwidth: {}\nheight: {}\n\n' \
                  'decoded image:-\nsize of decoded image: {}mb\nwidth: {}' \
                '\nheight: {}'.format(self.output_image_size.st_size/1000000,
                                      self.o_image_w, self.o_image_h,
                                      self.d_image_size/1000000,
                                      self.d_image_w, self.d_image_h)
            messagebox.showinfo('info', str)
        except:
            messagebox.showinfo('Info', 'Unable to get the information')

    # genData method converts each character in the input data into its 8-bit binary representation and stores it in a list.
    def genData(self, data):
        newd = []

        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd

    # modPix method modifies the least significant bit of each pixel in the input pix according to the binary representation of the characters in datalist. It yields modified pixel values
    def modPix(self, pix, data):
        datalist = self.genData(data)
        # print(datalist)
        lendata = len(datalist)
        imdata = iter(pix)
        for i in range(lendata):
            # Extracting 3 pixels at a time
            pix = [value for value in imdata.__next__()[:3] +
                   imdata.__next__()[:3] +
                   imdata.__next__()[:3]]
            # print(pix)
            # Pixel value should be made
            # odd for 1 and even for 0
            for j in range(0, 8):
                if (datalist[i][j] == '0') and (pix[j] % 2 != 0):
                    pix[j] -= 1

                elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                    pix[j] -= 1
            # ninth pixel of every set tells
            # whether to stop or read further.
            # even means keep reading; odd means the
            # message is over.
            if (i == lendata - 1):
                if (pix[-1] % 2 == 0):
                    pix[-1] -= 1
            else:
                if (pix[-1] % 2 != 0):
                    pix[-1] -= 1

            pix = tuple(pix)
            # print(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]

    def encode_enc(self, newimg, data):
        w = newimg.size[0]
        # print(w)
        (x, y) = (0, 0)

        for pixel in self.modPix(newimg.getdata(), data):

            # Putting modified pixels in the new image
            newimg.putpixel((x, y), pixel)
            if (x == w - 1):
                x = 0
                y += 1
            else:
                x += 1

    def enc_fun(self, text_area, myimg, text_area_key):
        data = text_area.get("1.0", "end-1c")
        key = text_area_key.get("1.0", "end-1c")
        # print(data)
        if (len(data) == 0):
            messagebox.showinfo("Alert", "Kindly enter text in TextBox")
        else:
            newimg = myimg.copy()
            # change data
            newmsg = encryptMessage(data, key)
            # print(newmsg)
            self.encode_enc(newimg, newmsg)
            my_file = BytesIO()
            temp = os.path.splitext(os.path.basename(myimg.filename))[0]
            newimg.save(tkinter.filedialog.asksaveasfilename(
            initialfile=temp, filetypes=([('png', '*.png')]), defaultextension=".png"))
            self.d_image_size = my_file.tell()
            self.d_image_w, self.d_image_h = newimg.size
            messagebox.showinfo(
                "Success", "Successfully encoded your message!")

    def page3(self, frame):
        frame.destroy()
        self.main(root)


root = Tk()
o = Stegno()
o.main(root)
root.mainloop()
