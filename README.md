# Image Steganography AES

A Python-based GUI tool using AES encryption and LSB steganography to securely hide/extract secret messages within images for private communication.  
Rebuilt and maintained by **Chandan Agarwal**.

## Features

- **Message Encryption:**  
  Uses **AES-256 (GCM)** to encrypt the secret message before hiding it, ensuring strong security and message integrity.

- **LSB Image Steganography:**  
  Implements Least Significant Bit (LSB) encoding to embed encrypted messages within image pixels, ensuring minimal distortion.

- **Easy-to-Use GUI:**  
  Built using Tkinter, offering a clean and user-friendly interface for embedding and extracting hidden messages.

## Tech Stack

- **Python 3.x:**  
  Core programming language for logic and processing.

- **Tkinter:**  
  GUI toolkit for building the application's interface.

- **Pillow (PIL):**  
  Image processing library used for handling and manipulating image files.

- **cryptography:**  
  Provides AES encryption for secure message protection.

- **NumPy:**  
  Used for pixel-level data manipulation.

## Requirements

To run this project, you will need Python 3.x and the following libraries installed:

- `Pillow`
- `cryptography`
- `numpy`

Install all dependencies using:
pip install -r requirements.txt

## Contact

GitHub: [@Chandan-1206](https://github.com/Chandan-1206)
LinkedIn: https://www.linkedin.com/in/chandan-agarwal-823b47280/

## This project is Open source.
