
# Image Steganography

A Python-based GUI tool using LSB steganography and Columnar Transposition Cipher to securely hide/extract secret messages within images for private communication.

## Features

-Message Encryption:
Uses a Columnar Transposition Cipher to encrypt the secret message before hiding it, adding a layer of security.

-LSB Image Steganography:
Implements Least Significant Bit (LSB) encoding to embed encrypted messages within image pixels, ensuring minimal distortion.

-Easy-to-Use GUI:
Built using Tkinter, offering a user-friendly graphical interface for both embedding and extracting hidden messages.

## Tech Stack

-Python 3.x: 
 Core programming language for logic and processing

-Tkinter:
 GUI toolkit for creating the application's user interface

-PIL (Pillow):
 Image processing library used for handling and manipulating image files

## Requirements

To run this project, you will need Python 3.x and the following libraries:

- `Pillow` (for image processing)
- `cryptography` (for encryption)
- `numpy` (for data manipulation)

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/tyagi0320/Image-Steganography.git
    cd Image-Steganography
    ```

2. Set up a virtual environment:

    - On Windows:
      ```bash
      python -m venv myenv
      myenv\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      python3 -m venv myenv
      source myenv/bin/activate
      ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python app.py
```
## Future Enhancements

- Add support for more encryption algorithms (e.g., AES, RSA) to enhance message security.
- Extend functionality to handle different image types beyond PNG for broader usability.
- Integrate AI to detect whether an image has hidden data — useful for learning or forensics.
- Package the application using PyInstaller or cx_Freeze to make it installable on Windows/Linux/Mac.
- Create a web interface using Flask or Django for easier access and sharing.

## Contact

Email: tharshit03@gmail.com  
GitHub: [@tyagi0320](https://github.com/tyagi0320)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
