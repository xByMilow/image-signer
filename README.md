# Image Signature Manager

Image Signer is a modern Python based desktop application for digitally signing images with embedded metadata. It uses a combination of SHA 512 hashing, SQLite storage, JSON based signature formats, and invisible pixel level data embedding for secure image traceability.

> Built with `Tkinter`, `Pillow`, `sqlite3`, and a strong focus on usability and digital integrity.

---

## Features

* **Digital Image Signing** with embedded invisible metadata
* **Receivers & Comments** for image tracking
* **Powerful Search Tools**

  * By ID
  * By SHA-512 hash
  * By hidden metadata in pixels
* **SQLite Integration** for persistent image data
* **Modern Tkinter GUI** with tabbed navigation and live image preview
* **Image & Signature Archiving** with structured folder output
* **Metadata Extraction** & integrity validation

---

## How It Works

### Signature Creation

1. You select an image and input receiver information.
2. The app generates:

   * a unique image ID
   * a digital signature (`.json`) with SHA-512 hash
   * an embedded copy of the image with the ID hidden in its pixels.
3. All data is stored in an SQLite database.

### Hidden Metadata

The hidden metadata is embedded directly into the pixel data using steganography principles (using LSB bit manipulation). This allows the signature to be validated later—even if the image appears visually unchanged.

---

## GUI Overview

| Tab                 | Description                                                             |
| ------------------- | ----------------------------------------------------------------------- |
| **Sign Image**      | Select image, enter receiver + comment, sign, and save with preview     |
| **Manage Images**   | View all signed images, refresh list, open files, and show full details |
| **Search**          | Search by ID or by image hash                                           |
| **Metadata Search** | Load image and check for embedded ID and match in database              |

---

## Requirements

> All dependencies are standard or easily installable via pip.

* Python 3.8+
* `Pillow`
* `tkinter` (preinstalled with most Python distributions)
* `sqlite3` (builtin)
* Other standard modules: `hashlib`, `json`, `secrets`, `base64`, etc.

Install dependencies manually:

```bash
pip install pillow
```

---

## Installation

### Setup

```bash
git clone https://github.com/xbymilow/image-signer.git
cd image-signer
python -m venv .venv
WINDOWS: .venv\Scripts\activate LINUX: source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Make sure you have Python 3.8+ installed.

---

## Example Use Case

1. Select an image (e.g., `sample.png`)
2. Enter:

   * Receiver: `John Doe`
   * Comment: `Confidential Project Image`
3. Click **Sign Image**
4. Output:

   * A new image in `data/images/` with embedded metadata
   * A `.json` signature file in `data/signatures/`
   * Entry in `database.db`

You can now validate this image at any time via the **Metadata Search** tab.

---

## Security

* SHA-512 ensures high-fidelity hash validation.
* Embedded metadata is invisible to casual inspection and standard EXIF tools.
* Optional: Extend with signature verification or encryption for production use.
