import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sqlite3
import hashlib
import secrets
import os
from PIL import Image, ImageTk
from PIL.ExifTags import TAGS
import json
import shutil
from datetime import datetime
import struct
import base64

class ImageSignatureManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Signature Manager")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        self.secret_marker = b'\xAB\xBC\xCD\xDE\xEF\xFA\xFB\xFC'
        self.setup_styles()
        self.init_database()
        self.create_directories()
        self.create_widgets()
        
    def setup_styles(self):
        """Modern styles for tkinter widgets"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('TButton', background='#404040', foreground='#ffffff')
        style.configure('TEntry', background='#404040', foreground='#ffffff')
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TNotebook', background='#2b2b2b')
        style.configure('TNotebook.Tab', background='#404040', foreground='#ffffff')
        
    def init_database(self):
        """Initialize SQLite database"""
        self.conn = sqlite3.connect('database.db')
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS images (
                image_id TEXT PRIMARY KEY,
                receiver TEXT NOT NULL,
                comment TEXT,
                image_hash TEXT NOT NULL,
                image_signature TEXT NOT NULL,
                original_filename TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
        
    def create_directories(self):
        """Create required directories"""
        os.makedirs('data/images', exist_ok=True)
        os.makedirs('data/signatures', exist_ok=True)
        
    def generate_id(self):
        """Generate a 16-character unique ID"""
        return secrets.token_hex(8).upper()
        
    def calculate_hash(self, filepath):
        """Calculate SHA512 hash of a file"""
        sha512_hash = hashlib.sha512()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha512_hash.update(chunk)
        return sha512_hash.hexdigest()
        
    def create_signature(self, image_id, receiver, comment, image_hash):
        """Create a digital signature"""
        signature_data = {
            'image_id': image_id,
            'receiver': receiver,
            'comment': comment,
            'image_hash': image_hash,
            'timestamp': datetime.now().isoformat()
        }
        return json.dumps(signature_data, indent=2)

        
def embed_hidden_metadata(self, image_path, image_id, output_path):
    """Embed hidden metadata into an image"""
    try:
        img = Image.open(image_path)
        
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        id_bytes = image_id.encode('utf-8')
        header = self.secret_marker + struct.pack('<I', len(id_bytes)) + id_bytes
        pixels = list(img.getdata())
        
        if len(pixels) * 4 < len(header) * 8:
            raise ValueError("Image too small for metadata")
        
        bit_index = 0
        for byte in header:
            for bit in range(8):
                if bit_index >= len(pixels) * 4:
                    break
                pixel_index = bit_index // 4
                channel_index = bit_index % 4
                pixel_list = list(pixels[pixel_index])
                bit_value = (byte >> bit) & 1
                pixel_list[channel_index] = (pixel_list[channel_index] & 0xFE) | bit_value
                pixels[pixel_index] = tuple(pixel_list)
                bit_index += 1
        
        new_img = Image.new('RGBA', img.size)
        new_img.putdata(pixels)
        new_img.save(output_path, 'PNG')
        return True
        
    except Exception as e:
        print(f"Error embedding metadata: {e}")
        return False
    
def extract_hidden_metadata(self, image_path):
    """Extract hidden metadata from an image"""
    try:
        img = Image.open(image_path)
        
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        pixels = list(img.getdata())
        
        marker_bits = []
        for byte in self.secret_marker:
            for bit in range(8):
                marker_bits.append((byte >> bit) & 1)
        
        extracted_bits = []
        for i in range(len(marker_bits) + 32 + 1024):
            if i >= len(pixels) * 4:
                break
            
            pixel_index = i // 4
            channel_index = i % 4
            
            extracted_bits.append(pixels[pixel_index][channel_index] & 1)
        
        marker_found = True
        for i, expected_bit in enumerate(marker_bits):
            if i >= len(extracted_bits) or extracted_bits[i] != expected_bit:
                marker_found = False
                break
        
        if not marker_found:
            return None
        
        length_bits = extracted_bits[len(marker_bits):len(marker_bits) + 32]
        length_bytes = []
        for i in range(0, 32, 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(length_bits):
                    byte_val |= length_bits[i + j] << j
            length_bytes.append(byte_val)
        
        id_length = struct.unpack('<I', bytes(length_bytes))[0]
        
        if id_length > 128:
            return None
        
        id_start = len(marker_bits) + 32
        id_bits = extracted_bits[id_start:id_start + id_length * 8]
        
        id_bytes = []
        for i in range(0, len(id_bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(id_bits):
                    byte_val |= id_bits[i + j] << j
            id_bytes.append(byte_val)
        
        image_id = bytes(id_bytes[:id_length]).decode('utf-8')
        return image_id
        
    except Exception as e:
        print(f"Error extracting metadata: {e}")
        return None

        
def create_widgets(self):
    """Create GUI widgets"""
    main_frame = ttk.Frame(self.root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    self.sign_frame = ttk.Frame(notebook)
    notebook.add(self.sign_frame, text="Sign Image")
    self.create_sign_tab()
    
    self.manage_frame = ttk.Frame(notebook)
    notebook.add(self.manage_frame, text="Manage Images")
    self.create_manage_tab()
    
    self.search_frame = ttk.Frame(notebook)
    notebook.add(self.search_frame, text="Search")
    self.create_search_tab()
    
    self.metadata_frame = ttk.Frame(notebook)
    notebook.add(self.metadata_frame, text="Metadata Search")
    self.create_metadata_tab()

        
def create_sign_tab(self):
    """Sign Images"""
    title = ttk.Label(self.sign_frame, text="Sign", 
                      font=('Arial', 16, 'bold'))
    title.pack(pady=10)
    
    file_frame = ttk.Frame(self.sign_frame)
    file_frame.pack(fill=tk.X, padx=20, pady=5)
    
    ttk.Label(file_frame, text="Image:").pack(anchor=tk.W)
    self.file_path = tk.StringVar()
    file_entry_frame = ttk.Frame(file_frame)
    file_entry_frame.pack(fill=tk.X, pady=5)
    
    ttk.Entry(file_entry_frame, textvariable=self.file_path, 
              state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(file_entry_frame, text="Browse", 
               command=self.browse_file).pack(side=tk.RIGHT, padx=(5, 0))
    
    receiver_frame = ttk.Frame(self.sign_frame)
    receiver_frame.pack(fill=tk.X, padx=20, pady=5)
    
    ttk.Label(receiver_frame, text="Receiver:").pack(anchor=tk.W)
    self.receiver_var = tk.StringVar()
    ttk.Entry(receiver_frame, textvariable=self.receiver_var).pack(fill=tk.X, pady=5)
    
    comment_frame = ttk.Frame(self.sign_frame)
    comment_frame.pack(fill=tk.X, padx=20, pady=5)
    
    ttk.Label(comment_frame, text="Comment:").pack(anchor=tk.W)
    self.comment_text = scrolledtext.ScrolledText(comment_frame, height=4, 
                                                  bg='#404040', fg='#ffffff')
    self.comment_text.pack(fill=tk.X, pady=5)
    
    preview_frame = ttk.Frame(self.sign_frame)
    preview_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
    
    ttk.Label(preview_frame, text="Preview:").pack(anchor=tk.W)
    self.preview_label = ttk.Label(preview_frame)
    self.preview_label.pack(pady=5)
    
    ttk.Button(self.sign_frame, text="Sign Image", 
               command=self.sign_image).pack(pady=20)
        
def create_manage_tab(self):
    """Tab for managing signed images"""
    title = ttk.Label(self.manage_frame, text="Signed Images", 
                      font=('Arial', 16, 'bold'))
    title.pack(pady=10)
    
    tree_frame = ttk.Frame(self.manage_frame)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    columns = ('ID', 'Receiver', 'Filename', 'Date')
    self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
    
    for col in columns:
        self.tree.heading(col, text=col)
        self.tree.column(col, width=150)
    
    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
    self.tree.configure(yscrollcommand=scrollbar.set)
    
    self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    details_frame = ttk.Frame(self.manage_frame)
    details_frame.pack(fill=tk.X, padx=20, pady=10)
    
    ttk.Label(details_frame, text="Details:").pack(anchor=tk.W)
    self.details_text = scrolledtext.ScrolledText(details_frame, height=6, 
                                                  bg='#404040', fg='#ffffff')
    self.details_text.pack(fill=tk.X, pady=5)
    
    button_frame = ttk.Frame(self.manage_frame)
    button_frame.pack(fill=tk.X, padx=20, pady=10)
    
    ttk.Button(button_frame, text="Refresh", 
               command=self.refresh_list).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Show Details", 
               command=self.show_details).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Open Image", 
               command=self.open_image).pack(side=tk.LEFT, padx=5)
    
    self.tree.bind('<<TreeviewSelect>>', self.on_select)
    
    self.refresh_list()

        
def create_search_tab(self):
    """Tab for search functions"""
    title = ttk.Label(self.search_frame, text="Search Images", 
                      font=('Arial', 16, 'bold'))
    title.pack(pady=10)
    
    search_frame = ttk.Frame(self.search_frame)
    search_frame.pack(fill=tk.X, padx=20, pady=10)
    
    id_frame = ttk.Frame(search_frame)
    id_frame.pack(fill=tk.X, pady=5)
    
    ttk.Label(id_frame, text="Search by ID:").pack(anchor=tk.W)
    id_search_frame = ttk.Frame(id_frame)
    id_search_frame.pack(fill=tk.X, pady=5)
    
    self.search_id_var = tk.StringVar()
    ttk.Entry(id_search_frame, textvariable=self.search_id_var).pack(
        side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(id_search_frame, text="Search", 
               command=self.search_by_id).pack(side=tk.RIGHT, padx=(5, 0))
    
    hash_frame = ttk.Frame(search_frame)
    hash_frame.pack(fill=tk.X, pady=5)
    
    ttk.Label(hash_frame, text="File for hash comparison:").pack(anchor=tk.W)
    hash_search_frame = ttk.Frame(hash_frame)
    hash_search_frame.pack(fill=tk.X, pady=5)
    
    self.search_file_var = tk.StringVar()
    ttk.Entry(hash_search_frame, textvariable=self.search_file_var, 
              state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(hash_search_frame, text="Browse", 
               command=self.browse_search_file).pack(side=tk.RIGHT, padx=(5, 0))
    
    ttk.Button(search_frame, text="Search by Hash", 
               command=self.search_by_hash).pack(pady=10)
    
    results_frame = ttk.Frame(self.search_frame)
    results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    ttk.Label(results_frame, text="Search Results:").pack(anchor=tk.W)
    self.search_results = scrolledtext.ScrolledText(results_frame, 
                                                    bg='#404040', fg='#ffffff')
    self.search_results.pack(fill=tk.BOTH, expand=True, pady=5)

def create_metadata_tab(self):
    """Tab for metadata search"""
    title = ttk.Label(self.metadata_frame, text="Search Hidden Metadata", 
                      font=('Arial', 16, 'bold'))
    title.pack(pady=10)
    
    info_frame = ttk.Frame(self.metadata_frame)
    info_frame.pack(fill=tk.X, padx=20, pady=10)
    
    info_text = """This function searches for hidden metadata in images.
The metadata is embedded in the pixel data and is invisible to regular metadata tools."""
    
    ttk.Label(info_frame, text=info_text, wraplength=600).pack(anchor=tk.W)
    
    file_frame = ttk.Frame(self.metadata_frame)
    file_frame.pack(fill=tk.X, padx=20, pady=10)
    
    ttk.Label(file_frame, text="Image file for metadata analysis:").pack(anchor=tk.W)
    metadata_search_frame = ttk.Frame(file_frame)
    metadata_search_frame.pack(fill=tk.X, pady=5)
    
    self.metadata_file_var = tk.StringVar()
    ttk.Entry(metadata_search_frame, textvariable=self.metadata_file_var, 
              state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(metadata_search_frame, text="Browse", 
               command=self.browse_metadata_file).pack(side=tk.RIGHT, padx=(5, 0))
    
    ttk.Button(file_frame, text="Extract Metadata", 
               command=self.extract_metadata).pack(pady=10)
    
    results_frame = ttk.Frame(self.metadata_frame)
    results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    ttk.Label(results_frame, text="Metadata Results:").pack(anchor=tk.W)
    self.metadata_results = scrolledtext.ScrolledText(results_frame, 
                                                      bg='#404040', fg='#ffffff')
    self.metadata_results.pack(fill=tk.BOTH, expand=True, pady=5)

def browse_file(self):
    """Select image file"""
    file_path = filedialog.askopenfilename(
        title="Select image file",
        filetypes=[
            ("Image files", "*.png *.jpg *.jpeg *.webp *.bmp *.gif *.tiff"),
            ("All files", "*.*")
        ]
    )
    if file_path:
        self.file_path.set(file_path)
        self.show_preview(file_path)
        
def browse_search_file(self):
    """Select file for hash search"""
    file_path = filedialog.askopenfilename(
        title="Select file for hash comparison",
        filetypes=[
            ("Image files", "*.png *.jpg *.jpeg *.webp *.bmp *.gif *.tiff"),
            ("All files", "*.*")
        ]
    )
    if file_path:
        self.search_file_var.set(file_path)
        
def browse_metadata_file(self):
    """Select file for metadata analysis"""
    file_path = filedialog.askopenfilename(
        title="Select image file for metadata analysis",
        filetypes=[
            ("Image files", "*.png *.jpg *.jpeg *.webp *.bmp *.gif *.tiff"),
            ("All files", "*.*")
        ]
    )
    if file_path:
        self.metadata_file_var.set(file_path)

            
def show_preview(self, file_path):
    """Display image preview"""
    try:
        image = Image.open(file_path)
        image.thumbnail((200, 200), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        self.preview_label.configure(image=photo)
        self.preview_label.image = photo
    except Exception as e:
        messagebox.showerror("Error", f"Cannot display preview: {e}")
        
def sign_image(self):
    """Sign and save image"""
    if not self.file_path.get():
        messagebox.showerror("Error", "Please select an image file")
        return
        
    if not self.receiver_var.get().strip():
        messagebox.showerror("Error", "Please enter a receiver")
        return
        
    try:
        image_id = self.generate_id()
        
        original_hash = self.calculate_hash(self.file_path.get())
        
        comment = self.comment_text.get(1.0, tk.END).strip()
        receiver = self.receiver_var.get().strip()
        
        signature = self.create_signature(image_id, receiver, comment, original_hash)
        
        original_filename = os.path.basename(self.file_path.get())
        base_name, ext = os.path.splitext(original_filename)
        
        output_filename = f"{image_id}_{base_name}.png"
        image_dest = os.path.join('data/images', output_filename)
        signature_dest = os.path.join('data/signatures', f"{image_id}.json")
        
        if not self.embed_hidden_metadata(self.file_path.get(), image_id, image_dest):
            raise Exception("Error embedding hidden metadata")
        
        modified_hash = self.calculate_hash(image_dest)
        
        with open(signature_dest, 'w', encoding='utf-8') as f:
            f.write(signature)
            
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO images (image_id, receiver, comment, image_hash, 
                                image_signature, original_filename)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (image_id, receiver, comment, modified_hash, signature_dest, output_filename))
        self.conn.commit()
        
        messagebox.showinfo("Success", 
                            f"Image signed successfully!\nID: {image_id}\nHidden metadata embedded!")
        
        self.file_path.set("")
        self.receiver_var.set("")
        self.comment_text.delete(1.0, tk.END)
        self.preview_label.configure(image="")
        
        self.refresh_list()
        
    except Exception as e:
        messagebox.showerror("Error", f"Error while signing: {e}")

            
def extract_metadata(self):
    """Extract hidden metadata from image"""
    if not self.metadata_file_var.get():
        messagebox.showwarning("Warning", "Please select an image file")
        return
        
    try:
        extracted_id = self.extract_hidden_metadata(self.metadata_file_var.get())
        
        self.metadata_results.delete(1.0, tk.END)
        
        if extracted_id:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM images WHERE image_id = ?', (extracted_id,))
            result = cursor.fetchone()
            
            if result:
                result_text = f"""Hidden metadata found!
Extracted ID: {extracted_id}

Database record:
ID: {result[0]}
Receiver: {result[1]}
Comment: {result[2]}
Hash: {result[3]}
Filename: {result[5]}
Timestamp: {result[6]}

Status: ✅ Image is registered in the database
"""
            else:
                result_text = f"""Hidden metadata found!
Extracted ID: {extracted_id}

Status: ⚠️ ID found, but no database record available
"""
                
            self.metadata_results.insert(tk.END, result_text)
        else:
            self.metadata_results.insert(tk.END, "No hidden metadata found.\nThe image was not signed using this system.")
            
    except Exception as e:
        messagebox.showerror("Error", f"Error while extracting metadata: {e}")

def refresh_list(self):
    """Refresh the list of signed images"""
    for item in self.tree.get_children():
        self.tree.delete(item)
        
    cursor = self.conn.cursor()
    cursor.execute('SELECT image_id, receiver, original_filename, timestamp FROM images ORDER BY timestamp DESC')
    
    for row in cursor.fetchall():
        self.tree.insert('', tk.END, values=row)

            
def on_select(self, event):
    """Item selected in the list"""
    pass

def show_details(self):
    """Display details of the selected image"""
    selection = self.tree.selection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an image")
        return
        
    item = self.tree.item(selection[0])
    image_id = item['values'][0]
    
    cursor = self.conn.cursor()
    cursor.execute('SELECT * FROM images WHERE image_id = ?', (image_id,))
    row = cursor.fetchone()
    
    if row:
        details = f"""ID: {row[0]}
Receiver: {row[1]}
Comment: {row[2]}
Hash: {row[3]}
Filename: {row[5]}
Timestamp: {row[6]}
Hidden Metadata: ✅ Embedded"""
        
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)

def open_image(self):
    """Open selected image"""
    selection = self.tree.selection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an image")
        return
        
    item = self.tree.item(selection[0])
    image_id = item['values'][0]
    filename = item['values'][2]
    
    image_path = os.path.join('data/images', filename)
    
    if os.path.exists(image_path):
        os.startfile(image_path)
    else:
        messagebox.showerror("Error", "Image file not found")

            
def search_by_id(self):
    """Search by ID"""
    search_id = self.search_id_var.get().strip()
    if not search_id:
        messagebox.showwarning("Warning", "Please enter an ID")
        return
        
    cursor = self.conn.cursor()
    cursor.execute('SELECT * FROM images WHERE image_id LIKE ?', (f'%{search_id}%',))
    results = cursor.fetchall()
    
    self.search_results.delete(1.0, tk.END)
    if results:
        for row in results:
            result_text = f"""ID: {row[0]}
Receiver: {row[1]}
Comment: {row[2]}
Filename: {row[5]}
Timestamp: {row[6]}
Hidden Metadata: ✅ Embedded
{'='*50}
"""
            self.search_results.insert(tk.END, result_text)
    else:
        self.search_results.insert(tk.END, "No results found.")

def search_by_hash(self):
    """Search by hash"""
    if not self.search_file_var.get():
        messagebox.showwarning("Warning", "Please select a file")
        return
        
    try:
        file_hash = self.calculate_hash(self.search_file_var.get())
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM images WHERE image_hash = ?', (file_hash,))
        results = cursor.fetchall()
        
        self.search_results.delete(1.0, tk.END)
        if results:
            self.search_results.insert(tk.END, f"Hash: {file_hash}\n\n")
            for row in results:
                result_text = f"""Match found!
ID: {row[0]}
Receiver: {row[1]}
Comment: {row[2]}
Filename: {row[5]}
Timestamp: {row[6]}
Hidden Metadata: ✅ Embedded
{'='*50}
"""
                self.search_results.insert(tk.END, result_text)
        else:
            self.search_results.insert(tk.END, f"Hash: {file_hash}\n\nNo match found.")
            
    except Exception as e:
        messagebox.showerror("Error", f"Error during hash comparison: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageSignatureManager(root)
    root.mainloop()
