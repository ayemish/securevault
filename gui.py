"""
gui.py - SecureVault Graphical User Interface
=============================================
Tkinter-based GUI wrapping all SecureVault modules.
Run with: python gui.py

Layout:
  - Left sidebar: module navigation buttons
  - Right panel: active module UI (swaps on button click)
  - Bottom: status bar showing last operation result
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

# ── Import all SecureVault modules ──────────────────────────
from module1_classical import (
    caesar_encrypt, caesar_decrypt, rot13,
    vigenere_encrypt, vigenere_decrypt,
    otp_encrypt, otp_decrypt,
    substitution_encrypt, substitution_decrypt,
    columnar_encrypt, columnar_decrypt
)
from module2_stream import (
    stream_encrypt, stream_decrypt,
    block_encrypt, block_decrypt,
    LCG, frequency_test
)
from module3_hash import (
    hash_message, compare_all_hashes,
    hmac_sha256, verify_hmac,
    hash_password, verify_password,
    hash_file, birthday_attack
)
from module4_keyx import (
    gcd, extended_gcd, modular_inverse,
    euler_totient, crt, miller_rabin,
    dh_generate_private_key, dh_compute_public_key,
    dh_compute_shared_secret, DH_PRIME_512, DH_GENERATOR
)
from module5_blockchain import get_blockchain, log_event
from bonus_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify


# ─────────────────────────────────────────────
#  THEME
# ─────────────────────────────────────────────

BG          = "#0d1117"   # main background
SIDEBAR_BG  = "#161b22"   # sidebar
PANEL_BG    = "#0d1117"   # right panel
CARD_BG     = "#161b22"   # card / input area
ACCENT      = "#58a6ff"   # blue accent
ACCENT2     = "#3fb950"   # green accent
DANGER      = "#f85149"   # red
TEXT        = "#e6edf3"   # primary text
TEXT_DIM    = "#8b949e"   # secondary text
BORDER      = "#30363d"   # border color
BTN_BG      = "#21262d"   # button background
BTN_HOVER   = "#30363d"   # button hover

FONT_TITLE  = ("Courier New", 13, "bold")
FONT_LABEL  = ("Courier New", 10)
FONT_SMALL  = ("Courier New", 9)
FONT_MONO   = ("Courier New", 10)
FONT_OUT    = ("Courier New", 9)


# ─────────────────────────────────────────────
#  HELPER WIDGETS
# ─────────────────────────────────────────────

def make_label(parent, text, font=None, color=TEXT, **kwargs):
    return tk.Label(parent, text=text, font=font or FONT_LABEL,
                    fg=color, bg=kwargs.pop('bg', PANEL_BG), **kwargs)


def make_entry(parent, width=40, show=None):
    e = tk.Entry(parent, width=width, font=FONT_MONO,
                 bg=CARD_BG, fg=TEXT, insertbackground=ACCENT,
                 relief='flat', bd=4, show=show or '')
    return e


def make_button(parent, text, command, color=ACCENT):
    b = tk.Button(parent, text=text, command=command,
                  font=FONT_LABEL, fg=BG, bg=color,
                  activebackground=TEXT, activeforeground=BG,
                  relief='flat', bd=0, padx=12, pady=6, cursor='hand2')
    return b


def make_output(parent, height=8):
    t = scrolledtext.ScrolledText(
        parent, height=height, font=FONT_OUT,
        bg=CARD_BG, fg=ACCENT2, insertbackground=ACCENT,
        relief='flat', bd=4, wrap=tk.WORD,
        state='normal'
    )
    return t


def output_write(widget, text):
    widget.config(state='normal')
    widget.delete('1.0', tk.END)
    widget.insert(tk.END, text)
    widget.config(state='disabled')


def row_label_entry(parent, label_text, row, col=0, width=35, show=None):
    make_label(parent, label_text, bg=PANEL_BG).grid(
        row=row, column=col, sticky='w', padx=(0, 8), pady=4)
    e = make_entry(parent, width=width, show=show)
    e.grid(row=row, column=col+1, sticky='w', pady=4)
    return e


# ─────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────

class SecureVaultApp:

    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault — Cryptographic Security System")
        self.root.configure(bg=BG)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self._build_layout()
        self._build_sidebar()
        self.show_panel("home")

    # ── Layout ──────────────────────────────────

    def _build_layout(self):
        # Sidebar (fixed width)
        self.sidebar = tk.Frame(self.root, bg=SIDEBAR_BG, width=200)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)

        # Main panel (fills rest)
        self.main_frame = tk.Frame(self.root, bg=PANEL_BG)
        self.main_frame.pack(side='left', fill='both', expand=True)

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Ready.")
        self.status_bar = tk.Label(
            self.root, textvariable=self.status_var,
            font=FONT_SMALL, fg=TEXT_DIM, bg=SIDEBAR_BG,
            anchor='w', padx=10
        )
        self.status_bar.pack(side='bottom', fill='x')

        # Active panel reference
        self.active_panel = None

    def _build_sidebar(self):
        # Logo
        tk.Label(self.sidebar, text="🔐", font=("Courier New", 28),
                 fg=ACCENT, bg=SIDEBAR_BG).pack(pady=(20, 4))
        tk.Label(self.sidebar, text="SecureVault", font=("Courier New", 12, "bold"),
                 fg=TEXT, bg=SIDEBAR_BG).pack()
        tk.Label(self.sidebar, text="v1.0", font=FONT_SMALL,
                 fg=TEXT_DIM, bg=SIDEBAR_BG).pack(pady=(0, 16))

        ttk.Separator(self.sidebar, orient='horizontal').pack(fill='x', padx=12)

        # Navigation items
        nav = [
            ("🏠  Home",              "home"),
            ("1.  Classical Ciphers", "classical"),
            ("2.  Stream & Block",    "stream"),
            ("3.  Hash & Auth",       "hash"),
            ("4.  Key Exchange",      "keyx"),
            ("5.  Blockchain",        "blockchain"),
            ("★   RSA (Bonus)",       "rsa"),
            ("★   Network Sim",       "network"),
            ("★   Merkle Tree",       "merkle"),
        ]

        self.nav_buttons = {}
        for label, key in nav:
            b = tk.Button(
                self.sidebar, text=label,
                font=FONT_SMALL, fg=TEXT_DIM, bg=SIDEBAR_BG,
                activebackground=CARD_BG, activeforeground=ACCENT,
                relief='flat', bd=0, padx=16, pady=8, anchor='w',
                cursor='hand2',
                command=lambda k=key: self.show_panel(k)
            )
            b.pack(fill='x')
            self.nav_buttons[key] = b

    def set_status(self, msg, color=TEXT_DIM):
        self.status_var.set(f"  {msg}")
        self.status_bar.config(fg=color)

    # ── Panel Switcher ───────────────────────────

    def show_panel(self, key):
        if self.active_panel:
            self.active_panel.destroy()

        # Highlight active nav button
        for k, b in self.nav_buttons.items():
            b.config(fg=ACCENT if k == key else TEXT_DIM,
                     bg=CARD_BG if k == key else SIDEBAR_BG)

        panel_builders = {
            "home":       self._panel_home,
            "classical":  self._panel_classical,
            "stream":     self._panel_stream,
            "hash":       self._panel_hash,
            "keyx":       self._panel_keyx,
            "blockchain": self._panel_blockchain,
            "rsa":        self._panel_rsa,
            "network":    self._panel_network,
            "merkle":     self._panel_merkle,
        }

        self.active_panel = tk.Frame(self.main_frame, bg=PANEL_BG)
        self.active_panel.pack(fill='both', expand=True)
        panel_builders.get(key, self._panel_home)(self.active_panel)

    # ── Section Header helper ────────────────────

    def _section(self, parent, title, subtitle=""):
        tk.Label(parent, text=title, font=FONT_TITLE,
                 fg=ACCENT, bg=PANEL_BG).pack(anchor='w', padx=24, pady=(20, 2))
        if subtitle:
            tk.Label(parent, text=subtitle, font=FONT_SMALL,
                     fg=TEXT_DIM, bg=PANEL_BG).pack(anchor='w', padx=24, pady=(0, 12))
        ttk.Separator(parent, orient='horizontal').pack(fill='x', padx=24, pady=(0, 16))

    # ── Card frame ──────────────────────────────

    def _card(self, parent, **kwargs):
        f = tk.Frame(parent, bg=CARD_BG, bd=0, relief='flat', **kwargs)
        f.pack(fill='x', padx=24, pady=6)
        return f

    # ─────────────────────────────────────────────
    #  HOME PANEL
    # ─────────────────────────────────────────────

    def _panel_home(self, parent):
        self._section(parent, "SecureVault", "Integrated Cryptographic Security System")

        info = [
            ("Module 1", "Classical Cipher Engine",      "Caesar, ROT-13, Vigenere, OTP, Substitution, Transposition"),
            ("Module 2", "Stream & Block Cipher",         "LCG keystream, S-box/P-box block cipher, Avalanche"),
            ("Module 3", "Hash & Authentication",         "MD5/SHA-256, HMAC, PBKDF2, File Integrity, Birthday Attack"),
            ("Module 4", "Key Exchange & Number Theory",  "DH, Extended GCD, CRT, Euler Totient, Miller-Rabin"),
            ("Module 5", "Blockchain Audit Logger",       "Proof-of-Work, Tamper Detection, Persistent JSON"),
            ("Bonus ★",  "RSA + Network Sim + Merkle",   "+7 bonus marks"),
        ]

        for tag, title, desc in info:
            c = self._card(parent)
            tk.Label(c, text=tag, font=("Courier New", 9, "bold"),
                     fg=BG, bg=ACCENT, padx=6, pady=2).grid(row=0, column=0, padx=12, pady=10, sticky='nw')
            tk.Label(c, text=title, font=("Courier New", 11, "bold"),
                     fg=TEXT, bg=CARD_BG).grid(row=0, column=1, sticky='w', padx=8, pady=(10, 2))
            tk.Label(c, text=desc, font=FONT_SMALL,
                     fg=TEXT_DIM, bg=CARD_BG).grid(row=1, column=1, sticky='w', padx=8, pady=(0, 10))

        bc = get_blockchain()
        self.set_status(f"Blockchain loaded — {len(bc.chain)} blocks  |  All modules ready.", ACCENT2)

    # ─────────────────────────────────────────────
    #  MODULE 1 — CLASSICAL CIPHERS
    # ─────────────────────────────────────────────

    def _panel_classical(self, parent):
        self._section(parent, "Module 1 — Classical Ciphers")

        nb = ttk.Notebook(parent)
        nb.pack(fill='both', expand=True, padx=24, pady=4)

        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook', background=PANEL_BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=BTN_BG, foreground=TEXT_DIM,
                        font=FONT_SMALL, padding=[10, 4])
        style.map('TNotebook.Tab', background=[('selected', CARD_BG)],
                  foreground=[('selected', ACCENT)])

        # ── Caesar Tab ──────────────────────────
        t1 = tk.Frame(nb, bg=PANEL_BG); nb.add(t1, text="Caesar / ROT-13")
        f1 = tk.Frame(t1, bg=PANEL_BG); f1.pack(padx=20, pady=16, anchor='nw')

        msg1 = row_label_entry(f1, "Message:", 0)
        shift1 = row_label_entry(f1, "Shift:", 1, width=10)

        out1 = make_output(t1, height=6); out1.pack(padx=20, pady=8, fill='x')

        def do_caesar():
            try:
                enc = caesar_encrypt(msg1.get(), int(shift1.get()))
                dec = caesar_decrypt(enc, int(shift1.get()))
                r13 = rot13(msg1.get())
                output_write(out1,
                    f"Caesar Encrypted : {enc}\n"
                    f"Caesar Decrypted : {dec}\n"
                    f"ROT-13           : {r13}\n"
                    f"ROT-13 x2        : {rot13(r13)}"
                )
                self.set_status("Caesar cipher applied.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f1, "Encrypt / Decrypt", do_caesar).grid(
            row=2, column=1, sticky='w', pady=8)

        # ── Vigenere Tab ────────────────────────
        t2 = tk.Frame(nb, bg=PANEL_BG); nb.add(t2, text="Vigenere")
        f2 = tk.Frame(t2, bg=PANEL_BG); f2.pack(padx=20, pady=16, anchor='nw')

        msg2  = row_label_entry(f2, "Message:", 0)
        key2  = row_label_entry(f2, "Key (letters):", 1)
        out2  = make_output(t2, height=6); out2.pack(padx=20, pady=8, fill='x')

        def do_vigenere():
            try:
                enc = vigenere_encrypt(msg2.get(), key2.get())
                dec = vigenere_decrypt(enc, key2.get())
                output_write(out2,
                    f"Encrypted : {enc}\n"
                    f"Decrypted : {dec}"
                )
                self.set_status("Vigenere cipher applied.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f2, "Encrypt / Decrypt", do_vigenere).grid(
            row=2, column=1, sticky='w', pady=8)

        # ── OTP Tab ─────────────────────────────
        t3 = tk.Frame(nb, bg=PANEL_BG); nb.add(t3, text="One-Time Pad")
        f3 = tk.Frame(t3, bg=PANEL_BG); f3.pack(padx=20, pady=16, anchor='nw')

        msg3 = row_label_entry(f3, "Plaintext:", 0)
        out3 = make_output(t3, height=8); out3.pack(padx=20, pady=8, fill='x')

        otp_store = {}

        def do_otp_enc():
            ct_hex, key_hex = otp_encrypt(msg3.get())
            otp_store['ct']  = ct_hex
            otp_store['key'] = key_hex
            output_write(out3,
                f"Ciphertext (hex) : {ct_hex}\n"
                f"Key (hex)        : {key_hex}\n\n"
                f"[!] Key stored — click Decrypt to verify."
            )
            self.set_status("OTP encrypted.", ACCENT2)

        def do_otp_dec():
            if 'ct' not in otp_store:
                self.set_status("Encrypt something first.", DANGER); return
            pt = otp_decrypt(otp_store['ct'], otp_store['key'])
            output_write(out3,
                f"Ciphertext (hex) : {otp_store['ct']}\n"
                f"Key (hex)        : {otp_store['key']}\n"
                f"Decrypted        : {pt}"
            )
            self.set_status("OTP decrypted.", ACCENT2)

        bf = tk.Frame(t3, bg=PANEL_BG); bf.pack(padx=20, anchor='w')
        make_button(bf, "Encrypt", do_otp_enc).pack(side='left', padx=(0, 8))
        make_button(bf, "Decrypt", do_otp_dec, color=ACCENT2).pack(side='left')

        # ── Substitution Tab ────────────────────
        t4 = tk.Frame(nb, bg=PANEL_BG); nb.add(t4, text="Substitution")
        f4 = tk.Frame(t4, bg=PANEL_BG); f4.pack(padx=20, pady=16, anchor='nw')

        msg4 = row_label_entry(f4, "Message:", 0)
        key4 = row_label_entry(f4, "Key (26 chars):", 1, width=28)
        key4.insert(0, "QWERTYUIOPASDFGHJKLZXCVBNM")
        out4 = make_output(t4, height=6); out4.pack(padx=20, pady=8, fill='x')

        def do_sub():
            try:
                enc = substitution_encrypt(msg4.get(), key4.get())
                dec = substitution_decrypt(enc, key4.get())
                output_write(out4, f"Encrypted : {enc}\nDecrypted : {dec}")
                self.set_status("Substitution cipher applied.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f4, "Encrypt / Decrypt", do_sub).grid(
            row=2, column=1, sticky='w', pady=8)

        # ── Columnar Tab ────────────────────────
        t5 = tk.Frame(nb, bg=PANEL_BG); nb.add(t5, text="Columnar")
        f5 = tk.Frame(t5, bg=PANEL_BG); f5.pack(padx=20, pady=16, anchor='nw')

        msg5 = row_label_entry(f5, "Message:", 0)
        key5 = row_label_entry(f5, "Key:", 1, width=20)
        out5 = make_output(t5, height=6); out5.pack(padx=20, pady=8, fill='x')

        def do_col():
            try:
                enc = columnar_encrypt(msg5.get(), key5.get())
                dec = columnar_decrypt(enc, key5.get())
                output_write(out5, f"Encrypted : {enc}\nDecrypted : {dec}")
                self.set_status("Columnar transposition applied.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f5, "Encrypt / Decrypt", do_col).grid(
            row=2, column=1, sticky='w', pady=8)

    # ─────────────────────────────────────────────
    #  MODULE 2 — STREAM & BLOCK
    # ─────────────────────────────────────────────

    def _panel_stream(self, parent):
        self._section(parent, "Module 2 — Stream & Block Cipher")

        nb = ttk.Notebook(parent)
        nb.pack(fill='both', expand=True, padx=24, pady=4)

        # ── Stream Tab ──────────────────────────
        t1 = tk.Frame(nb, bg=PANEL_BG); nb.add(t1, text="Stream Cipher")
        f1 = tk.Frame(t1, bg=PANEL_BG); f1.pack(padx=20, pady=16, anchor='nw')

        msg1  = row_label_entry(f1, "Message:", 0)
        seed1 = row_label_entry(f1, "Seed (key):", 1, width=20)
        out1  = make_output(t1, height=6); out1.pack(padx=20, pady=8, fill='x')
        stream_store = {}

        def do_stream_enc():
            try:
                ct = stream_encrypt(msg1.get(), int(seed1.get()))
                stream_store['ct'] = ct
                stream_store['seed'] = seed1.get()
                output_write(out1, f"Ciphertext (hex): {ct}")
                self.set_status("Stream cipher encrypted.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        def do_stream_dec():
            if 'ct' not in stream_store:
                self.set_status("Encrypt first.", DANGER); return
            try:
                pt = stream_decrypt(stream_store['ct'], int(stream_store['seed']))
                output_write(out1,
                    f"Ciphertext : {stream_store['ct']}\n"
                    f"Decrypted  : {pt}"
                )
                self.set_status("Stream cipher decrypted.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        bf = tk.Frame(t1, bg=PANEL_BG); bf.pack(padx=20, anchor='w')
        make_button(bf, "Encrypt", do_stream_enc).pack(side='left', padx=(0, 8))
        make_button(bf, "Decrypt", do_stream_dec, color=ACCENT2).pack(side='left')

        # ── Block Tab ───────────────────────────
        t2 = tk.Frame(nb, bg=PANEL_BG); nb.add(t2, text="Block Cipher")
        f2 = tk.Frame(t2, bg=PANEL_BG); f2.pack(padx=20, pady=16, anchor='nw')

        msg2  = row_label_entry(f2, "Message:", 0)
        seed2 = row_label_entry(f2, "Seed (key):", 1, width=20)
        out2  = make_output(t2, height=6); out2.pack(padx=20, pady=8, fill='x')
        block_store = {}

        def do_block_enc():
            try:
                ct = block_encrypt(msg2.get(), int(seed2.get()))
                block_store['ct'] = ct
                block_store['seed'] = seed2.get()
                output_write(out2, f"Ciphertext (hex): {ct}")
                self.set_status("Block cipher encrypted.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        def do_block_dec():
            if 'ct' not in block_store:
                self.set_status("Encrypt first.", DANGER); return
            try:
                pt = block_decrypt(block_store['ct'], int(block_store['seed']))
                output_write(out2,
                    f"Ciphertext : {block_store['ct']}\n"
                    f"Decrypted  : {pt}"
                )
                self.set_status("Block cipher decrypted.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        bf2 = tk.Frame(t2, bg=PANEL_BG); bf2.pack(padx=20, anchor='w')
        make_button(bf2, "Encrypt", do_block_enc).pack(side='left', padx=(0, 8))
        make_button(bf2, "Decrypt", do_block_dec, color=ACCENT2).pack(side='left')

        # ── Frequency Test Tab ──────────────────
        t3 = tk.Frame(nb, bg=PANEL_BG); nb.add(t3, text="Frequency Test")
        f3 = tk.Frame(t3, bg=PANEL_BG); f3.pack(padx=20, pady=16, anchor='nw')

        seed3 = row_label_entry(f3, "Seed:", 0, width=20)
        out3  = make_output(t3, height=8); out3.pack(padx=20, pady=8, fill='x')

        def do_freq():
            try:
                lcg = LCG(seed=int(seed3.get()))
                data = lcg.generate_bytes(1000)
                total = 8000
                ones  = sum(bin(b).count('1') for b in data)
                zeros = total - ones
                ratio = ones / total
                result = (
                    f"LCG Frequency Test (1000 bytes)\n"
                    f"{'─'*35}\n"
                    f"Total bits : {total}\n"
                    f"Ones       : {ones}  ({ones/total*100:.1f}%)\n"
                    f"Zeros      : {zeros}  ({zeros/total*100:.1f}%)\n"
                    f"Ratio      : {ratio:.4f}  (ideal = 0.5000)\n\n"
                    f"Result     : {'PASS ✓' if 0.45 <= ratio <= 0.55 else 'FAIL ✗'}"
                )
                output_write(out3, result)
                self.set_status("Frequency test complete.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f3, "Run Test", do_freq).grid(row=1, column=1, sticky='w', pady=8)

    # ─────────────────────────────────────────────
    #  MODULE 3 — HASH & AUTH
    # ─────────────────────────────────────────────

    def _panel_hash(self, parent):
        self._section(parent, "Module 3 — Hash & Authentication")

        nb = ttk.Notebook(parent)
        nb.pack(fill='both', expand=True, padx=24, pady=4)

        # ── Hash Tab ────────────────────────────
        t1 = tk.Frame(nb, bg=PANEL_BG); nb.add(t1, text="Hash Functions")
        f1 = tk.Frame(t1, bg=PANEL_BG); f1.pack(padx=20, pady=16, anchor='nw')

        msg1 = row_label_entry(f1, "Message:", 0)
        algo_var = tk.StringVar(value='sha256')
        algos = ['md5', 'sha1', 'sha256', 'sha512']
        tk.Label(f1, text="Algorithm:", font=FONT_LABEL, fg=TEXT, bg=PANEL_BG).grid(
            row=1, column=0, sticky='w', pady=4)
        algo_menu = ttk.Combobox(f1, values=algos, textvariable=algo_var,
                                 width=12, font=FONT_MONO, state='readonly')
        algo_menu.grid(row=1, column=1, sticky='w', pady=4)
        out1 = make_output(t1, height=8); out1.pack(padx=20, pady=8, fill='x')

        def do_hash():
            try:
                msg = msg1.get()
                lines = []
                for a in algos:
                    d = hash_message(msg, a)
                    lines.append(f"{a.upper():<8}: {d}")
                output_write(out1, '\n'.join(lines))
                self.set_status("All hashes computed.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f1, "Hash All Algorithms", do_hash).grid(
            row=2, column=1, sticky='w', pady=8)

        # ── HMAC Tab ────────────────────────────
        t2 = tk.Frame(nb, bg=PANEL_BG); nb.add(t2, text="HMAC")
        f2 = tk.Frame(t2, bg=PANEL_BG); f2.pack(padx=20, pady=16, anchor='nw')

        key2 = row_label_entry(f2, "Secret Key:", 0)
        msg2 = row_label_entry(f2, "Message:", 1)
        out2 = make_output(t2, height=6); out2.pack(padx=20, pady=8, fill='x')
        hmac_store = {}

        def do_hmac():
            try:
                mac = hmac_sha256(key2.get(), msg2.get())
                hmac_store['mac'] = mac
                hmac_store['key'] = key2.get()
                hmac_store['msg'] = msg2.get()
                output_write(out2, f"HMAC-SHA256: {mac}")
                self.set_status("HMAC computed.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        def do_verify_hmac():
            if 'mac' not in hmac_store:
                self.set_status("Compute HMAC first.", DANGER); return
            valid = verify_hmac(hmac_store['key'], msg2.get(), hmac_store['mac'])
            output_write(out2,
                f"HMAC       : {hmac_store['mac']}\n"
                f"Valid      : {valid}\n"
                f"{'[+] Authentic' if valid else '[!] TAMPERED or wrong key'}"
            )
            self.set_status("HMAC verified.", ACCENT2 if valid else DANGER)

        bf = tk.Frame(t2, bg=PANEL_BG); bf.pack(padx=20, anchor='w')
        make_button(bf, "Compute HMAC", do_hmac).pack(side='left', padx=(0, 8))
        make_button(bf, "Verify", do_verify_hmac, color=ACCENT2).pack(side='left')

        # ── Password Tab ────────────────────────
        t3 = tk.Frame(nb, bg=PANEL_BG); nb.add(t3, text="Password (PBKDF2)")
        f3 = tk.Frame(t3, bg=PANEL_BG); f3.pack(padx=20, pady=16, anchor='nw')

        pwd3 = row_label_entry(f3, "Password:", 0, show='*')
        out3 = make_output(t3, height=8); out3.pack(padx=20, pady=8, fill='x')
        pwd_store = {}

        def do_hash_pwd():
            self.set_status("Hashing (100k iterations)...", ACCENT)
            def run():
                stored = hash_password(pwd3.get())
                pwd_store['stored'] = stored
                output_write(out3, f"Stored JSON:\n{stored}")
                self.set_status("Password hashed with PBKDF2.", ACCENT2)
            threading.Thread(target=run, daemon=True).start()

        def do_verify_pwd():
            if 'stored' not in pwd_store:
                self.set_status("Hash a password first.", DANGER); return
            valid = verify_password(pwd3.get(), pwd_store['stored'])
            output_write(out3,
                f"Stored : {pwd_store['stored'][:60]}...\n\n"
                f"Result : {'LOGIN SUCCESS ✓' if valid else 'LOGIN FAILED ✗'}"
            )
            self.set_status("Password verified.", ACCENT2 if valid else DANGER)

        bf3 = tk.Frame(t3, bg=PANEL_BG); bf3.pack(padx=20, anchor='w')
        make_button(bf3, "Hash Password", do_hash_pwd).pack(side='left', padx=(0, 8))
        make_button(bf3, "Verify Login", do_verify_pwd, color=ACCENT2).pack(side='left')

        # ── File Integrity Tab ──────────────────
        t4 = tk.Frame(nb, bg=PANEL_BG); nb.add(t4, text="File Integrity")
        f4 = tk.Frame(t4, bg=PANEL_BG); f4.pack(padx=20, pady=16, anchor='nw')

        path_var = tk.StringVar()
        tk.Label(f4, text="File:", font=FONT_LABEL, fg=TEXT, bg=PANEL_BG).grid(
            row=0, column=0, sticky='w', pady=4)
        tk.Entry(f4, textvariable=path_var, width=35, font=FONT_MONO,
                 bg=CARD_BG, fg=TEXT, insertbackground=ACCENT,
                 relief='flat', bd=4).grid(row=0, column=1, sticky='w', pady=4)
        make_button(f4, "Browse", lambda: path_var.set(
            filedialog.askopenfilename()), color=BTN_BG).grid(
            row=0, column=2, padx=8)

        out4 = make_output(t4, height=6); out4.pack(padx=20, pady=8, fill='x')

        def do_hash_file():
            try:
                digest = hash_file(path_var.get())
                output_write(out4, f"SHA-256:\n{digest}")
                self.set_status("File hashed.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f4, "Hash File", do_hash_file).grid(
            row=1, column=1, sticky='w', pady=8)

    # ─────────────────────────────────────────────
    #  MODULE 4 — KEY EXCHANGE
    # ─────────────────────────────────────────────

    def _panel_keyx(self, parent):
        self._section(parent, "Module 4 — Key Exchange & Number Theory")

        nb = ttk.Notebook(parent)
        nb.pack(fill='both', expand=True, padx=24, pady=4)

        # ── Number Theory Tab ───────────────────
        t1 = tk.Frame(nb, bg=PANEL_BG); nb.add(t1, text="Number Theory")
        f1 = tk.Frame(t1, bg=PANEL_BG); f1.pack(padx=20, pady=16, anchor='nw')

        a1 = row_label_entry(f1, "a:", 0, width=20)
        b1 = row_label_entry(f1, "b:", 1, width=20)
        out1 = make_output(t1, height=10); out1.pack(padx=20, pady=8, fill='x')

        def do_numth():
            try:
                a, b = int(a1.get()), int(b1.get())
                g_val, x, y = extended_gcd(a, b)
                inv = modular_inverse(a, b) if gcd(a, b) == 1 else "N/A (not coprime)"
                phi = euler_totient(a) if a < 10000 else f"(skipped, {a} too large)"
                mr  = miller_rabin(a)
                output_write(out1,
                    f"Extended GCD({a}, {b})\n"
                    f"  gcd={g_val}, x={x}, y={y}\n"
                    f"  Verify: {a}*{x} + {b}*{y} = {a*x+b*y}\n\n"
                    f"Modular Inverse of {a} mod {b} = {inv}\n\n"
                    f"Euler Totient φ({a}) = {phi}\n\n"
                    f"Miller-Rabin primality of {a}: {'PRIME' if mr else 'NOT PRIME'}"
                )
                self.set_status("Number theory computed.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        make_button(f1, "Compute All", do_numth).grid(
            row=2, column=1, sticky='w', pady=8)

        # ── DH Tab ──────────────────────────────
        t2 = tk.Frame(nb, bg=PANEL_BG); nb.add(t2, text="Diffie-Hellman")
        out2 = make_output(t2, height=14); out2.pack(padx=20, pady=16, fill='x')

        def do_dh():
            self.set_status("Running DH key exchange...", ACCENT)
            def run():
                p, g = DH_PRIME_512, DH_GENERATOR
                a_priv = dh_generate_private_key(p)
                a_pub  = dh_compute_public_key(a_priv, g, p)
                b_priv = dh_generate_private_key(p)
                b_pub  = dh_compute_public_key(b_priv, g, p)
                a_sec  = dh_compute_shared_secret(b_pub, a_priv, p)
                b_sec  = dh_compute_shared_secret(a_pub, b_priv, p)
                match  = a_sec == b_sec
                log_event("KEY_EXCHANGE", {"method": "DH", "match": str(match)})
                output_write(out2,
                    f"Generator  g = {g}\n"
                    f"Prime      p = (512-bit)\n\n"
                    f"Alice private = ...{str(a_priv)[-12:]}\n"
                    f"Alice public  = ...{str(a_pub)[-12:]}\n\n"
                    f"Bob private   = ...{str(b_priv)[-12:]}\n"
                    f"Bob public    = ...{str(b_pub)[-12:]}\n\n"
                    f"Alice secret  = ...{str(a_sec)[-20:]}\n"
                    f"Bob secret    = ...{str(b_sec)[-20:]}\n\n"
                    f"Secrets match : {match}\n"
                    f"{'[+] Secure channel established!' if match else '[!] Mismatch!'}"
                )
                self.set_status("DH key exchange complete.", ACCENT2)
            threading.Thread(target=run, daemon=True).start()

        make_button(t2, "Run DH Exchange", do_dh).pack(padx=20, anchor='w')

    # ─────────────────────────────────────────────
    #  MODULE 5 — BLOCKCHAIN
    # ─────────────────────────────────────────────

    def _panel_blockchain(self, parent):
        self._section(parent, "Module 5 — Blockchain Audit Logger")

        nb = ttk.Notebook(parent)
        nb.pack(fill='both', expand=True, padx=24, pady=4)

        # ── History Tab ─────────────────────────
        t1 = tk.Frame(nb, bg=PANEL_BG); nb.add(t1, text="Chain History")
        out1 = make_output(t1, height=16); out1.pack(padx=20, pady=16, fill='both', expand=True)

        def do_history():
            bc = get_blockchain()
            lines = []
            for b in bc.chain:
                import time as _time
                ts = _time.strftime('%Y-%m-%d %H:%M:%S', _time.localtime(b.timestamp))
                lines.append(
                    f"Block #{b.index}  [{b.event_type}]  {ts}\n"
                    f"  Hash     : {b.block_hash[:30]}...\n"
                    f"  Prev     : {b.previous_hash[:30]}...\n"
                    f"  Nonce    : {b.nonce}\n"
                    f"  Data     : {b.event_data}\n"
                    f"{'─'*50}"
                )
            output_write(out1, '\n'.join(lines))
            self.set_status(f"Chain loaded — {len(bc.chain)} blocks.", ACCENT2)

        make_button(t1, "Load Chain", do_history).pack(padx=20, anchor='w', pady=4)

        # ── Validate Tab ────────────────────────
        t2 = tk.Frame(nb, bg=PANEL_BG); nb.add(t2, text="Validate Chain")
        out2 = make_output(t2, height=12); out2.pack(padx=20, pady=16, fill='x')

        def do_validate():
            bc = get_blockchain()
            lines = []
            valid = True
            for i in range(1, len(bc.chain)):
                cur  = bc.chain[i]
                prev = bc.chain[i-1]
                ok1  = cur.block_hash == cur.compute_hash()
                ok2  = cur.previous_hash == prev.block_hash
                status = "OK ✓" if (ok1 and ok2) else "TAMPERED ✗"
                if not (ok1 and ok2): valid = False
                lines.append(f"Block #{i}: {status}")
            lines.append(f"\n{'Chain VALID ✓' if valid else 'Chain COMPROMISED ✗'}")
            output_write(out2, '\n'.join(lines))
            self.set_status("Validation complete.", ACCENT2 if valid else DANGER)

        make_button(t2, "Validate Chain", do_validate).pack(padx=20, anchor='w', pady=4)

        # ── Add Block Tab ───────────────────────
        t3 = tk.Frame(nb, bg=PANEL_BG); nb.add(t3, text="Add Block")
        f3 = tk.Frame(t3, bg=PANEL_BG); f3.pack(padx=20, pady=16, anchor='nw')

        etype3 = row_label_entry(f3, "Event Type:", 0, width=20)
        edata3 = row_label_entry(f3, "Event Data:", 1)
        out3   = make_output(t3, height=6); out3.pack(padx=20, pady=8, fill='x')

        def do_add_block():
            self.set_status("Mining block...", ACCENT)
            def run():
                bc = get_blockchain()
                b  = bc.add_block(etype3.get().upper(), {"info": edata3.get()})
                output_write(out3,
                    f"Block #{b.index} mined!\n"
                    f"Nonce : {b.nonce}\n"
                    f"Hash  : {b.block_hash[:40]}..."
                )
                self.set_status(f"Block #{b.index} added.", ACCENT2)
            threading.Thread(target=run, daemon=True).start()

        make_button(f3, "Mine & Add Block", do_add_block).grid(
            row=2, column=1, sticky='w', pady=8)

    # ─────────────────────────────────────────────
    #  BONUS — RSA
    # ─────────────────────────────────────────────

    def _panel_rsa(self, parent):
        self._section(parent, "Bonus — RSA Implementation", "+3 marks")

        out = make_output(parent, height=16)
        out.pack(padx=24, pady=8, fill='x')

        f = tk.Frame(parent, bg=PANEL_BG); f.pack(padx=24, anchor='nw')
        msg_e = row_label_entry(f, "Message (short):", 0)

        rsa_store = {}

        def do_rsa():
            self.set_status("Generating 512-bit RSA keys...", ACCENT)
            def run():
                try:
                    pub, priv = rsa_keygen(512)
                    rsa_store['pub']  = pub
                    rsa_store['priv'] = priv
                    msg = msg_e.get() or "SecureVault"
                    ct  = rsa_encrypt(msg, pub)
                    pt  = rsa_decrypt(ct, priv)
                    sig = rsa_sign(msg, priv)
                    vld = rsa_verify(msg, sig, pub)
                    vt  = rsa_verify(msg + "!", sig, pub)
                    e, n = pub
                    d, _ = priv
                    output_write(out,
                        f"RSA KEY PAIR (512-bit)\n{'─'*40}\n"
                        f"e (public)  = {e}\n"
                        f"n (modulus) = ...{str(n)[-20:]}\n"
                        f"d (private) = ...{str(d)[-20:]}\n\n"
                        f"ENCRYPTION\n{'─'*40}\n"
                        f"Message   : {msg}\n"
                        f"Encrypted : ...{str(ct)[-30:]}\n"
                        f"Decrypted : {pt}\n"
                        f"Match     : {pt == msg}\n\n"
                        f"SIGNATURE\n{'─'*40}\n"
                        f"Signature : ...{str(sig)[-30:]}\n"
                        f"Valid     : {vld}\n"
                        f"Tampered  : {vt}  (should be False)"
                    )
                    self.set_status("RSA demo complete.", ACCENT2)
                except Exception as e:
                    self.set_status(str(e), DANGER)
            threading.Thread(target=run, daemon=True).start()

        make_button(f, "Run RSA Demo", do_rsa).grid(row=1, column=1, sticky='w', pady=8)

   
    def _panel_network(self, parent):
        self._section(parent, "Bonus — Network Simulation", "+2 marks  |  Alice + Bob + Eve on separate threads")

        out = make_output(parent, height=18)
        out.pack(padx=24, pady=8, fill='x')

        def append(text):
            out.config(state='normal')
            out.insert(tk.END, text + '\n')
            out.see(tk.END)
            out.config(state='disabled')
            out.update_idletasks()

        def do_sim():
            # Clear output
            out.config(state='normal')
            out.delete('1.0', tk.END)
            out.config(state='disabled')

            self.set_status("Running simulation...", ACCENT)

            def run():
                import queue as _queue
                import time as _time

                a2b   = _queue.Queue()
                b2a   = _queue.Queue()
                log_q = _queue.Queue()
                results = {}

                def safe_append(text):
                    # Schedule UI update on main thread
                    self.root.after(0, append, text)
                    _time.sleep(0.05)  # small delay so output is readable

                def alice():
                    _time.sleep(0.2)
                    a = dh_generate_private_key(DH_PRIME_512)
                    A = dh_compute_public_key(a, DH_GENERATOR, DH_PRIME_512)
                    safe_append(f"[Alice] Generated private key a = ...{str(a)[-8:]}")
                    safe_append(f"[Alice] Computed  public  key A = ...{str(A)[-8:]}")
                    safe_append(f"[Alice] Sending A over public channel...")
                    a2b.put(A)
                    log_q.put(('A', A))
                    B = b2a.get(timeout=15)
                    safe_append(f"[Alice] Received Bob's key   B = ...{str(B)[-8:]}")
                    secret = dh_compute_shared_secret(B, a, DH_PRIME_512)
                    safe_append(f"[Alice] Shared secret = ...{str(secret)[-14:]}")
                    results['alice'] = secret

                def bob():
                    _time.sleep(0.5)
                    b = dh_generate_private_key(DH_PRIME_512)
                    B = dh_compute_public_key(b, DH_GENERATOR, DH_PRIME_512)
                    safe_append(f"[Bob  ] Generated private key b = ...{str(b)[-8:]}")
                    safe_append(f"[Bob  ] Computed  public  key B = ...{str(B)[-8:]}")
                    A = a2b.get(timeout=15)
                    safe_append(f"[Bob  ] Received Alice's key  A = ...{str(A)[-8:]}")
                    safe_append(f"[Bob  ] Sending B over public channel...")
                    b2a.put(B)
                    log_q.put(('B', B))
                    secret = dh_compute_shared_secret(A, b, DH_PRIME_512)
                    safe_append(f"[Bob  ] Shared secret = ...{str(secret)[-14:]}")
                    results['bob'] = secret

                def eve():
                    seen = {}
                    while len(seen) < 2:
                        try:
                            k, v = log_q.get(timeout=10)
                            seen[k] = v
                            safe_append(f"[Eve  ] Intercepted key {k} = ...{str(v)[-8:]}")
                        except:
                            break
                    safe_append("[Eve  ] Has both public keys but CANNOT compute the secret.")
                    safe_append("[Eve  ] Discrete log is computationally infeasible. Giving up.")

                ta = threading.Thread(target=alice, daemon=True)
                tb = threading.Thread(target=bob,   daemon=True)
                te = threading.Thread(target=eve,   daemon=True)
                ta.start(); tb.start(); te.start()
                ta.join();  tb.join();  te.join()

                match = results.get('alice') == results.get('bob')
                self.root.after(0, append, "─" * 40)
                self.root.after(0, append, f"Secrets match : {match}")
                self.root.after(0, append, f"{'[+] Secure channel established!' if match else '[!] Mismatch'}")
                self.root.after(0, self.set_status, "Simulation complete.", ACCENT2)

            # Run everything in one background thread — GUI stays responsive
            threading.Thread(target=run, daemon=True).start()

        make_button(parent, "Run Simulation", do_sim).pack(padx=24, anchor='w', pady=4)

    def _panel_merkle(self, parent):
        self._section(parent, "Bonus — Merkle Tree", "+2 marks  |  Built from blockchain block hashes")

        out = make_output(parent, height=16)
        out.pack(padx=24, pady=8, fill='x')

        merkle_store = {}

        f = tk.Frame(parent, bg=PANEL_BG); f.pack(padx=24, anchor='nw')
        idx_e = row_label_entry(f, "Block index for proof:", 0, width=10)

        def do_build():
            try:
                from bonus_merkle import MerkleTree
                bc = get_blockchain()
                hashes = [b.block_hash for b in bc.chain]
                tree = MerkleTree(hashes)
                merkle_store['tree']   = tree
                merkle_store['hashes'] = hashes
                lines = [f"Merkle Tree — {len(hashes)} leaves\n{'─'*40}"]
                for i, lvl in enumerate(tree.tree):
                    name = "Leaves" if i == 0 else ("Root" if i == len(tree.tree)-1 else f"Level {i}")
                    lines.append(f"[{name}]")
                    for j, h in enumerate(lvl):
                        lines.append(f"  [{j}] {h[:28]}...")
                lines.append(f"\nMerkle Root:\n{tree.root}")
                output_write(out, '\n'.join(lines))
                self.set_status("Merkle tree built.", ACCENT2)
            except Exception as e:
                self.set_status(str(e), DANGER)

        def do_proof():
            if 'tree' not in merkle_store:
                self.set_status("Build tree first.", DANGER); return
            try:
                idx   = int(idx_e.get())
                tree  = merkle_store['tree']
                hashes= merkle_store['hashes']
                proof = tree.get_proof(idx)
                valid = tree.verify_proof(hashes[idx], idx, proof)
                lines = [
                    f"Merkle Proof for Block #{idx}\n{'─'*40}",
                    f"Leaf : {hashes[idx][:30]}...",
                    f"\nProof steps ({len(proof)}):"
                ]
                for i, (sib, pos) in enumerate(proof):
                    lines.append(f"  Step {i+1}: {pos.upper()} sibling = {sib[:24]}...")
                lines.append(f"\nValid: {valid}")
                lines.append(f"{'[+] Block confirmed in tree.' if valid else '[!] Not in tree.'}")
                output_write(out, '\n'.join(lines))
                self.set_status("Merkle proof verified.", ACCENT2 if valid else DANGER)
            except Exception as e:
                self.set_status(str(e), DANGER)

        bf = tk.Frame(parent, bg=PANEL_BG); bf.pack(padx=24, anchor='w', pady=4)
        make_button(bf, "Build Tree", do_build).pack(side='left', padx=(0, 8))
        make_button(bf, "Generate Proof", do_proof, color=ACCENT2).pack(side='left')


if __name__ == "__main__":
    root = tk.Tk()
    app  = SecureVaultApp(root)
    root.mainloop()