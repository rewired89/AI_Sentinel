# aihunter/ui/alerts/windows_popup.py
# Fully English, custom dialog (no OS-localized buttons).
import tkinter as tk
from tkinter import ttk

def show_alert(title: str, message: str):
    # Create a tiny, always-on-top window with English UI
    root = tk.Tk()
    root.title(title or "AI Sentinel — Security Alert")
    root.attributes("-topmost", True)
    root.resizable(False, False)

    # Remove from taskbar and make it feel like a dialog
    root.overrideredirect(False)

    # Content
    frame = ttk.Frame(root, padding=16)
    frame.grid()

    lbl = ttk.Label(frame, text=message or "Security alert.", justify="left", wraplength=480)
    lbl.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

    def close():
        try:
            root.destroy()
        except Exception:
            pass

    ok_btn = ttk.Button(frame, text="OK", command=close)
    ok_btn.grid(row=1, column=1, sticky="e")

    # Center on screen
    root.update_idletasks()
    w = root.winfo_width()
    h = root.winfo_height()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    x = int((sw - w) / 2)
    y = int((sh - h) / 3)
    root.geometry(f"+{x}+{y}")

    root.mainloop()
