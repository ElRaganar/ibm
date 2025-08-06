import os
import json
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font
import ttkbootstrap as tb
import logging
from datetime import datetime



RULES_PATH = 'rules.json'


LOG_DIR = "logs"
REPORT_DIR = "reports"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

log_file_path = os.path.join(LOG_DIR, "app_log.log")
logging.basicConfig(
    filename=log_file_path,
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)



def get_rules():
    if not os.path.exists(RULES_PATH):
        return {
            "Games": ["game", "steam", "play"],
            "Development": ["code", "editor", "vscode", "intellij"],
            "Utilities": ["setup", "tool", "utility"],
            "Media": ["music", "video", "player"]
        }
    with open(RULES_PATH, 'r') as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_PATH, 'w') as f:
        json.dump(rules, f, indent=4)

def file_hash(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def scan_folder(path, rules):
    hashes = {}
    duplicates = []
    categorized = {}

    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                h = file_hash(full_path)
                if h in hashes:
                    duplicates.append(full_path)
                else:
                    hashes[h] = full_path

                matched = False
                for category, keywords in rules.items():
                    if any(keyword.lower() in file.lower() for keyword in keywords):
                        categorized.setdefault(category, []).append(full_path)
                        matched = True
                        break
                if not matched:
                    categorized.setdefault("Uncategorized", []).append(full_path)
            except Exception as e:
                print(f"Error scanning {full_path}: {e}")

    return duplicates, categorized

def generate_report(duplicates, categorized):
    lines = ["🧾 Scan Report", "=" * 40]
    lines.append(f"Total Duplicates: {len(duplicates)}\n")
    for d in duplicates:
        lines.append(f"- {d}")

    lines.append("\n📁 Categorized Applications:\n")
    for category, files in categorized.items():
        lines.append(f"{category} ({len(files)} files):")
        for f in files:
            lines.append(f"  - {f}")
        lines.append("")

    return "\n".join(lines)


class AppManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Application Manager")
        self.style = tb.Style("darkly")
        self.root.resizable(False, False)
        self.rules = get_rules()
        self.scan_path = tk.StringVar()
        self.custom_font = font.Font(family="Helvetica", size=11)
        
        self.build_gui()

    def build_gui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

  
        ttk.Label(frame, text="Select Folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.scan_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(frame, text="📁 Browse", command=self.browse_folder, bootstyle="primary").grid(row=0, column=2, padx=5)
        ttk.Button(frame, text="✅ Scan", command=self.scan, bootstyle="success").grid(row=0, column=3, padx=5)

    
        self.result_text = tk.Text(frame, height=30, wrap="none",font=self.custom_font)
        self.result_text.grid(row=1, column=0, columnspan=4, pady=10, sticky="nsew")
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(1, weight=1)
    
        # self.result_text = tk.Text(frame, height=20, wrap="none", font=custom_font)


        ttk.Button(frame, text="🧹 Clean Duplicates", command=self.delete_duplicates, bootstyle="danger").grid(row=2, column=0, pady=5)
        ttk.Button(frame, text="✏️ Edit Rules", command=self.open_rule_editor, bootstyle="warning").grid(row=2, column=1, pady=5)
        ttk.Button(frame, text="💾 Save Rules", command=lambda: save_rules(self.rules), bootstyle="info").grid(row=2, column=2, pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.scan_path.set(folder)

    def scan(self):
        path = self.scan_path.get()
        if not path or not os.path.isdir(path):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        duplicates, categorized = scan_folder(path, self.rules)

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "--- Duplicates ---\n")
        for f in duplicates:
            self.result_text.insert(tk.END, f"{f}\n")

        self.result_text.insert(tk.END, "\n--- Categorized ---\n")
        for cat, files in categorized.items():
            self.result_text.insert(tk.END, f"\n[{cat}]\n")
            for f in files:
                self.result_text.insert(tk.END, f"{f}\n")
        # Save report to file
        report_text = generate_report(duplicates, categorized)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file_path = os.path.join(REPORT_DIR, f"session_report_{timestamp}.txt")
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        logging.info("Scan completed and report saved to %s", report_file_path)

        self.duplicates = duplicates

    def delete_duplicates(self):
        if not hasattr(self, 'duplicates') or not self.duplicates:
            messagebox.showinfo("No Duplicates", "No duplicates found to delete.")
            return

        deleted = []
        for f in self.duplicates:
            try:
                os.remove(f)
                deleted.append(f)
            except Exception as e:
                print(f"Error deleting {f}: {e}")

        messagebox.showinfo("Done", f"Deleted {len(deleted)} duplicate files.")
        self.scan()  # Refresh view

    def open_rule_editor(self):
        editor = tk.Toplevel(self.root)
        editor.title("Edit Categorization Rules")
        editor.resizable(False, False)
        rule_frame = ttk.Frame(editor, padding=10)
        rule_frame.pack(fill="both", expand=True)

        row = 0
        self.rule_entries = {}
        for category, keywords in self.rules.items():
            ttk.Label(rule_frame, text=f"{category}:").grid(row=row, column=0, sticky="w")
            
            var = tk.StringVar(value=", ".join(keywords))
            entry = ttk.Entry(rule_frame, textvariable=var, width=50)
            entry.grid(row=row, column=1, padx=5)

            self.rule_entries[category] = var
            
            ttk.Button(
                rule_frame, text="❌", 
                command=lambda c=category: self.remove_category(c, editor),
                bootstyle="danger").grid(row=row, column=2, padx=5)
            row += 1  

        ttk.Button(
            rule_frame, text="➕ Add Category", 
            command=lambda: self.add_category(rule_frame),
            bootstyle="primary"
        ).grid(row=row, column=0, pady=10)

        ttk.Button(
            rule_frame, text="✅ Save", 
            command=lambda: self.save_rule_changes(editor),
            bootstyle="success"
        ).grid(row=row, column=1)


    def remove_category(self, category, window):
        if category in self.rules:
            del self.rules[category]
        window.destroy()
        self.open_rule_editor()

    def add_category(self, parent):
        def add():
            cat = cat_var.get().strip()
            keys = keys_var.get().strip().split(',')
            if cat:
                self.rules[cat] = [k.strip() for k in keys if k.strip()]
                top.destroy()
                self.open_rule_editor()

        top = tk.Toplevel(parent)
        top.title("New Category")
        top.resizable(False, False)

        cat_var = tk.StringVar()
        keys_var = tk.StringVar()

        ttk.Label(top, text="Category Name:").grid(row=0, column=0)
        ttk.Entry(top, textvariable=cat_var).grid(row=0, column=1)
        ttk.Label(top, text="Keywords (comma-separated):").grid(row=1, column=0)
        ttk.Entry(top, textvariable=keys_var).grid(row=1, column=1)
        ttk.Button(top, text="Add", command=add).grid(row=2, column=1)

    def save_rule_changes(self, window):
        for cat, var in self.rule_entries.items():
            self.rules[cat] = [k.strip() for k in var.get().split(',') if k.strip()]
        save_rules(self.rules)
        messagebox.showinfo("Saved", "Rules updated successfully.")
        window.destroy()

if __name__ == '__main__':
    root = tb.Window(themename="darkly")
    app = AppManagerGUI(root)
    root.geometry("800x600")
    root.mainloop()
