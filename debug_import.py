import sys
import os
sys.path.insert(0, os.getcwd())

try:
    import cfdiag.network
    print("Import successful")
    print(dir(cfdiag.network))
except Exception as e:
    print(f"Import failed: {e}")
