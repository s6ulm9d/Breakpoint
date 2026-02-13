
import sys
import site
import os

print(f"Executable: {sys.executable}")
print("Sys Path:")
for p in sys.path:
    print(f"  {p}")

print(f"User Site: {site.getusersitepackages()}")
try:
    import networkx
    print(f"NetworkX imported from: {networkx.__file__}")
except ImportError:
    print("NetworkX NOT importable")
