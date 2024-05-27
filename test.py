try:
    from Crypto.Util import number
    print("pycryptodome is installed correctly.")
except ImportError as e:
    print("Error: pycryptodome is not installed correctly.")
    print(e)