# generar_bytearray.py
# para buscar los Bad Character o BadCharacter
 
def generate_bytearray():
    bad_chars = [0x00]
    bytearray = bytes([x for x in range(1, 256) if x not in bad_chars])
    return bytearray
 
def print_bytearray(bytearray):
    hex_array = ['\\x{:02x}'.format(b) for b in bytearray]
    print("".join(hex_array))
 
if __name__ == "__main__":
    bytearray = generate_bytearray()
    print("Generated bytearray:")
    print_bytearray(bytearray)
