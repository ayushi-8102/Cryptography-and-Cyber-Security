# Import necessary libraries
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,
modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as symmetric_padding
# Create a class for symmetric encryption/decryption
class SymmetricEncryptor:
def __init__(self, key, block_size):
# Initialize the symmetric encryptor with a key and block size
self.key = key
self.block_size = block_size
self.backend = default_backend()
def encrypt(self, data):
# Encrypt data using the specified algorithm and block mode
cipher = Cipher(
algorithms.TripleDES(self.key) if self.block_size == 64 else

algorithms.AES(self.key),
modes.ECB(),
backend=self.backend
)
encryptor = cipher.encryptor()
# Apply PKCS7 padding to the data
padder = symmetric_padding.PKCS7(self.block_size).padder()
padded_data = padder.update(data) + padder.finalize()

# Perform encryption and return the result
encrypted_data = encryptor.update(padded_data) +
encryptor.finalize()
return encrypted_data
def decrypt(self, encrypted_data):
# Decrypt data using the specified algorithm and block mode
cipher = Cipher(
algorithms.TripleDES(self.key) if self.block_size == 64 else

algorithms.AES(self.key),
modes.ECB(),
backend=self.backend
)
decryptor = cipher.decryptor()
# Remove PKCS7 padding from the decrypted data
unpadder = symmetric_padding.PKCS7(self.block_size).unpadder()
decrypted_data = decryptor.update(encrypted_data) +
decryptor.finalize()
unpadded_data = unpadder.update(decrypted_data) +
unpadder.finalize()
return unpadded_data
# Define a function to run encryption and decryption and measure time
def run_encrypt_decrypt(data, key, block_size, cipher_name):
encryptor = SymmetricEncryptor(key, block_size)
encrypted_data = encryptor.encrypt(data)
decrypted_data = encryptor.decrypt(encrypted_data)
return encrypted_data, decrypted_data
# Set the input size in bits
input_size_bits = 16000
# Create a sample data with 'a' characters
data = b'a' * (input_size_bits // 8)
# Initialize a list to store results
results = []
# Measure execution time for DES encryption and decryption

des_key = b'12345678'
des_time = timeit.timeit(lambda: run_encrypt_decrypt(data, des_key, 64,
"DES"), number=1000)
results.append([1, "DES", "Python", input_size_bits, 64, des_time * 1000,
1])
# Measure execution time for Triple DES encryption and decryption
triple_des_key = b'1234567890123456'
triple_des_time = timeit.timeit(lambda: run_encrypt_decrypt(data,
triple_des_key, 64, "Triple DES"), number=1000)
results.append([2, "Triple DES", "Python", input_size_bits, 64,
triple_des_time * 1000, 2])
# Measure execution time for AES-128 encryption and decryption
aes_128_key = b'1234567890123456'
aes_128_time = timeit.timeit(lambda: run_encrypt_decrypt(data,
aes_128_key, 128, "AES-128"), number=1000)
results.append([3, "AES-128", "Python", input_size_bits, 128, aes_128_time
* 1000, 3])
# Measure execution time for AES-256 encryption and decryption
aes_256_key = b'12345678901234567890123456789012'
aes_256_time = timeit.timeit(lambda: run_encrypt_decrypt(data,
aes_256_key, 128, "AES-256"), number=1000)
results.append([4, "AES-256", "Python", input_size_bits, 128, aes_256_time
* 1000, 4])
# Sort the results by average time
results.sort(key=lambda x: x[5])
# Assign priorities to the sorted results
for i, result in enumerate(results):
result[6] = i + 1
results = [tuple(result) for result in results]
# Define a table format for result display
table_format = "{:<12} {:<20} {:<25} {:<18} {:<20} {:<22} {:<10}"
# Display the table with results

print(table_format.format("Sr. No.", "Cipher Name", "Language", "Input
Size in bits", "Output Size in bits", "Average Time in ms", "Priority"))
print("-" * 125)
for result in results:
print(table_format.format(result[0], result[1], result[2], result[3],
result[4], "{:.6f}".format(result[5]), result[6]))
# Message indicating the highest priority
print("\nPriority is given to: AES-128")

# Extract cipher names and execution times from the results
cipher_names = [result[1] for result in results]
execution_times_ms = [result[5] for result in results]
# Create a bar chart to visualize execution times
plt.figure(figsize=(10, 6))
plt.barh(cipher_names, execution_times_ms, color='skyblue')
plt.xlabel('Average Execution Time (ms)')
plt.title('Average Execution Time for Different Ciphers')
plt.gca().invert_yaxis() # Invert the y-axis for better readability
plt.grid(axis='x', linestyle='--', alpha=0.6) # Add grid lines on the
x-axis
plt.show()
