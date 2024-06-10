import hashlib
import time
import mmh3
import cityhash
import farmhash
import whirlpool
from pyblake2 import blake2s
import random
import string
import csv
import matplotlib.pyplot as plt
# Function to generate a random string of length n
def random_string(n):
return ''.join(random.choice(string.ascii_letters + string.digits) for _ in
range(n))
# Function to calculate MD5 hash
def md5_hash(input_str):
return hashlib.md5(input_str.encode()).hexdigest()
# Function to calculate SHA-1 hash
def sha1_hash(input_str):
return hashlib.sha1(input_str.encode()).hexdigest()
# Function to calculate SHA-256 hash
def sha256_hash(input_str):
return hashlib.sha256(input_str.encode()).hexdigest()
# Function to calculate SHA-512 hash

def sha512_hash(input_str):
return hashlib.sha512(input_str.encode()).hexdigest()
# Function to calculate MurmurHash3
def murmur_hash(input_str):
return str(mmh3.hash(input_str))
# Function to calculate CityHash32
def city_hash32(input_str):
return str(cityhash.CityHash32(input_str))
# Function to calculate CityHash64
def city_hash64(input_str):
return str(cityhash.CityHash64(input_str))
# Function to calculate FarmHash32
def farm_hash32(input_str):
return str(farmhash.hash32(input_str))
# Function to calculate FarmHash64
def farm_hash64(input_str):
return str(farmhash.hash64(input_str))
# Function to calculate Whirlpool hash
def whirlpool_hash(input_str):
return whirlpool.new(input_str.encode()).hexdigest()
# Function to calculate BLAKE2s hash
def blake2s_hash(input_str):
return blake2s(input_str.encode()).hexdigest()
# Measure and print the time taken for each hash calculation
def measure_hash_functions():
hash_functions = [
("MD5", md5_hash),
("SHA-1", sha1_hash),
("SHA-256", sha256_hash),
("SHA-512", sha512_hash),
("MurmurHash3", murmur_hash),

("CityHash32", city_hash32),
("CityHash64", city_hash64),
("FarmHash32", farm_hash32),
("FarmHash64", farm_hash64),
("Whirlpool", whirlpool_hash),
("BLAKE2s", blake2s_hash),
]
# Store execution times for sorting and priority calculation
execution_times = []
for name, func in hash_functions:
# Generate a random 1000-character string
input_str = random_string(1000)
# Measure the start time
start_time = time.perf_counter() * 1000
# Calculate the hash
hashed_value = func(input_str)
# Measure the end time
end_time = time.perf_counter() * 1000
# Calculate execution time in milliseconds
execution_time_ms = (end_time - start_time)
# Store the result
execution_times.append((name, execution_time_ms, hashed_value))
# Sort execution times by ascending order
execution_times.sort(key=lambda x: x[1])
# Calculate priorities
priorities = {name: index + 1 for index, (name, _, _) in
enumerate(execution_times)}
# Print the results in a tabular format

print("{:<10} {:<20} {:<20} {:<20}".format("Serial No.", "Hash Function",
"Time (ms)", "Priority"))
for index, (name, execution_time_ms, _) in enumerate(execution_times):
print("{:<10} {:<20} {:<20.6f} {:<20}".format(index + 1, name,
execution_time_ms, priorities[name]))
# Analyze and comment on the comparative efficiency
print("\nComparative Efficiency Analysis:")
print("The most efficient hash function is {} with Priority
1.".format(execution_times[0][0]))
# Run the measurement
measure_hash_functions()
