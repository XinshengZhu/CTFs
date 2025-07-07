from datetime import datetime, timedelta
import time

# Read the encrypted flag
with open('flag.enc', 'rb') as f:
    encrypted = f.read()
print(f"Read {len(encrypted)} bytes from flag.enc")
print(f"First few bytes (hex): {encrypted[:16].hex()}")

# Start from May 1, 2024 00:00:00
start_date = datetime(2024, 5, 1, 0, 0, 0)
start_timestamp = int(start_date.timestamp())

# End at May 31, 2024 23:59:59
end_date = datetime(2024, 5, 31, 23, 59, 59)
end_timestamp = int(end_date.timestamp())

def decrypt_with_timestamp(timestamp):
    """Decrypt the encrypted data using the given timestamp as seed"""
    # The seed is the timestamp minus 1
    seed = timestamp-1
    
    decrypted = bytearray()
    for byte in encrypted:
        # The seed is updated with the previous seed and the magic number
        seed = (0x5851f42d4c957f2d*seed+1)&0xFFFFFFFFFFFFFFFF
        # The random value is the seed right-shifted by 33 bits
        rand_val = seed>>0x21
        # The internal value is the random value minus the random value divided by 127, left-shifted by 7, and then minus the random value divided by 127 again
        internal_val = rand_val-(((rand_val//0x7f)<<7)-(rand_val//0x7f))
        # The decrypted value is the byte XORed with the internal value
        decrypted.append(byte ^ internal_val)
    
    return decrypted

def is_valid_flag(data):
    """Check if the decrypted data contains a valid flag"""
    try:
        # Try to decode as ASCII/UTF-8
        text = data.decode('utf-8', errors='strict')
        
        # Check for flag format
        if 'PWNME{' in text and '}' in text:
            return text    
        return None
    except UnicodeDecodeError:
        return None

print("\nStarting full search...")
start_time = time.time()
last_update = start_time
check_count = 0

# Iterate through the timestamp range
for day in range(31):
    current_date = start_date + timedelta(days=day)
    day_start = int(current_date.timestamp())
    print(f"Checking day {day+1}/31: {current_date.strftime('%Y-%m-%d')}")
    
    flag = None
    for hour in range(24):
        for minute in range(60):            
            for second in range(60):
                timestamp = day_start + hour * 3600 + minute * 60 + second
                decrypted = decrypt_with_timestamp(timestamp)
                check_count += 1
                
                flag = is_valid_flag(decrypted)
                if flag:
                    print(f"\nFound valid flag at {current_date.strftime('%Y-%m-%d')} {hour:02d}:{minute:02d}:{second:02d} (timestamp: {timestamp}):")
                    print(flag)
                    
                    # Calculate and display total execution time
                    total_time = time.time() - start_time
                    hours = int(total_time // 3600)
                    minutes = int((total_time % 3600) // 60)
                    seconds = int(total_time % 60)
                    print(f"Total execution time: {hours:02d}:{minutes:02d}:{seconds:02d}")
                    print(f"Checked {check_count} timestamps")
                    exit(0)
    
    # If we've checked an entire day with no results, print a summary
    if not flag:
        print(f"No flag found for {current_date.strftime('%Y-%m-%d')}")

# Found valid flag at 2024-05-08 20:01:17 (timestamp: 1715198477)
# PWNME{4baf3723f62a15f22e86d57130bc40c3}