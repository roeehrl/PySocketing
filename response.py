import io



binary_stream = io.BytesIO()
# Binary data and strings are different types, so a str
# must be encoded to binary using ascii, utf-8, or other.
binary_stream.write(b'adamcode12345678')
binary_stream.write(b'3')
binary_stream.write(bytes(2))
binary_stream.write(bytes(4))
binary_stream.write(bytes(255))

# Move cursor back to the beginning of the buffer
#binary_stream.seek(0)

# Read all data from the buffer
stream_data = binary_stream.read()

# The stream_data is type 'bytes', immutable
print(type(stream_data))
print(stream_data)

# To modify the actual contents of the existing buffer
# use getbuffer() to get an object you can modify.
# Modifying this object updates the underlying BytesIO buffer
mutable_buffer = binary_stream.getbuffer()
print(type(mutable_buffer))  # class 'memoryview'
mutable_buffer[17] = 11
mutable_buffer[18] = 2
mutable_buffer[22] = 255

# Re-read the original stream. Contents will be modified
# because we modified the mutable buffer
binary_stream.seek(0)
print(binary_stream.read())
