import sqlite3

# Connect to the .db file
conn = sqlite3.connect("messaging_server.db")

# Create a cursor object
cursor = conn.cursor()

# Example: list all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables:", tables)

print('USER TABLE')
# Example: read data from users
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()
for row in rows:
    print(row)

print('Sqlite Sequence')
cursor.execute("SELECT * FROM sqlite_sequence")
rows = cursor.fetchall()
for row in rows:
    print(row)

print('Messages')
cursor.execute("SELECT * FROM messages")
rows = cursor.fetchall()
for row in rows:
    print(row)

print('Contacts')
cursor.execute("SELECT * FROM contacts")
rows = cursor.fetchall()
for row in rows:
    print(row)

# Close connection
conn.close()