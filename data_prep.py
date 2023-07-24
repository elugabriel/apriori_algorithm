import pandas as pd
from sqlalchemy import create_engine

# Define the path to your SQL script file
sql_script_file = 'sales_data.sql'

# Create an in-memory SQLite database
engine = create_engine('sqlite:///:memory:')

# Read the SQL script file
with open(sql_script_file, 'r') as file:
    sql_script = file.read()

# Execute the SQL script using the SQLAlchemy engine
with engine.begin() as connection:
    connection.execute(sql_script)

# Fetch the results into a DataFrame
df = pd.read_sql_query('SELECT * FROM your_table', engine)

# Convert the DataFrame to a CSV file
df.to_csv('output.csv', index=False)
