import streamlit as st

cheatsheet = {
    "Find MariaDB Docker Process": [
        {
            "description": "List all running Docker containers",
            "command": "docker ps"
        },
        {
            "description": "Find the container running MariaDB (look for 'mariadb' in the IMAGE column)",
            "command": "docker ps | grep mariadb"
        },
    ],
    "Login to MariaDB in Docker": [
        {
            "description": "Login to MariaDB",
            "command": "docker exec -it mariadb mariadb -u <username> -p"
        },
    ],
    "Database Operations": [
        {
            "description": "Show all databases",
            "command": "SHOW DATABASES;"
        },
        {
            "description": "Create a new database",
            "command": "CREATE DATABASE <db_name>;"
        },
        {
            "description": "Select a database",
            "command": "USE <db_name>;"
        },
        {
            "description": "Drop a database",
            "command": "DROP DATABASE <db_name>;"
        },
    ],
    "Table Operations": [
        {
            "description": "Show all tables",
            "command": "SHOW TABLES;"
        },
        {
            "description": "Create a new table",
            "command": "CREATE TABLE <table_name> (column1 TYPE, column2 TYPE, ...);"
        },
        {
            "description": "Describe table structure",
            "command": "DESCRIBE <table_name>;"
        },
        {
            "description": "Drop a table",
            "command": "DROP TABLE <table_name>;"
        },
    ],
    "Data Operations": [
        {
            "description": "Insert data",
            "command": "INSERT INTO <table_name> (column1, column2) VALUES (value1, value2);"
        },
        {
            "description": "Select data",
            "command": "SELECT * FROM <table_name>;"
        },
        {
            "description": "Update data",
            "command": "UPDATE <table_name> SET column=value WHERE <condition>;"
        },
        {
            "description": "Delete data",
            "command": "DELETE FROM <table_name> WHERE <condition>;"
        },
    ],
    "User Management": [
        {
            "description": "Create a new user",
            "command": "CREATE USER 'username'@'host' IDENTIFIED BY 'password';"
        },
        {
            "description": "Grant privileges",
            "command": "GRANT ALL PRIVILEGES ON <db_name>.* TO 'username'@'host';"
        },
        {
            "description": "Apply privilege changes",
            "command": "FLUSH PRIVILEGES;"
        },
        {
            "description": "Show user grants",
            "command": "SHOW GRANTS FOR 'username'@'host';"
        },
        {
            "description": "Delete a user",
            "command": "DROP USER 'username'@'host';"
        },
    ],
}

st.title("MariaDB Cheat Sheet")

for category, items in cheatsheet.items():
    st.header(category, divider=True)
    for item in items:
        st.markdown(f"**{item['description']}**")
        lang = "bash" if "docker" in item['command'] or "bash" in item['command'] or item['command'].startswith("#") else "sql"
        st.code(item['command'], language=lang)


with st.expander("What's `host` in username"):
    st.markdown(
        """
        In MariaDB, users are specified as `'username'@'host'`.  
        - `'localhost'`: Only allows connections from the server itself  
        - `'%'`: Allows connections from any host  
        
        Example:  
        ```sql
        CREATE USER 'user1'@'%' IDENTIFIED BY 'pass';
        ```
        """
    )

with st.expander("What kinds of GRANT can I use?"):
    st.markdown(
        """
        Main types of GRANT privileges in MariaDB:

        - `ALL PRIVILEGES`: All permissions
        - `SELECT`: Read data
        - `INSERT`: Insert data
        - `UPDATE`: Update data
        - `DELETE`: Delete data
        - `CREATE`: Create databases/tables
        - `DROP`: Drop databases/tables
        - `ALTER`: Alter table structure
        - `INDEX`: Create/drop indexes
        - `GRANT OPTION`: Grant privileges to others

        Example:  
        ```sql
        GRANT SELECT, INSERT ON <db_name>.* TO 'username'@'host';
        ```
        """
    )
