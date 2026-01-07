
import os
import re
from dotenv import load_dotenv
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

# -----------------------------
# Connection settings (host/port from env; user/pass via login form)
# -----------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")

SYSTEM_SCHEMAS = {
    "mysql", "information_schema", "performance_schema", "sys"
}


def make_db_url(db_name: str, user: str, password: str) -> str:
    """
    Build a SQLAlchemy connection URL.
    If db_name is empty, connect without selecting a schema (for SHOW GRANTS, etc.).
    """
    base = f"mysql+pymysql://{user}:{password}@{DB_HOST}:{DB_PORT}"
    if db_name:
        return f"{base}/{db_name}?charset=utf8mb4"
    else:
        return f"{base}/?charset=utf8mb4"


# --- Engine factory with cache keyed by (db, user, host, port) ---
@st.cache_resource
def _engine_cached(db_name: str, user: str, password: str, host: str, port: str):
    return create_engine(make_db_url(db_name, user, password), pool_pre_ping=True)


def get_engine(db_name: str = ""):
    """
    Get an engine for the currently logged-in user from session_state.
    """
    user = st.session_state.get("db_user", "")
    password = st.session_state.get("db_password", "")
    if not user or not password:
        raise RuntimeError("Not logged in (missing user/password).")
    return _engine_cached(db_name, user, password, DB_HOST, DB_PORT)


def test_connection() -> tuple[bool, str]:
    """
    Try to connect and run a simple query.
    """
    try:
        with get_engine("").connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "Connection successful."
    except SQLAlchemyError as e:
        return False, f"Connection failed: {e}"


def ensure_login():
    """
    Show the login form until a valid connection is established.
    Credentials persist in st.session_state for the session lifetime.
    """
    default_user = os.getenv("DB_USER", "")
    default_pass = os.getenv("DB_PASSWORD", "")

    if not st.session_state.get("logged_in", False):
        with st.form("login_form", width="content"):
            st.caption(f"{DB_HOST}:{DB_PORT}")
            user = st.text_input("DB User", value=st.session_state.get("db_user", default_user))
            password = st.text_input("DB Password", value=st.session_state.get("db_password", default_pass), type="password")
            submitted = st.form_submit_button("Log in")

        if submitted:
            st.session_state["db_user"] = (user or "").strip()
            st.session_state["db_password"] = password or ""
            ok, msg = test_connection()
            if ok:
                st.session_state["logged_in"] = True
                # Clear caches because credentials changed
                st.cache_data.clear()
                st.cache_resource.clear()
                st.rerun()
            else:
                st.error(msg)
        # Stop until login succeeds
        st.stop()


def logout():
    """
    Clear credentials and caches, then restart the app flow.
    """
    for k in ["logged_in", "db_user", "db_password"]:
        if k in st.session_state:
            st.session_state.pop(k)
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()


# -----------------------------
# Utilities
# -----------------------------

def extract_dbs_from_grants(grant_rows: list[str]) -> list[str]:
    """
    Parse SHOW GRANTS output and extract schema names that look like: ON `db`.* TO ...
    """
    dbs = set()
    pattern = re.compile(r"ON\s+`([^`]+)`\.\*\s+TO\s+", re.IGNORECASE)
    for g in grant_rows:
        m = pattern.search(g)
        if m:
            db = m.group(1)
            if db and db not in SYSTEM_SCHEMAS:
                dbs.add(db)
    return sorted(dbs)


@st.cache_data(show_spinner=False)
def find_allowed_dbs_for_user(current_user: str) -> list[str]:
    """
    Derive allowed schemas for the current DB user:
    1) Prefer SHOW GRANTS parsing.
    2) If grants are global and no db-specific entries exist, list SCHEMATA and probe with SELECT 1.
    Cache includes current_user to avoid cross-user contamination.
    """
    try:
        with get_engine("").connect() as conn:
            rows = conn.execute(text("SHOW GRANTS FOR CURRENT_USER")).fetchall()
            grants = [r[0] for r in rows]
            dbs = extract_dbs_from_grants(grants)

            if not dbs:
                # Global-only grants: enumerate available schemata (excluding system) and probe access.
                schemata = conn.execute(text("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA")).fetchall()
                candidates = [s[0] for s in schemata if s[0] not in SYSTEM_SCHEMAS]

                accessible = []
                for db in candidates:
                    try:
                        with get_engine(db).connect() as c2:
                            c2.execute(text("SELECT 1"))
                        accessible.append(db)
                    except SQLAlchemyError:
                        # Skip dbs without permission
                        pass
                dbs = sorted(accessible)

            return dbs
    except SQLAlchemyError as e:
        st.error(f"Failed to fetch user grants: {e}")
        return []


@st.cache_data(show_spinner=False)
def list_tables(db_name: str, current_user: str):
    """
    Return all table names in the given schema. Cache key includes current_user.
    """
    try:
        with get_engine(db_name).connect() as conn:
            q = text("""
                SELECT TABLE_NAME
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = :db
                ORDER BY TABLE_NAME
            """)
            rows = conn.execute(q, {"db": db_name}).fetchall()
            return [r[0] for r in rows]
    except SQLAlchemyError as e:
        st.error(f"Error while listing tables: {e}")
        return []


@st.cache_data(show_spinner=False)
def fetch_preview(db_name: str, table: str, current_user: str, limit=100, where_clause=None, order_by=None):
    """
    Preview rows from a specific table with optional WHERE / ORDER BY and LIMIT.
    Cache key includes current_user.
    """
    sql = f"SELECT * FROM `{table}`"
    params = {}
    if where_clause:
        sql += f" WHERE {where_clause}"
    if order_by:
        sql += f" ORDER BY {order_by}"
    sql += f" LIMIT :limit"
    params["limit"] = limit

    try:
        with get_engine(db_name).connect() as conn:
            df = pd.read_sql(text(sql), conn, params=params)
            return df
    except SQLAlchemyError as e:
        st.error(f"Error while fetching data: {e}")
        return pd.DataFrame()

# -----------------------------
# CREATE TABLE utilities
# -----------------------------


def sanitize_identifier(name: str) -> str | None:
    """
    Allow only SQL identifiers like [A-Za-z_][A-Za-z0-9_]*.
    Returns the name if valid, else None.
    """
    if not name:
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return name
    return None


def build_type_sql(col_type: str, length: int | None, precision: int | None, scale: int | None) -> str | None:
    """
    Map UI type + parameters to MySQL/MariaDB column type SQL.
    """
    t = (col_type or "").upper()
    if t == "INT":
        return "INT"
    if t == "BIGINT":
        return "BIGINT"
    if t == "BOOLEAN":
        return "TINYINT(1)"
    if t == "TEXT":
        return "TEXT"
    if t == "DATE":
        return "DATE"
    if t == "DATETIME":
        return "DATETIME"
    if t in ("VARCHAR", "CHAR"):
        if not length or length <= 0:
            return None
        return f"{t}({length})"
    if t == "DECIMAL":
        if not precision or precision <= 0 or scale is None or scale < 0:
            return None
        return f"DECIMAL({precision},{scale})"
    return None


def ensure_id_autocolumn(columns: list[dict]) -> list[dict]:
    """
    Ensure an auto-generated `id` column exists and is the sole primary key:
    - If no `id` provided, insert as the first column.
    - If `id` provided, enforce BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY.
    - Remove primary_key flag from other columns to avoid composite PK.
    """
    id_pos = None
    for i, c in enumerate(columns):
        name = (c.get("name") or "").strip()
        if name.lower() == "id":
            id_pos = i
            break

    if id_pos is None:
        id_col = {
            "name": "id",
            "type": "BIGINT",
            "length": None,
            "precision": None,
            "scale": None,
            "nullable": False,
            "unique": False,
            "primary": True,
            "auto_inc": True,
            "default_raw": None,
        }
        columns = [id_col] + columns
        id_pos = 0
    else:
        c = columns[id_pos]
        c["type"] = "BIGINT"
        c["length"] = None
        c["precision"] = None
        c["scale"] = None
        c["nullable"] = False
        c["primary"] = True
        c["auto_inc"] = True
        c["default_raw"] = None if (c.get("default_raw") or "").strip() == "" else c["default_raw"]

    for j, c in enumerate(columns):
        if j != id_pos:
            c["primary"] = False

    return columns


def create_table(db_name: str, table_name: str, columns: list[dict]) -> tuple[bool, str]:
    """
    Build and execute a CREATE TABLE statement using given column definitions.
    """
    tname = sanitize_identifier(table_name)
    if not tname:
        return False, "Invalid table name. Use letters, digits, and underscores; must start with a letter or underscore."

    columns = ensure_id_autocolumn(columns)

    col_sql_parts: list[str] = []
    pk_cols: list[str] = []

    for c in columns:
        cname = sanitize_identifier(c.get("name", ""))
        if not cname:
            return False, "Invalid column name detected."

        type_sql = build_type_sql(
            c.get("type", ""),
            c.get("length"),
            c.get("precision"),
            c.get("scale"),
        )
        if not type_sql:
            return False, f"Invalid type parameters for column `{cname}`."

        col_def = f"`{cname}` {type_sql}"
        if not c.get("nullable", True):
            col_def += " NOT NULL"
        if c.get("auto_inc", False):
            col_def += " AUTO_INCREMENT"
        if c.get("unique", False):
            col_def += " UNIQUE"
        default_raw = c.get("default_raw")
        if default_raw:
            col_def += f" DEFAULT {default_raw}"

        col_sql_parts.append(col_def)

        if c.get("primary", False):
            pk_cols.append(f"`{cname}`")

    col_sql_parts.append(f"PRIMARY KEY ({', '.join(pk_cols)})")

    ddl = (
        f"CREATE TABLE `{tname}` (\n  " +
        ",\n  ".join(col_sql_parts) +
        "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
    )

    try:
        with get_engine(db_name).connect() as conn:
            conn.execute(text(ddl))
        return True, f"Table `{tname}` created successfully."
    except SQLAlchemyError as e:
        return False, f"Failed to create table: {e}"

# -----------------------------
# Database & User utilities
# -----------------------------


def sanitize_dbname(name: str) -> str | None:
    """
    Restrict database name to [A-Za-z_][A-Za-z0-9_]*.
    """
    return sanitize_identifier(name)


def sanitize_username(name: str) -> str | None:
    """
    Restrict username to [A-Za-z_][A-Za-z0-9_]* (safe subset).
    """
    if not name:
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return name
    return None


@st.cache_data(show_spinner=False)
def user_exists(username: str, host: str, current_user: str) -> bool:
    """
    Check whether a MySQL user exists at a given host.
    Cached per current_user.
    """
    try:
        with get_engine("").connect() as conn:
            q = text("SELECT COUNT(*) FROM mysql.user WHERE User=:u AND Host=:h")
            cnt = conn.execute(q, {"u": username, "h": host}).scalar() or 0
            return cnt > 0
    except SQLAlchemyError:
        # If query fails (permissions), assume not exist and let CREATE handle errors.
        return False


def create_database(db_name: str, charset: str, collate: str) -> tuple[bool, str]:
    """
    Create a schema with the given charset/collation if it does not exist.
    """
    dname = sanitize_dbname(db_name)
    if not dname:
        return False, "Invalid database name. Use letters, digits, and underscores; must start with a letter or underscore."
    ddl = f"CREATE DATABASE IF NOT EXISTS `{dname}` CHARACTER SET {charset} COLLATE {collate};"
    try:
        with get_engine("").connect() as conn:
            conn.execute(text(ddl))
        return True, f"Database `{dname}` created (or already exists)."
    except SQLAlchemyError as e:
        return False, f"Failed to create database: {e}"


def grant_privileges(username: str, host: str, db_names: list[str], mode: str) -> tuple[bool, str]:
    """
    Grant privileges on selected databases to the given user@host.
    mode: one of ['Read-only', 'Read-Write (DML)', 'Read-Write + DDL', 'All privileges']
    """
    if mode == "Read-only":
        priv = "SELECT"
    elif mode == "Read-Write (DML)":
        priv = "SELECT, INSERT, UPDATE, DELETE"
    elif mode == "Read-Write + DDL":
        priv = "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX"
    elif mode == "All privileges":
        priv = "ALL PRIVILEGES"
    else:
        return False, "Invalid privilege mode."

    try:
        with get_engine("").connect() as conn:
            for db in db_names:
                dname = sanitize_dbname(db)
                if not dname:
                    return False, f"Invalid database name in grant: `{db}`"
                grant_sql = f"GRANT {priv} ON `{dname}`.* TO '{username}'@'{host}';"
                conn.execute(text(grant_sql))
            conn.execute(text("FLUSH PRIVILEGES;"))
        return True, f"Granted `{mode}` to '{username}'@'{host}' on: {', '.join(db_names)}"
    except SQLAlchemyError as e:
        return False, f"Failed to grant privileges: {e}"


def create_or_update_user(username: str, host: str, password: str) -> tuple[bool, str, bool]:
    """
    Create the user if not exists; otherwise update its password.
    Returns (ok, message, created_flag).
    """
    uname = sanitize_username(username)
    if not uname:
        return False, "Invalid username. Use letters, digits, and underscores; must start with a letter or underscore.", False
    h = host or "%"
    try:
        with get_engine("").connect() as conn:
            if user_exists(uname, h, st.session_state["db_user"]):
                conn.execute(text(f"ALTER USER '{uname}'@'{h}' IDENTIFIED BY :pw"), {"pw": password})
                return True, f"User '{uname}'@'{h}' password updated.", False
            else:
                conn.execute(text(f"CREATE USER '{uname}'@'{h}' IDENTIFIED BY :pw"), {"pw": password})
                return True, f"User '{uname}'@'{h}' created.", True
    except SQLAlchemyError as e:
        return False, f"Failed to create or update user: {e}", False


# -----------------------------
# Main UI
# -----------------------------

def main():
    st.set_page_config(page_title="DB Editor", layout="wide", page_icon=":material/database:")
    st.title("Database Editor")

    ensure_login()  # Blocks until login succeeds

    current_user = st.session_state["db_user"]

    # --- Sidebar: connection & options ---
    with st.sidebar:
        st.subheader("Connection")
        st.caption(f"{current_user}")
        st.caption(f"{DB_HOST}:{DB_PORT}")
        logout_btn = st.button("Log out", type="secondary")
        if logout_btn:
            logout()

        allowed_dbs = find_allowed_dbs_for_user(current_user)
        if not allowed_dbs:
            st.error("No accessible databases found. Please check permissions or configuration.")
            st.stop()

        selected_db = st.selectbox("Database", allowed_dbs, index=0)

        st.divider()
        auto_load = st.toggle("Auto-load tables", value=True)

        st.divider()
        st.subheader("Display options")
        limit = st.slider("Row limit (LIMIT)", value=30, min_value=10, max_value=1000, step=10)

    # --- Root-only operations ---
    if current_user == "root":
        with st.expander("Create new database", expanded=False):
            st.caption("Create a new schema with charset/collation. If it exists, nothing breaks.")

            with st.form("create_database_form"):
                new_db_name = st.text_input("Database name", value="", help="Use only letters, digits, and underscores.")
                c1, c2 = st.columns(2)
                with c1:
                    charset = st.selectbox("Charset", ["utf8mb4", "utf8", "latin1"], index=0)
                with c2:
                    collate_options = {
                        "utf8mb4": ["utf8mb4_unicode_ci", "utf8mb4_general_ci", "utf8mb4_bin"],
                        "utf8": ["utf8_unicode_ci", "utf8_general_ci", "utf8_bin"],
                        "latin1": ["latin1_swedish_ci", "latin1_bin"],
                    }
                    collate = st.selectbox("Collation", collate_options.get(charset, ["utf8mb4_unicode_ci"]), index=0)

                submitted_db = st.form_submit_button("Create database")
                if submitted_db:
                    ok, msg = create_database(new_db_name, charset, collate)
                    if ok:
                        st.success(msg)
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error(msg)

        with st.expander("Create / Manage user", expanded=False):
            st.caption("Create a new user or update password if it already exists. Then grant privileges to selected databases.")

            with st.form("create_user_form"):
                u_cols = st.columns([1, 1, 1, 1.5])
                with u_cols[0]:
                    username = st.text_input("Username", value="", help="Letters, digits, underscores; start with letter or underscore.")
                with u_cols[1]:
                    host_choice = st.selectbox("Host", ["%", "localhost", "custom"], index=0)
                with u_cols[2]:
                    custom_host = st.text_input("Custom host", value="", help="Wildcard or exact host.", disabled=(host_choice != "custom"))
                with u_cols[3]:
                    password = st.text_input("Password", value="", type="password")

                grant_cols = st.columns([1.2, 2.0])
                with grant_cols[0]:
                    grant_mode = st.selectbox(
                        "Privilege level",
                        ["Read-only", "Read-Write (DML)", "Read-Write + DDL", "All privileges"],
                        index=1
                    )
                with grant_cols[1]:
                    dbs_to_grant = st.multiselect("Databases to grant", allowed_dbs, default=[selected_db])

                submitted_user = st.form_submit_button("Create/Update user & Grant")
                if submitted_user:
                    host_val = custom_host if host_choice == "custom" else host_choice
                    ok_u, msg_u, created = create_or_update_user(username.strip(), host_val.strip(), password)
                    if not ok_u:
                        st.error(msg_u)
                    else:
                        st.success(msg_u)
                        ok_g, msg_g = grant_privileges(username.strip(), host_val.strip(), dbs_to_grant, grant_mode)
                        if ok_g:
                            st.success(msg_g)
                            st.cache_data.clear()
                            st.rerun()
                        else:
                            st.error(msg_g)

    # --- Tables view for the selected DB ---
    tables = list_tables(selected_db, current_user)

    st.markdown(f"### `{selected_db}`")

    with st.expander("Create new table", expanded=False):
        st.caption("`id` column (BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY) will be added automatically. Do not add `id` column yourself.")

        col_count = st.number_input("Number of columns (excluding `id`)", value=1, min_value=1, max_value=50, step=1)

        with st.form("create_table_form"):
            tbl_name = st.text_input("Table name", value="", help="Use only letters, digits, and underscores.")

            columns: list[dict] = []
            for i in range(int(col_count)):
                st.markdown(f"**Column {i+1}**")
                c_cols = st.columns([1.6, 1.2, 1.1, 1.1, 1.6])
                with c_cols[0]:
                    cname = st.text_input("name", key=f"ct_name_{i}")
                with c_cols[1]:
                    ctype = st.selectbox(
                        "type",
                        ["INT", "BIGINT", "VARCHAR", "CHAR", "TEXT", "DATE", "DATETIME", "DECIMAL", "BOOLEAN"],
                        index=0,
                        key=f"ct_type_{i}"
                    )
                length = None
                precision = None
                scale = None
                with c_cols[2]:
                    if ctype in ("VARCHAR", "CHAR"):
                        length = st.number_input("length", min_value=1, max_value=65535, value=255, step=1, key=f"ct_len_{i}")
                    elif ctype == "DECIMAL":
                        precision = st.number_input("precision", min_value=1, max_value=65, value=10, step=1, key=f"ct_prec_{i}")
                        scale = st.number_input("scale", min_value=0, max_value=30, value=2, step=1, key=f"ct_scale_{i}")
                with c_cols[3]:
                    nullable = st.checkbox("nullable", value=True, key=f"ct_null_{i}")
                    unique = st.checkbox("unique", value=False, key=f"ct_unique_{i}")
                with c_cols[4]:
                    default_raw = st.text_input(
                        "default (raw SQL)",
                        value="",
                        key=f"ct_def_{i}",
                        help="e.g., 'active', 0, CURRENT_TIMESTAMP"
                    )

                columns.append({
                    "name": cname,
                    "type": ctype,
                    "length": length,
                    "precision": precision,
                    "scale": scale,
                    "nullable": nullable,
                    "unique": unique,
                    "primary": False,
                    "auto_inc": False,
                    "default_raw": (default_raw.strip() or None),
                })

                st.divider()

            submitted = st.form_submit_button("Create table")
            if submitted:
                ok, msg = create_table(selected_db, tbl_name, columns)
                if ok:
                    st.success(msg)
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(msg)

    if not tables:
        st.warning(f"No tables found in `{selected_db}`. Check schema or permissions.")
        st.stop()

    st.caption(f"{len(tables)} tables")
    for tbl in tables:
        with st.expander(f"{tbl}", expanded=False):
            cols = st.columns(5)
            with cols[0]:
                where_clause = st.text_input(
                    "WHERE", value="", key=f"where_{selected_db}_{tbl}",
                    help="e.g., status = 'active' AND score > 50"
                )
            with cols[1]:
                order_by = st.text_input(
                    "ORDER BY", value="", key=f"order_{selected_db}_{tbl}",
                    help="e.g., created_at DESC, id ASC"
                )

            df = pd.DataFrame()
            if auto_load:
                df = fetch_preview(
                    selected_db, tbl, current_user,
                    limit=limit,
                    where_clause=where_clause or None,
                    order_by=order_by or None
                )
            else:
                run = st.button("Load", key=f"run_{selected_db}_{tbl}")
                if run:
                    df = fetch_preview(
                        selected_db, tbl, current_user,
                        limit=limit,
                        where_clause=where_clause or None,
                        order_by=order_by or None
                    )

            if df.empty:
                if auto_load:
                    st.info("No rows to display. Adjust WHERE/ORDER BY and try again.")
                else:
                    st.info("Click Load to fetch data. You can set WHERE/ORDER BY before loading.")
            else:
                st.write(f"**Table**: `{tbl}` / **Rows displayed**: {len(df)}")
                st.dataframe(df, use_container_width=True)

                with st.expander("Basic stats (numeric columns only)", expanded=False):
                    num_df = df.select_dtypes(include="number")
                    if not num_df.empty:
                        st.dataframe(num_df.describe().T, use_container_width=True)
                    else:
                        st.caption("No numeric columns.")


if __name__ == "__main__":
    main()
