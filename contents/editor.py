import os
import re
from dotenv import load_dotenv
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

# -----------------------------
# Connection defaults from env
# -----------------------------
DB_HOST_DEFAULT = os.getenv("DB_HOST", "localhost")
DB_PORT_DEFAULT = os.getenv("DB_PORT", "3306")
DB_USER_DEFAULT = os.getenv("DB_USER", "")
DB_PASSWORD_DEFAULT = os.getenv("DB_PASSWORD", "")

SYSTEM_SCHEMAS = {"mysql", "information_schema", "performance_schema", "sys"}


def make_db_url(db_name: str, user: str, password: str, host: str, port: str) -> str:
    base = f"mysql+pymysql://{user}:{password}@{host}:{port}"
    if db_name:
        return f"{base}/{db_name}?charset=utf8mb4"
    else:
        return f"{base}/?charset=utf8mb4"


@st.cache_resource
def _engine_cached(db_name: str, user: str, password: str, host: str, port: str):
    return create_engine(
        make_db_url(db_name, user, password, host, port),
        pool_pre_ping=True
    )


def get_engine(db_name: str = ""):
    user = st.session_state.get("db_user", "")
    password = st.session_state.get("db_password", "")
    host = st.session_state.get("db_host", DB_HOST_DEFAULT)
    port = st.session_state.get("db_port", DB_PORT_DEFAULT)
    if not user or not password:
        raise RuntimeError("Not logged in (missing user/password).")
    return _engine_cached(db_name, user, password, host, port)


def test_connection() -> tuple[bool, str]:
    try:
        with get_engine("").connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "Connection successful."
    except SQLAlchemyError as e:
        return False, f"Connection failed: {e}"


def ensure_login():
    if not st.session_state.get("logged_in", False):
        with st.form("login_form"):
            c1, c2 = st.columns(2)
            with c1:
                host = st.text_input(
                    "Host",
                    value=st.session_state.get("db_host", DB_HOST_DEFAULT),
                    help="Hostname or IP"
                )
            with c2:
                port = st.text_input(
                    "Port",
                    value=st.session_state.get("db_port", DB_PORT_DEFAULT),
                    help="e.g., 3306"
                )
            user = st.text_input(
                "User",
                value=st.session_state.get("db_user", DB_USER_DEFAULT)
            )
            password = st.text_input(
                "Password",
                value=st.session_state.get("db_password", DB_PASSWORD_DEFAULT),
                type="password"
            )
            submitted = st.form_submit_button("Log in")

        if submitted:
            st.session_state["db_host"] = (host or "").strip() or DB_HOST_DEFAULT
            st.session_state["db_port"] = (port or "").strip() or DB_PORT_DEFAULT
            st.session_state["db_user"] = (user or "").strip()
            st.session_state["db_password"] = password or ""
            ok, msg = test_connection()
            if ok:
                st.session_state["logged_in"] = True
                st.cache_data.clear()
                st.cache_resource.clear()
                st.rerun()
            else:
                st.error(msg)
        st.stop()


def logout():
    for k in ["logged_in", "db_user", "db_password", "db_host", "db_port"]:
        if k in st.session_state:
            st.session_state.pop(k)
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()


# -----------------------------
# Utilities
# -----------------------------

def extract_dbs_from_grants(grant_rows: list[str]) -> list[str]:
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
    try:
        with get_engine("").connect() as conn:
            rows = conn.execute(text("SHOW GRANTS FOR CURRENT_USER")).fetchall()
            grants = [r[0] for r in rows]
            dbs = extract_dbs_from_grants(grants)

            if not dbs:
                schemata = conn.execute(text("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA")).fetchall()
                candidates = [s[0] for s in schemata if s[0] not in SYSTEM_SCHEMAS]

                accessible = []
                for db in candidates:
                    try:
                        with get_engine(db).connect() as c2:
                            c2.execute(text("SELECT 1"))
                        accessible.append(db)
                    except SQLAlchemyError:
                        pass
                dbs = sorted(accessible)

            return dbs
    except SQLAlchemyError as e:
        st.error(f"Failed to fetch user grants: {e}")
        return []


@st.cache_data(show_spinner=False)
def list_tables(db_name: str, current_user: str):
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


# 追加: 権限確認（対象DBでCREATE可能か）
@st.cache_data(show_spinner=False)
def has_create_priv_on_db(db_name: str, current_user: str) -> bool:
    try:
        with get_engine("").connect() as conn:
            rows = conn.execute(text("SHOW GRANTS FOR CURRENT_USER")).fetchall()
            grants = [r[0] for r in rows]
    except SQLAlchemyError:
        return False

    db_pat = re.compile(rf"ON\s+`{re.escape(db_name)}`\.\*\s+TO\s+", re.IGNORECASE)
    global_pat = re.compile(r"ON\s+\*\.\*\s+TO\s+", re.IGNORECASE)
    for g in grants:
        m = re.match(r"GRANT\s+(.+?)\s+ON\s", g, re.IGNORECASE)
        if not m:
            continue
        privs = m.group(1).upper()
        on_db = bool(db_pat.search(g)) or bool(global_pat.search(g))
        if on_db and ("ALL PRIVILEGES" in privs or "CREATE" in privs):
            return True
    return False


@st.cache_data(show_spinner=False)
def fetch_preview(db_name: str, table: str, current_user: str, limit=100, where_clause=None, order_by=None):
    sql = f"SELECT * FROM `{table}`"
    params = {}
    if where_clause:
        sql += f" WHERE {where_clause}"
    if order_by:
        sql += f" ORDER BY {order_by}"
    sql += " LIMIT :limit"
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
    if not name:
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return name
    return None


def build_type_sql(col_type: str, length: int | None, precision: int | None, scale: int | None) -> str | None:
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
    return sanitize_identifier(name)


def sanitize_username(name: str) -> str | None:
    if not name:
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return name
    return None


@st.cache_data(show_spinner=False)
def user_exists(username: str, host: str, current_user: str) -> bool:
    try:
        with get_engine("").connect() as conn:
            q = text("SELECT COUNT(*) FROM mysql.user WHERE User=:u AND Host=:h")
            cnt = conn.execute(q, {"u": username, "h": host}).scalar() or 0
            return cnt > 0
    except SQLAlchemyError:
        return False


def create_database(db_name: str, charset: str, collate: str) -> tuple[bool, str]:
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

    ensure_login()

    current_user = st.session_state["db_user"]
    current_host = st.session_state.get("db_host", DB_HOST_DEFAULT)
    current_port = st.session_state.get("db_port", DB_PORT_DEFAULT)

    st.caption(f"{current_user}@{current_host}:{current_port}")

    with st.sidebar:
        if False:
            logout()

        allowed_dbs = find_allowed_dbs_for_user(current_user)
        if not allowed_dbs:
            st.error("No accessible databases found. Please check permissions or configuration.")
            st.stop()

        selected_db = st.selectbox("Database", allowed_dbs, index=0)

        st.divider()
        st.subheader("Display options")
        limit = st.slider("Row limit (LIMIT)", value=100, min_value=10, max_value=1000, step=10)

    # CREATE TABLE は権限があるときのみ表示
    can_create = has_create_priv_on_db(selected_db, current_user)
    if can_create:
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

    tables = list_tables(selected_db, current_user)

    st.markdown(f"### `{selected_db}`")

    if not tables:
        st.warning(f"No tables found in `{selected_db}`. Check schema or permissions.")
        st.stop()

    st.caption(f"{len(tables)} tables")

    # プレビューは「開いた後にロード」する：初期表示ではロードしない
    for tbl in tables:
        with st.expander(f"{tbl}", expanded=False):
            cols = st.columns(5)
            with cols[0]:
                # 明示ロード方式（開いた後、ボタン押下で初回ロード → 以降は状態維持）
                load_key = f"loaded_{selected_db}_{tbl}"
                run = st.button("Load", key=f"run_{selected_db}_{tbl}")
                if run:
                    st.session_state[load_key] = True
            with cols[1]:
                where_clause = st.text_input(
                    "WHERE", value="", key=f"where_{selected_db}_{tbl}",
                    help="e.g., status = 'active' AND score > 50"
                )
            with cols[2]:
                order_by = st.text_input(
                    "ORDER BY", value="", key=f"order_{selected_db}_{tbl}",
                    help="e.g., created_at DESC, id ASC"
                )

            df = pd.DataFrame()
            if st.session_state.get(load_key, False):
                df = fetch_preview(
                    selected_db, tbl, current_user,
                    limit=limit,
                    where_clause=where_clause or None,
                    order_by=order_by or None
                )

            if df.empty:
                if st.session_state.get(load_key, False):
                    st.info("No rows to display. Adjust WHERE/ORDER BY and try again.")
                else:
                    st.caption("Open and click Load to fetch preview.")
            else:
                st.write(f"**Table**: `{tbl}` / **Rows displayed**: {len(df)}")
                st.dataframe(df, use_container_width=True)

                with st.expander("Basic stats (numeric columns only)", expanded=False):
                    num_df = df.select_dtypes(include="number")
                    if not num_df.empty:
                        st.dataframe(num_df.describe().T, use_container_width=True)
                    else:
                        st.caption("No numeric columns.")


main()
