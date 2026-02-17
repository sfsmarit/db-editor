import streamlit as st

pages = [
    st.Page("contents/editor.py", title="Editor", icon=":material/database:"),
    st.Page("contents/sql_memo.py", title="SQL Memo", icon=":material/bookmark:"),
]
st.navigation(pages).run()
