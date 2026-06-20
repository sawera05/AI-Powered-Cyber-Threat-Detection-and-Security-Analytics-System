import streamlit as st


USERS = {
    "admin": {"password": "admin", "role": "admin"},
    "analyst": {"password": "1234", "role": "analyst"}
}


def login():

    st.sidebar.title("🔐 SOC Login")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        st.sidebar.success(f"Logged in as {st.session_state.user}")
        return True

    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):

        user = USERS.get(username)

        if user and user["password"] == password:

            st.session_state.authenticated = True
            st.session_state.user = username
            st.session_state.role = user["role"]

            st.sidebar.success("Login Successful")
            return True

        else:
            st.sidebar.error("Invalid credentials")

    return False