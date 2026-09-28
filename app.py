import streamlit as st

st.set_page_config(page_title="طمّان AI", page_icon="🤖", layout="centered")

st.title("🤖 طَمّن AI")
st.markdown("أهلاً بك! اسأل طمّان أي شيء 👇")

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("اكتب سؤالك هنا..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    
    with st.chat_message("assistant"):
        response = f"رد من طمّان على: **{prompt}** ✨"
        st.markdown(response)
        st.session_state.messages.append({"role": "assistant", "content": response})
