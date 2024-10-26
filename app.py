import os
import platform
import json
import requests
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.markdown import Markdown
from typing import Any
import streamlit as st

# Load secrets from Streamlit
API_KEY = st.secrets["api_key"]  # Your API key is stored in Streamlit secrets
console = Console()

chat_history = []

def clearscr() -> None:
    """Clear the console screen based on the operating system."""
    try:
        osp = platform.system()
        match osp:
            case 'Darwin':
                os.system("clear")
            case 'Linux':
                os.system("clear")
            case 'Windows':
                os.system("cls")
    except Exception:
        pass

def fetch_model_response(prompt: str) -> str:
    """Fetch the model's response based on the input prompt."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "prompt": prompt,
        "temperature": 0.75,
        "max_tokens": 3500,
        "top_p": 1
    }
    
    # Commented out the API endpoint for future use
    # response = requests.post("https://your-api-endpoint.com", headers=headers, json=payload)
    
    # Simulated response for local testing
    return f"Simulated response for: {prompt}"

def Print_AI_out(prompt: str) -> None:
    """Display the AI output in a styled panel."""
    global chat_history
    out = fetch_model_response(prompt)
    ai_out = Markdown(out)

    # Display the output in a Streamlit-friendly way
    st.markdown(f"**AI Output:**\n{out}")

    # Store the output in chat history
    save_data = {
        "Query": str(prompt),
        "AI Answer": str(out)
    }
    chat_history.append(save_data)

def save_chat(chat_history: list[Any]) -> None:
    """Save the chat history to a JSON file."""
    with open('chat_history.json', 'w+') as f:
        f.write(json.dumps(chat_history))

def vuln_analysis(scan_type: str, file_path: str) -> None:
    """Analyze vulnerabilities based on scan data."""
    global chat_history
    with open(file_path, "r") as f:
        file_data = f.read()
    
    instructions = """
    You are a Universal Vulnerability Analyzer powered by the Llama3 model. Your main objective is to analyze any provided scan data or log data to identify potential vulnerabilities in the target system or network. 
    Please provide the scan type and the scan data or log data that needs to be analyzed. 
    """
    data = f"""
        Provide the scan type: {scan_type} 
        Provide the scan data or log data that needs to be analyzed: {file_data}
    """
    prompt = f"[INST] <<SYS>> {instructions}<</SYS>> Data to be analyzed: {data} [/INST]"
    
    Print_AI_out(prompt)

def static_analysis(language_used: str, file_path: str) -> None:
    """Perform static analysis on code files."""
    global chat_history
    with open(file_path, "r") as f:
        file_data = f.read()
    
    instructions = """
        Analyze the given programming file details to identify and clearly report bugs, vulnerabilities, and syntax errors.
        Additionally, search for potential exposure of sensitive information such as API keys, passwords, and usernames. Please provide result in Markdown.
    """
    data = f"""
        - Programming Language: {language_used}
        - File Name: {file_path}
        - File Data: {file_data}
    """
    prompt = f"[INST] <<SYS>> {instructions}<</SYS>> Data to be analyzed: {data} [/INST]"
    
    Print_AI_out(prompt)

def main() -> None:
    """Main function to run the application."""
    clearscr()

    contact_dev = """
    Email = imshivam077@gmail.com
    LinkedIn = https://www.linkedin.com/in/shivam-shukla-5500ba239
    """

    help_menu = """
    - clear_screen: Clears the console screen for better readability.
    - quit_bot: This is used to quit the chat application.
    - contact_dev: Provides my contact information.
    - save_chat: Saves the current session's interactions.
    - help_menu: Lists chatbot commands.
    - vuln_analysis: Does a Vuln analysis using the scan data or log file.
    - static_code_analysis: Does a Static code analysis using the scan data or log file.
    """
    
    # Print the developer contact information and help menu
    console.print(Panel(Markdown(contact_dev)), style="bold blue")
    console.print(Panel(Markdown(help_menu)), style="bold yellow")

    # Streamlit interface
    st.title("AI Analysis Tool")
    st.sidebar.title("Options")
    
    if st.sidebar.button("Save Chat"):
        save_chat(chat_history)
        st.sidebar.success("Chat history saved!")

    prompt = st.text_input("Enter your prompt:", placeholder="What do you want to analyze?")
    
    if st.button("Send"):
        if prompt:
            st.markdown(f"**User:** {prompt}")
            Print_AI_out(prompt)

if __name__ == "__main__":
    main()
