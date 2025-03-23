# Advanced Threat Detection using AI & ML

## Overview
Advanced Threat Detection using AI & ML is a security tool that simulates, detects, and prevents cyberattacks using machine learning and AI-powered attack generation. It supports five predefined attack types and integrates Meta Llama (via Groq API) to generate AI-driven attacks. The project leverages a Random Forest model for attack detection and provides visual analytics of attack details, severity, and attacker IP logs.

## Features
- **Predefined Attack Detection**: Identifies five types of attacks:
  - Cross-Site Scripting (XSS)
  - SQL Injection
  - Distributed Denial of Service (DDoS)
  - Man-in-the-Middle (MITM)
  - Bruteforce
- **Attack Simulation**:
  - Button to simulate **10 random attacks**
  - Button to trigger **AI-generated attacks** using Meta Llama via Groq API
- **Machine Learning-Based Detection**:
  - Uses **Random Forest** for attack detection
  - Button to **train the model** for improved accuracy
- **Visualization & Logging**:
  - Displays attack logs with attacker IP, attack type, and severity
  - Interactive charts for real-time monitoring
- **Security Features**:
  - Option to **blacklist attacker IPs** to prevent future attacks

## Technologies Used
- **Backend**: Python, Flask
- **Machine Learning**: Scikit-learn (Random Forest Model)
- **AI Attack Generation**: Meta Llama via Groq API
- **Visualization**: Matplotlib, Seaborn, Plotly
- **Database**: SQLite / MySQL (for logs and blacklist management)
- **Frontend**: HTML, CSS, JavaScript (with Bootstrap)

## Installation
### Steps to Run the Project (Works on Windows, Linux, and macOS)
1. **Download the Project**:
   - Clone the repository using Git:
   ```bash
   git clone https://github.com/yourusername/advanced-threat-detection.git
   ```
2. **Open in PyCharm**:
   - Open PyCharm and navigate to the project folder.
3. **Install Required Pip Modules**:
   - Open the terminal in PyCharm and run:
   ```bash
   pip install flask requests random json os datetime
   ```
4. **Set Up Groq API Key**:
   - Get your API key from [Groq Console](https://console.groq.com/keys)
   - Open `app.py` and add the following line:
   ```python
   # Updated Groq API key
   GROQ_API_KEY = "your-api-key-here"
   ```
5. **Run the Project**:
   - In PyCharm, open `app.py` and click the **Run** button or run in terminal:
   ```bash
   python app.py
   ```
6. **Access the Web Interface**:
   - The terminal will display a link. Open that link in your browser.
   - Example: `http://127.0.0.1:5000/`

---

## Screenshots
(Add screenshots of the application here)

---

## Contributing
Feel free to contribute by submitting pull requests, reporting issues, or suggesting improvements.

## Credits
Special thanks to [Santhosh D](https://github.com/santhoshD123) for his guides that helped me understand AI.

## Contact
For any doubts, contact me on **Telegram**: [@Gokul0x50](https://t.me/gokul0x50)
