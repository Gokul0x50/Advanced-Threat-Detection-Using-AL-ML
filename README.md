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
### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Pip
- Virtual Environment (optional but recommended)
- PyCharm (Recommended IDE)

### Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/advanced-threat-detection.git
   cd advanced-threat-detection
   ```
2. **Open Project in PyCharm**:
   - Open PyCharm and select **File > Open**.
   - Navigate to the cloned project folder and open it.
3. **Create and Activate Virtual Environment (Optional)**:
   - In PyCharm, open the terminal and run:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install Dependencies**:
   - In PyCharm terminal, run:
   ```bash
   pip install -r requirements.txt
   ```
5. **Set Up Environment Variables** (e.g., Groq API Key):
   ```bash
   export GROQ_API_KEY='your-api-key'
   ```
   - On Windows, use:
   ```powershell
   set GROQ_API_KEY=your-api-key
   ```
6. **Run the Application**:
   - In PyCharm, open `app.py` and click the **Run** button or run in terminal:
   ```bash
   python app.py
   ```
7. **Access the Web Interface**:
   - Open `http://127.0.0.1:5000/` in your browser.

## Usage
- Click **"Simulate Attack"** to generate 10 random attacks.
- Click **"AI Attack"** to generate an AI-based attack via Meta Llama.
- Click **"Train Model"** to train the Random Forest model.
- View logs and blacklist IPs as needed.

## Contributing
Feel free to contribute by submitting pull requests, reporting issues, or suggesting improvements.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For any queries or collaborations, contact **Gokul P** at [your email].
