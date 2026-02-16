# Secure Scanner – Web Application Vulnerability Scanner

## Project Overview
Secure Scanner is a web-based vulnerability scanning tool developed using Python and Django as part of the CDAC PG-DITISS Cybersecurity program. This tool helps identify common web application vulnerabilities and security misconfigurations by scanning websites and analyzing their HTTP responses, headers, and input fields.

The scanner provides a user-friendly web interface where users can enter a target URL and receive detailed security analysis results. This helps developers and security professionals identify and fix vulnerabilities before attackers exploit them.

---

## Project Objective
The main objectives of this project are:

• Identify common web application vulnerabilities  
• Detect missing HTTP security headers  
• Improve website security posture  
• Automate basic vulnerability scanning  
• Provide easy-to-use web-based interface  
• Help developers secure their applications  

---

## System Architecture

User → Web Interface → Django Backend → Scanner Engine → Target Website → Response Analysis → Result Display

Components used:

• Frontend: HTML, CSS, Bootstrap  
• Backend: Django (Python)  
• Scanner Engine: Python Requests, BeautifulSoup  
• Database: SQLite  
• Version Control: Git & GitHub  

---

## Features

• Web-based vulnerability scanner  
• URL scanning functionality  
• Security header analysis  
• Detection of missing security headers  
• HTTP response analysis  
• Input field and form analysis  
• Automated scanning process  
• Real-time results display  
• User-friendly interface  

---

## Vulnerabilities Detected

Missing Security Headers:

• Content-Security-Policy  
• X-Frame-Options  
• X-XSS-Protection  
• Strict-Transport-Security  
• X-Content-Type-Options  

Other Issues:

• Insecure HTTP configuration  
• Missing security protections  
• Potential XSS vulnerable input fields  
• Security misconfigurations  

---

## Technologies Used

Python – Backend logic  
Django – Web framework  
HTML – Frontend structure  
CSS – Styling  
Bootstrap – UI design  
Requests – HTTP requests  
BeautifulSoup – HTML parsing  
SQLite – Database  
Git – Version control  
GitHub – Code hosting  

---

## Installation and Setup

Follow these steps to run locally:

Clone repository:
git clone https://github.com/snehith-0717/Secure-Scanner.git

Go to project folder:
cd Secure-Scanner/security_scanner

Create virtual environment:
python -m venv venv

Activate virtual environment (Windows):
venv\Scripts\activate

Install dependencies:
pip install -r requirements.txt

Run server:
python manage.py runserver

Open browser:
http://127.0.0.1:8000

---

## How It Works

1. User enters target website URL  
2. Backend receives request  
3. Scanner sends HTTP request to target  
4. Scanner analyzes headers and response  
5. Scanner detects security issues  
6. Scanner displays results  

---

## Example Use Cases

• Website security testing  
• Learning cybersecurity scanning  
• Academic cybersecurity project  
• Security misconfiguration detection  
• Developer security testing  

---

## Security Controls Implemented

• Input validation  
• Secure request handling  
• Controlled scanning logic  
• Error handling  

---

## Limitations

• Detects only basic vulnerabilities  
• Does not perform deep penetration testing  
• Cannot scan login-protected pages  

---

## Future Enhancements

• SQL Injection detection  
• XSS payload testing  
• Automated report generation  
• Authentication scanning  
• Cloud deployment  
• Advanced vulnerability detection  

---

## Author

Name: Snehith Siripurapu  
Course: PG-DITISS (CDAC)  
Domain: Cybersecurity  
Project: Secure Scanner  

GitHub: https://github.com/snehith-0717

---

## Academic Project

This project was developed as part of CDAC PG-DITISS Cybersecurity program.

---

## License

Educational use only.

---

## Acknowledgement

Thanks to CDAC for cybersecurity training and project guidance.
