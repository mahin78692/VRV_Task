# VRV_Task

## Overview
The **Log Analysis Project** is a Python-based script designed to analyze web server log files. It extracts useful insights, such as:
- **Requests per IP Address**: The number of requests made by each IP address.
- **Most Accessed Endpoint**: The endpoint accessed the most times.
- **Suspicious Activity Detection**: Identifying IP addresses with repeated failed login attempts (status code `401`).

The results are printed in the terminal and saved to a CSV file (`log_analysis_results.csv`).

---

## Features
1. Parse web server logs to extract IP addresses, request methods, endpoints, and status codes.
2. Count and rank requests per IP address.
3. Identify the most frequently accessed endpoint.
4. Detect suspicious activity based on failed login attempts.
5. Save the analysis results in a CSV file for further review.

---

## Prerequisites
- Python 3.7 or higher
- A web server log file in a standard format (e.g., Apache or Nginx log format)

---

## Installation
1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/your-username/log-analysis-project.git
   cd log-analysis-project
## pip install -r requirements.txt
