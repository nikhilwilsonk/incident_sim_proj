from flask import Flask, request, render_template_string, redirect
import os
import json
import datetime
import re
from ui import HTML_TEMPLATE

app = Flask(__name__)
os.makedirs('log/webapp', exist_ok=True)

def log_access(page, params):
    '''
    This function is to log the website accesses,
    the ip of the client
    the parameter which is being passed to the url 
    '''
    with open('log/webapp/access.log', 'a') as log_file:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        log_entry = f"[{timestamp}] IP: {ip} | Page: {page} | Params: {json.dumps(params)} | UA: {user_agent}\n"
        log_file.write(log_entry)

def log_security_event(event_type, input_value):
    '''
    this function is triggered whenever there is a security event
    sql injection attacks,
    cross-site scripting
    command executions are logged using this function
    '''
    with open('log/webapp/security.log', 'a') as log_file:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip = request.remote_addr
        log_entry = f"[{timestamp}] ALERT: Possible {event_type} attempt from {ip} - Input: {input_value}\n"
        log_file.write(log_entry)

@app.route('/')
def index():
    
    log_access(request.path, request.args.to_dict())
    results = []
    
    if 'id' in request.args:
        '''
        SQL Injection check:
        check if id parameter passed in the request.args==check for sql injection
        '''
        user_id = request.args.get('id')
        results.append(f"<div>Fetching user with ID: {user_id}</div>")
        results.append(f"<div>SQL Query: SELECT * FROM users WHERE id = {user_id}</div>")
        if any(char in user_id for char in ["'", '"', ";"]):
            log_security_event("SQL Injection", user_id)
    
    if 'host' in request.args:
        '''
        Command Injection check:
        check if host parameter passed in the request.args==check for command injection
        '''
        host = request.args.get('host')
        results.append(f"<div>Pinging host: {host}</div>")
        results.append(f"<div>Command: ping -c 1 {host}</div>")
        if any(char in host for char in [";", "|", "&"]):
            log_security_event("Command Injection", host)
    
    if 'message' in request.args:
        '''
        XSS Injection check:
        check if message parameter passed in the request.args==check for cross site
        '''
        message = request.args.get('message')
        results.append(f"<div>Your message: {message}</div>")
        if '<script>' in message.lower():
            log_security_event("XSS", message)
    '''
    rendering the ui template with additional
    last entered input
    '''
    return render_template_string(
        HTML_TEMPLATE,
        results=''.join(results) if results else None
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)