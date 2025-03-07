HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>A generic Web Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .card { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .warning { color: #856404; background-color: #fff3cd; border-color: #ffeeba; padding: 10px; }
        .results { background-color: #f8f9fa; padding: 15px; margin-top: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerable Web Application</h1>
        <div class="warning">
            <strong>Warning:</strong> This application is made vulnerable to test for various security vulnerabilities.
        </div>

        {% if results %}
        <div class="results">
            {{ results|safe }}
        </div>
        {% endif %}
        
        <div class="card">
            <h2>SQL Injection Test</h2>
            <form action="/" method="GET">
                <label for="id">User ID:</label>
                <input type="text" id="id" name="id">
                <input type="submit" value="Search">
            </form>
        </div>
        
        <div class="card">
            <h2>Command Injection Test</h2>
            <form action="/" method="GET">
                <label for="host">Host to ping:</label>
                <input type="text" id="host" name="host">
                <input type="submit" value="Ping">
            </form>
        </div>
        
        <div class="card">
            <h2>XSS Test</h2>
            <form action="/" method="GET">
                <label for="message">Message:</label>
                <input type="text" id="message" name="message">
                <input type="submit" value="Display">
            </form>
        </div>
    </div>
</body>
</html>
'''

THREAT_PATTERNS = {
    'sql_injection': [
        r".*SQL Injection.*",
        r".*SELECT.*WHERE.*=.*OR.*",
        r".*UNION SELECT.*",
        r".*'--.*",
        r".*\"\s+OR\s+\".*=.*"
    ],
    'xss': [
        r".*XSS attempt.*",
        r".*<script>.*</script>.*",
        r".*alert\(.*\).*",
        r".*javascript:.*"
    ],
    'command_injection': [
        r".*Command Injection.*",
        r".*;\s*ls\s*",
        r".*;\s*rm\s*",
        r".*\|\s*bash.*",
        r".*\|\s*sh.*"
    ],
    'directory_traversal': [
        r".*\.\.\/.*",
        r".*\.\.\\.*",
        r".*%2e%2e%2f.*"
    ]
}

ATTACK_MAPPING = {
    'sql_injection': {
        'tactic': 'Initial Access, Credential Access',
        'technique': 'T1190 - Exploit Public-Facing Application',
        'description': 'Attacker attempts to inject SQL commands to bypass authentication or extract data'
    },
    'xss': {
        'tactic': 'Initial Access, Defense Evasion',
        'technique': 'T1059.007 - Command and Scripting Interpreter: JavaScript',
        'description': 'Attacker attempts to inject malicious scripts to be executed in users\' browsers'
    },
    'command_injection': {
        'tactic': 'Execution, Privilege Escalation',
        'technique': 'T1059 - Command and Scripting Interpreter',
        'description': 'Attacker attempts to execute system commands through application vulnerabilities'
    }
}

MITIGATIONS = {
    'sql_injection': [
        'Use prepared statements or parameterized queries',
        'Implement input validation and sanitization',
        'Apply principle of least privilege for database accounts',
        'Consider using an ORM (Object-Relational Mapping) tool'
    ],
    'xss': [
        'Implement Content-Security-Policy headers',
        'Use context-appropriate output encoding',
        'Sanitize user input before rendering to page',
        'Use modern frameworks that automatically escape content'
    ],
    'command_injection': [
        'Avoid using system commands with user-supplied input',
        'Use safer alternatives to execute system functionality',
        'Implement strict input validation',
        'Run applications with minimal required privileges'
    ]
}
