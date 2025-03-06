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

