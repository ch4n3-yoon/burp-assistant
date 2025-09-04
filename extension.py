# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTextField, JCheckBox, JLabel, JButton, JTextArea, JScrollPane, JTabbedPane
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension
from java.awt.event import ActionListener
import threading
import datetime
import hashlib
import random
import string
import time




class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def __init__(self):
        self.log_file_path = "burp_http_log.txt"
        self.vuln_log_path = "burp_vulnerabilities.txt"
        self.test_log_path = "burp_test_results.txt"
        self.logging_enabled = True
        self.auto_test_enabled = True
        self.verbose_testing = True
        self.log_lock = threading.Lock()
        self.request_cache = {}
        self.test_cache = {}
        self.cache_expiry = 3600
        self.test_count = 0

    def _rand_token(self, n=8):
        alphabet = string.ascii_letters + string.digits
        return ''.join(random.choice(alphabet) for _ in range(n))
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Security Tester")
        callbacks.registerHttpListener(self)
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        
        print("Security Tester Extension loaded!")
        return
    
    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        tabbed_pane = JTabbedPane()
        
        tabbed_pane.addTab("Logging", self.create_logging_tab())
        tabbed_pane.addTab("Security", self.create_security_tab())
        tabbed_pane.addTab("Results", self.create_results_tab())
        
        self.main_panel.add(tabbed_pane, BorderLayout.CENTER)
        self.update_status()
    
    def create_logging_tab(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        panel.add(JLabel("Log File:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.file_path_field = JTextField(self.log_file_path, 30)
        panel.add(self.file_path_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 2
        self.enable_logging_checkbox = JCheckBox("Enable HTTP Logging", self.logging_enabled)
        panel.add(self.enable_logging_checkbox, gbc)
        
        gbc.gridy = 2
        self.status_label = JLabel()
        panel.add(self.status_label, gbc)
        
        gbc.gridy = 3
        apply_button = JButton("Apply Settings")
        panel.add(apply_button, gbc)
        
        return panel
    
    def create_security_tab(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.anchor = GridBagConstraints.WEST
        self.auto_test_checkbox = JCheckBox("Enable Auto Security Testing", self.auto_test_enabled)
        panel.add(self.auto_test_checkbox, gbc)
        
        gbc.gridy = 1
        self.verbose_test_checkbox = JCheckBox("Enable Verbose Test Logging", self.verbose_testing)
        panel.add(self.verbose_test_checkbox, gbc)
        
        gbc.gridy = 2
        gbc.gridwidth = 1
        panel.add(JLabel("Vuln Log:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.vuln_path_field = JTextField(self.vuln_log_path, 30)
        panel.add(self.vuln_path_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 3
        panel.add(JLabel("Test Log:"), gbc)
        
        gbc.gridx = 1
        self.test_log_field = JTextField(self.test_log_path, 30)
        panel.add(self.test_log_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 4
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.NONE
        self.test_status_label = JLabel()
        panel.add(self.test_status_label, gbc)
        
        gbc.gridy = 5
        clear_cache_button = JButton("Clear Cache")
        panel.add(clear_cache_button, gbc)
        
        gbc.gridy = 6
        clear_test_log_button = JButton("Clear Test Log")
        panel.add(clear_test_log_button, gbc)
        
        return panel
    
    def create_results_tab(self):
        panel = JPanel(BorderLayout())
        
        self.results_area = JTextArea()
        self.results_area.setEditable(False)
        self.results_area.setText("Security test results will appear here...\n")
        
        scroll_pane = JScrollPane(self.results_area)
        scroll_pane.setPreferredSize(Dimension(600, 400))
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        clear_button = JButton("Clear Results")
        panel.add(clear_button, BorderLayout.SOUTH)
        
        return panel
    
    def update_status(self):
        if hasattr(self, 'status_label'):
            if self.logging_enabled:
                status = "Logging: ON - " + self.log_file_path
            else:
                status = "Logging: OFF"
            self.status_label.setText(status)
        
        if hasattr(self, 'test_status_label'):
            if self.auto_test_enabled:
                test_status = "Security Testing: ACTIVE (Tests: " + str(self.test_count) + ")"
            else:
                test_status = "Security Testing: DISABLED"
            self.test_status_label.setText(test_status)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self.callbacks.TOOL_PROXY:
            return
  
        if self.logging_enabled:
            with self.log_lock:
                try:
                    self.write_log_entry(toolFlag, messageIsRequest, messageInfo)
                except Exception as e:
                    print("Log error: " + str(e))
        
        if self.auto_test_enabled and messageIsRequest:
            try:
                self.perform_security_tests(messageInfo)
            except Exception as e:
                print("Test error: " + str(e))
    
    def write_log_entry(self, toolFlag, messageIsRequest, messageInfo):
        with open(self.log_file_path, 'a') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            host = messageInfo.getHttpService().getHost()
            port = messageInfo.getHttpService().getPort()
            
            f.write("=" * 60 + "\n")
            f.write("Time: " + timestamp + "\n")
            f.write("Host: " + host + ":" + str(port) + "\n")
            f.write("Type: " + ("REQUEST" if messageIsRequest else "RESPONSE") + "\n")
            f.write("-" * 60 + "\n")
            
            if messageIsRequest and messageInfo.getRequest():
                self.write_request(f, messageInfo)
            elif not messageIsRequest and messageInfo.getResponse():
                self.write_response(f, messageInfo)
            
            f.write("\n")
    
    def write_request(self, f, messageInfo):
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            headers = request_info.getHeaders()
            
            f.write("REQUEST HEADERS:\n")
            for header in headers:
                f.write(header + "\n")
            
            body_offset = request_info.getBodyOffset()
            request_bytes = messageInfo.getRequest()
            
            if body_offset < len(request_bytes):
                try:
                    body = self.helpers.bytesToString(request_bytes[body_offset:])
                    f.write("\nREQUEST BODY:\n" + body + "\n")
                except Exception as encode_error:
                    f.write("\nREQUEST BODY: [ENCODING ERROR - " + str(len(request_bytes) - body_offset) + " bytes]\n")
        except Exception as e:
            f.write("Request error: " + str(e) + "\n")
    
    def write_response(self, f, messageInfo):
        try:
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            headers = response_info.getHeaders()
            
            f.write("RESPONSE HEADERS:\n")
            for header in headers:
                f.write(header + "\n")
            
            body_offset = response_info.getBodyOffset()
            response_bytes = messageInfo.getResponse()
            
            if body_offset < len(response_bytes):
                content_type = self.get_content_type(headers)
                
                if self.is_binary_content(content_type):
                    f.write("\nRESPONSE BODY: [BINARY DATA - " + content_type + " - " + str(len(response_bytes) - body_offset) + " bytes]\n")
                else:
                    try:
                        body = self.helpers.bytesToString(response_bytes[body_offset:])
                        f.write("\nRESPONSE BODY:\n")
                        if len(body) > 2000:
                            f.write(body[:2000] + "\n[TRUNCATED]\n")
                        else:
                            f.write(body + "\n")
                    except Exception:
                        f.write("\nRESPONSE BODY: [ENCODING ERROR - " + str(len(response_bytes) - body_offset) + " bytes]\n")
        except Exception as e:
            f.write("Response error: " + str(e) + "\n")
    
    def get_content_type(self, headers):
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip().lower()
        return "unknown"
    
    def is_binary_content(self, content_type):
        binary_types = ["image/", "video/", "audio/", "application/pdf", "application/zip", "application/octet-stream", "font/"]
        return any(content_type.startswith(bt) for bt in binary_types)
    
    def perform_security_tests(self, messageInfo):
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            parameters = request_info.getParameters()
            
            if not parameters:
                return
            
            cache_key = self.get_cache_key(messageInfo)
            current_time = time.time()
            
            if cache_key in self.test_cache:
                if current_time - self.test_cache[cache_key] < self.cache_expiry:
                    return
            
            self.test_cache[cache_key] = current_time
            
            for param in parameters:
                self.test_count += 1
                self.log_test_attempt(messageInfo, param)
                self.test_sqli(messageInfo, param)
                self.test_xss(messageInfo, param)
                self.update_status()
                
        except Exception as e:
            print("Security test error: " + str(e))
    
    def log_test_attempt(self, messageInfo, param):
        if not self.verbose_testing:
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            param_name = param.getName()
            param_value = param.getValue()
            
            with open(self.test_log_path, 'a') as f:
                f.write("-" * 60 + "\n")
                f.write("TEST ATTEMPT #" + str(self.test_count) + "\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("Parameter: " + param_name + " = " + param_value + "\n")
                f.write("Parameter Type: " + str(param.getType()) + "\n")
                f.write("\n")
            
        except Exception as e:
            print("Test log error: " + str(e))
    
    def test_sqli(self, messageInfo, param):
        try:
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            # Clean parameter value - remove any existing quotes for testing
            clean_value = param_value.replace("'", "").replace('"', "")
            
            sqli_found = False
            
            for quote in ["'", '"']:
                # Test 1: Add single quote
                test_value1 = clean_value + quote
                response1 = self.send_test_request(messageInfo, param_name, test_value1, param_type)
                
                if response1:
                    status1 = self.get_status_code(response1)
                    is_error1 = self.is_error_response(response1)
                    
                    if self.verbose_testing:
                        self.log_test_detail("SQLi Step 1", param_name, quote, test_value1, status1, is_error1)
                    
                    if is_error1:
                        # Test 2: Add double quote to "fix" syntax
                        test_value2 = clean_value + quote + quote
                        response2 = self.send_test_request(messageInfo, param_name, test_value2, param_type)
                        
                        if response2:
                            status2 = self.get_status_code(response2)
                            is_error2 = self.is_error_response(response2)
                            
                            if self.verbose_testing:
                                self.log_test_detail("SQLi Step 2", param_name, quote + quote, test_value2, status2, is_error2)
                            
                            if not is_error2:
                                sqli_found = True
                                self.log_sqli_vuln(messageInfo, param_name, quote, response1, response2, test_value1, test_value2)
                                break  # Stop testing this parameter once SQLi is found
            
            if self.verbose_testing and not sqli_found:
                self.log_test_result("SQLi", param_name, "SAFE - No SQL injection detected")
                        
        except Exception as e:
            print("SQLi test error: " + str(e))
    
    def test_xss(self, messageInfo, param):
        try:
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            # Clean parameter value - remove any existing quotes for testing
            clean_value = param_value.replace("'", "").replace('"', "").replace(">", "")

            token = self._rand_token(8)
            xss_payload = token + "'\">"
            test_value = clean_value + xss_payload
            
            response = self.send_test_request(messageInfo, param_name, test_value, param_type)
            
            if response:
                status = self.get_status_code(response)
                has_reflection = self.has_xss_reflection(response, token, xss_payload)
                
                if self.verbose_testing:
                    self.log_test_detail("XSS Test", param_name, xss_payload, test_value, status, has_reflection)
                
                if has_reflection:
                    self.log_xss_vuln(messageInfo, param_name, token, xss_payload, response, test_value)
                elif self.verbose_testing:
                    self.log_test_result("XSS", param_name, "SAFE - No reflection detected")
                
        except Exception as e:
            print("XSS test error: " + str(e))
    
    def log_test_detail(self, test_type, param_name, payload, test_value, status_code, result):
        try:
            with open(self.test_log_path, 'a') as f:
                f.write("  " + test_type + " - " + param_name + "\n")
                f.write("    Payload: " + payload + "\n")
                f.write("    Test Value: " + test_value + "\n")
                f.write("    Response Status: " + str(status_code) + "\n")
                f.write("    Result: " + str(result) + "\n")
                f.write("\n")
        except Exception as e:
            print("Test detail log error: " + str(e))
    
    def log_test_result(self, test_type, param_name, result):
        try:
            with open(self.test_log_path, 'a') as f:
                f.write("  " + test_type + " RESULT - " + param_name + ": " + result + "\n")
                f.write("\n")
        except Exception as e:
            print("Test result log error: " + str(e))
    
    def log_xss_vuln(self, messageInfo, param_name, token, payload, response, test_value):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            
            with open(self.vuln_log_path, 'a') as f:
                f.write("=" * 80 + "\n")
                f.write("XSS VULNERABILITY DETECTED\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("Parameter: " + param_name + "\n")
                f.write("Payload: " + payload + "\n")
                f.write("Test Value: " + test_value + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("-" * 80 + "\n")
                
                if response.getResponse():
                    response_info = self.helpers.analyzeResponse(response.getResponse())
                    body_offset = response_info.getBodyOffset()
                    response_bytes = response.getResponse()
                    
                    if body_offset < len(response_bytes):
                        try:
                            body = self.helpers.bytesToString(response_bytes[body_offset:])
                            context = self.get_xss_context(body, token)
                            f.write("XSS REFLECTION CONTEXT:\n")
                            f.write(context + "\n")
                        except Exception:
                            f.write("XSS REFLECTION: [Binary response - cannot show context]\n")
                
                f.write("\n")
            
            result_text = "[" + timestamp + "] XSS in '" + param_name + "' at " + str(request_info.getUrl()) + "\n"
            self.results_area.append(result_text)
            print("XSS vulnerability found in parameter: " + param_name)
            
        except Exception as e:
            print("XSS log error: " + str(e))
    
    def log_sqli_vuln(self, messageInfo, param_name, quote, error_response, success_response, test_value1, test_value2):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            
            with open(self.vuln_log_path, 'a') as f:
                f.write("=" * 80 + "\n")
                f.write("SQL INJECTION VULNERABILITY DETECTED\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("Parameter: " + param_name + "\n")
                f.write("Quote Used: " + quote + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("-" * 80 + "\n")
                
                if error_response and error_response.getResponse():
                    error_info = self.helpers.analyzeResponse(error_response.getResponse())
                    f.write("ERROR RESPONSE (with " + test_value1 + "):\n")
                    f.write("Status Code: " + str(error_info.getStatusCode()) + "\n")
                    
                    try:
                        body_offset = error_info.getBodyOffset()
                        response_bytes = error_response.getResponse()
                        if body_offset < len(response_bytes):
                            body = self.helpers.bytesToString(response_bytes[body_offset:])
                            error_context = self.get_sqli_error_context(body)
                            if error_context:
                                f.write("Error Context:\n" + error_context + "\n")
                    except Exception:
                        f.write("Error Context: [Could not extract error details]\n")
                
                if success_response and success_response.getResponse():
                    success_info = self.helpers.analyzeResponse(success_response.getResponse())
                    f.write("\nSUCCESS RESPONSE (with " + test_value2 + "):\n")
                    f.write("Status Code: " + str(success_info.getStatusCode()) + "\n")
                
                f.write("\n")
            
            result_text = "[" + timestamp + "] SQLi in '" + param_name + "' at " + str(request_info.getUrl()) + "\n"
            self.results_area.append(result_text)
            print("SQL Injection vulnerability found in parameter: " + param_name)
            
        except Exception as e:
            print("SQLi log error: " + str(e))
    
    def get_xss_context(self, response_body, search_term):
        try:
            lines = response_body.split('\n')
            context_lines = []
            
            for i, line in enumerate(lines):
                if search_term in line:
                    start = max(0, i - 5)
                    end = min(len(lines), i + 6)
                    
                    for j in range(start, end):
                        prefix = ">>> " if j == i else "    "
                        context_lines.append(prefix + "Line " + str(j+1) + ": " + lines[j])
                    
                    break
            
            return '\n'.join(context_lines) if context_lines else "Reflection found but context extraction failed"
            
        except Exception:
            return "Context extraction error"
    
    def get_sqli_error_context(self, response_body):
        try:
            sql_errors = ["sql", "mysql", "oracle", "postgresql", "sqlite", "syntax error", "unexpected token", "near '", "quoted string", "unterminated", "invalid query"]
            
            lines = response_body.lower().split('\n')
            error_lines = []
            
            for i, line in enumerate(lines):
                for error_pattern in sql_errors:
                    if error_pattern in line:
                        start = max(0, i - 2)
                        end = min(len(lines), i + 3)
                        
                        for j in range(start, end):
                            prefix = ">>> " if j == i else "    "
                            error_lines.append(prefix + lines[j].strip())
                        
                        return '\n'.join(error_lines)
            
            if len(response_body) > 0:
                preview_lines = response_body.split('\n')[:10]
                return '\n'.join(["    " + line.strip() for line in preview_lines if line.strip()])
            
            return "No error context found"
            
        except Exception:
            return "Error context extraction failed"
    
    def send_test_request(self, original_messageInfo, param_name, new_value, param_type):
        try:
            test_key = self.get_test_key(original_messageInfo, param_name, new_value)
            
            if test_key in self.request_cache:
                return self.request_cache[test_key]
            
            original_request = original_messageInfo.getRequest()
            new_param = self.helpers.buildParameter(param_name, new_value, param_type)
            modified_request = self.helpers.updateParameter(original_request, new_param)
            
            http_service = original_messageInfo.getHttpService()
            response = self.callbacks.makeHttpRequest(http_service, modified_request)
            
            self.request_cache[test_key] = response
            return response
            
        except Exception as e:
            print("Send request error: " + str(e))
            return None
    
    def is_error_response(self, messageInfo):
        try:
            if not messageInfo.getResponse():
                return True
            
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            status_code = response_info.getStatusCode()
            return status_code >= 400
        except Exception:
            return True
    
    def has_xss_reflection(self, messageInfo, token, payload):
        try:
            if not messageInfo.getResponse():
                return False
            
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            body_offset = response_info.getBodyOffset()
            response_bytes = messageInfo.getResponse()
            
            if body_offset < len(response_bytes):
                response_body = self.helpers.bytesToString(response_bytes[body_offset:])
                
                # Check for unencoded reflection of "asdf" part
                # XSS is only valid if the payload appears unencoded in response
                if token in response_body:
                    # Check if it's properly encoded (URL encoded or HTML encoded)
                    if self.is_properly_encoded(response_body, token):
                        return False  # Properly encoded = not vulnerable
                    else:
                        return True   # Unencoded reflection = potentially vulnerable
            
            return False
        except Exception:
            return False
    
    def is_properly_encoded(self, response_body, token):
        """Check if XSS payload is properly encoded in response"""  
        try:
            # Check for URL encoding patterns
            url_encoded_patterns = [
                "asdf%27",    # ' encoded as %27
                "asdf%22",    # " encoded as %22  
                "asdf%3e",    # > encoded as %3e
                "asdf%3E"     # > encoded as %3E (uppercase)
            ]
            
            # Check for HTML encoding patterns
            html_encoded_patterns = [
                "asdf&#39;",  # ' encoded as &#39;
                "asdf&#34;",  # " encoded as &#34;
                "asdf&gt;",   # > encoded as &gt;
                "asdf&quot;", # " encoded as &quot;
                "asdf&#x27;", # ' encoded as &#x27;
                "asdf&#x22;"  # " encoded as &#x22;
            ]
            
            response_lower = response_body.lower()
            
            # If we find encoded patterns, it's properly encoded
            for pattern in url_encoded_patterns + html_encoded_patterns:
                if pattern.lower() in response_lower:
                    return True
            
            # If we find the raw payload characters unencoded, it's vulnerable
            dangerous_raw = [token + "'", token + '"', token + ">"]
            for raw in dangerous_raw:
                if raw in response_body:
                    return False  # Unencoded = vulnerable
            
            # If "asdf" exists but special chars are not found, assume encoded
            return True
            
        except Exception:
            return True  # Default to safe (encoded) on error
    
    def get_status_code(self, messageInfo):
        try:
            if messageInfo.getResponse():
                response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
                return response_info.getStatusCode()
            return 0
        except Exception:
            return 0
    
    def get_cache_key(self, messageInfo):
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            return hashlib.md5((method + url).encode()).hexdigest()
        except Exception:
            return str(time.time())
    
    def get_test_key(self, messageInfo, param_name, param_value):
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = str(request_info.getUrl())
            key_string = url + param_name + param_value
            return hashlib.md5(key_string.encode()).hexdigest()
        except Exception:
            return str(time.time()) + param_name + param_value
    
    def getTabCaption(self):
        return "Security Tester"
    
    def getUiComponent(self):
        return self.main_panel
