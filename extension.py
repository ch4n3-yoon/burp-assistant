# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension
from java.awt.event import ActionListener
from javax.swing import JPanel, JTextField, JCheckBox, JLabel, JButton, JTextArea, JScrollPane, JTabbedPane
import datetime
import threading
import time
import hashlib

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
            
            # Create cache key based on URL path only (without query parameters)
            cache_key = self.get_path_cache_key(messageInfo)
            current_time = time.time()
            
            if cache_key in self.test_cache:
                if current_time - self.test_cache[cache_key] < self.cache_expiry:
                    if self.verbose_testing:
                        self.log_skip_reason("URL path already tested recently", "", str(request_info.getUrl()))
                    return
            
            self.test_cache[cache_key] = current_time
            
            # Test regular parameters
            for param in parameters:
                param_name = param.getName()
                param_value = param.getValue()
                param_type = param.getType()
                
                # Skip if parameter already looks like it has been tested (contains quotes)
                if "'" in param_value or '"' in param_value:
                    if self.verbose_testing:
                        self.log_skip_reason("Parameter already contains quotes", param_name, param_value)
                    continue
                
                self.test_count += 1
                self.log_test_attempt(messageInfo, param)
                
                # Test SQLi for all parameter types
                self.test_sqli(messageInfo, param)
                
                # Test XSS only for GET parameters (URL parameters)
                if param_type == 0:  # IParameter.PARAM_URL (GET parameters)
                    self.test_xss(messageInfo, param)
                elif self.verbose_testing:
                    self.log_skip_reason("XSS test skipped - not a GET parameter", param_name, "Type: " + str(param_type))
                
                self.update_status()
            
            # Test JSON body parameters if present
            self.test_json_body(messageInfo, request_info)
                
        except Exception as e:
            print("Security test error: " + str(e))
    
    def test_json_body(self, messageInfo, request_info):
        """Test JSON body parameters for SQLi"""
        try:
            # Check if request has JSON content type
            headers = request_info.getHeaders()
            is_json = False
            
            for header in headers:
                if header.lower().startswith("content-type:") and "application/json" in header.lower():
                    is_json = True
                    break
            
            if not is_json:
                return
            
            # Get request body
            body_offset = request_info.getBodyOffset()
            request_bytes = messageInfo.getRequest()
            
            if body_offset >= len(request_bytes):
                return
            
            try:
                body_string = self.helpers.bytesToString(request_bytes[body_offset:])
                if not body_string.strip():
                    return
                
                # Parse JSON and test string values
                self.parse_and_test_json(messageInfo, body_string, request_info)
                
            except Exception as e:
                if self.verbose_testing:
                    self.log_skip_reason("JSON parsing failed", "", str(e))
                
        except Exception as e:
            print("JSON body test error: " + str(e))
    
    def parse_and_test_json(self, messageInfo, json_string, request_info):
        """Parse JSON and test string values for SQLi"""
        try:
            import json
            json_data = json.loads(json_string)
            
            # Find all string values in JSON recursively
            string_params = []
            self.extract_json_strings(json_data, "", string_params)
            
            if not string_params:
                if self.verbose_testing:
                    with open(self.test_log_path, 'a') as f:
                        f.write("  JSON BODY: No string parameters found for testing\n\n")
                return
            
            # Test each string parameter
            for json_path, value in string_params:
                # Skip if value already contains quotes
                if "'" in value or '"' in value:
                    if self.verbose_testing:
                        self.log_skip_reason("JSON parameter already contains quotes", json_path, value)
                    continue
                
                self.test_count += 1
                self.log_json_test_attempt(messageInfo, json_path, value, json_string)
                self.test_json_sqli(messageInfo, request_info, json_string, json_path, value)
                self.update_status()
                
        except Exception as e:
            if self.verbose_testing:
                self.log_skip_reason("JSON parsing error", "", str(e))
    
    def extract_json_strings(self, obj, path, results):
        """Recursively extract string values from JSON object"""
        try:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = path + "." + key if path else key
                    self.extract_json_strings(value, new_path, results)
            elif isinstance(obj, list):
                for i, value in enumerate(obj):
                    new_path = path + "[" + str(i) + "]"
                    self.extract_json_strings(value, new_path, results)
            elif isinstance(obj, str) and len(obj.strip()) > 0:
                # Only test non-empty strings
                results.append((path, obj))
        except Exception:
            pass  # Skip problematic values
    
    def log_json_test_attempt(self, messageInfo, json_path, value, original_json):
        """Log JSON parameter test attempt"""
        if not self.verbose_testing:
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            
            with open(self.test_log_path, 'a') as f:
                f.write("-" * 60 + "\n")
                f.write("JSON TEST ATTEMPT #" + str(self.test_count) + "\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("JSON Path: " + json_path + " = " + value + "\n")
                f.write("Parameter Type: JSON/BODY\n")
                f.write("Original JSON: " + original_json[:200] + ("..." if len(original_json) > 200 else "") + "\n")
                f.write("\n")
            
        except Exception as e:
            print("JSON test log error: " + str(e))
    
    def test_json_sqli(self, messageInfo, request_info, original_json, json_path, value):
        """Test JSON parameter for SQL injection"""
        try:
            # Clean value
            clean_value = value.replace("'", "").replace('"', "")
            
            sqli_found = False
            endpoint_safe = False
            
            for quote in ["'", '"']:
                # Test 1: Add single quote
                test_value1 = clean_value + quote
                response1 = self.send_json_test_request(messageInfo, request_info, original_json, json_path, test_value1)
                
                if response1:
                    status1 = self.get_status_code(response1)
                    is_error1 = self.is_error_response(response1)
                    
                    if self.verbose_testing:
                        self.log_test_detail("JSON SQLi Step 1", json_path, quote, test_value1, status1, is_error1)
                    
                    # If single quote returns 200 OK, endpoint is likely safe
                    if status1 == 200 and not is_error1:
                        endpoint_safe = True
                        if self.verbose_testing:
                            self.log_test_result("JSON SQLi", json_path, "SAFE - Single quote returned 200 OK (endpoint not vulnerable)")
                        break
                    
                    if is_error1:
                        # Test 2: Add double quote to "fix" syntax
                        test_value2 = clean_value + quote + quote
                        response2 = self.send_json_test_request(messageInfo, request_info, original_json, json_path, test_value2)
                        
                        if response2:
                            status2 = self.get_status_code(response2)
                            is_error2 = self.is_error_response(response2)
                            
                            if self.verbose_testing:
                                self.log_test_detail("JSON SQLi Step 2", json_path, quote + quote, test_value2, status2, is_error2)
                            
                            if not is_error2:
                                sqli_found = True
                                self.log_json_sqli_vuln(messageInfo, json_path, quote, response1, response2, test_value1, test_value2, original_json)
                                break
            
            if self.verbose_testing and not sqli_found and not endpoint_safe:
                self.log_test_result("JSON SQLi", json_path, "SAFE - No SQL injection detected")
                        
        except Exception as e:
            print("JSON SQLi test error: " + str(e))
    
    def send_json_test_request(self, original_messageInfo, request_info, original_json, json_path, new_value):
        """Send modified JSON request"""
        try:
            import json
            
            # Parse original JSON
            json_data = json.loads(original_json)
            
            # Modify the specific path
            self.set_json_value(json_data, json_path, new_value)
            
            # Convert back to JSON string
            modified_json = json.dumps(json_data)
            
            # Create cache key for this specific test
            test_key = self.get_test_key(original_messageInfo, json_path, new_value)
            
            if test_key in self.request_cache:
                return self.request_cache[test_key]
            
            # Build new request with modified JSON
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            
            # Reconstruct request with new JSON body
            header_string = "\r\n".join(headers) + "\r\n\r\n"
            new_request_bytes = self.helpers.stringToBytes(header_string + modified_json)
            
            # Send request
            http_service = original_messageInfo.getHttpService()
            response = self.callbacks.makeHttpRequest(http_service, new_request_bytes)
            
            # Cache the response
            self.request_cache[test_key] = response
            return response
            
        except Exception as e:
            print("JSON request error: " + str(e))
            return None
    
    def set_json_value(self, obj, path, value):
        """Set value at specific JSON path"""
        try:
            if "." not in path and "[" not in path:
                # Simple key
                if isinstance(obj, dict):
                    obj[path] = value
                return
            
            # Complex path - split by dots and handle arrays
            parts = path.split(".")
            current = obj
            
            for i, part in enumerate(parts[:-1]):
                if "[" in part and "]" in part:
                    # Array access
                    key = part.split("[")[0]
                    index = int(part.split("[")[1].split("]")[0])
                    current = current[key][index]
                else:
                    current = current[part]
            
            # Set final value
            final_part = parts[-1]
            if "[" in final_part and "]" in final_part:
                key = final_part.split("[")[0]
                index = int(final_part.split("[")[1].split("]")[0])
                current[key][index] = value
            else:
                current[final_part] = value
                
        except Exception as e:
            print("JSON path set error: " + str(e))
    
    def log_json_sqli_vuln(self, messageInfo, json_path, quote, error_response, success_response, test_value1, test_value2, original_json):
        """Log JSON SQL injection vulnerability"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            
            with open(self.vuln_log_path, 'a') as f:
                f.write("=" * 80 + "\n")
                f.write("JSON SQL INJECTION VULNERABILITY DETECTED\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("JSON Parameter Path: " + json_path + "\n")
                f.write("Quote Used: " + quote + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("Original JSON: " + original_json[:500] + ("..." if len(original_json) > 500 else "") + "\n")
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
            
            result_text = "[" + timestamp + "] JSON SQLi in '" + json_path + "' at " + str(request_info.getUrl()) + "\n"
            self.results_area.append(result_text)
            print("JSON SQL Injection vulnerability found in parameter: " + json_path)
            
        except Exception as e:
            print("JSON SQLi log error: " + str(e))
    
    def get_path_cache_key(self, messageInfo):
        """Create cache key based on URL path only (without query parameters)"""
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            
            # Extract path from URL (remove query parameters)
            if '?' in url:
                base_url = url.split('?')[0]
            else:
                base_url = url
            
            cache_data = method + base_url
            return hashlib.md5(cache_data.encode()).hexdigest()
        except Exception:
            return str(time.time())
    
    def get_detailed_cache_key(self, messageInfo, parameters):
        """Create a cache key that includes URL and original parameter values (legacy function)"""
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            
            # Include original parameter values to avoid testing modified parameters
            param_string = ""
            for param in parameters:
                param_string += param.getName() + "=" + param.getValue() + "&"
            
            cache_data = method + url + param_string
            return hashlib.md5(cache_data.encode()).hexdigest()
        except Exception:
            return str(time.time())
    
    def log_skip_reason(self, reason, param_name, param_value):
        """Log why a parameter or URL was skipped"""
        try:
            with open(self.test_log_path, 'a') as f:
                if param_name:
                    f.write("  SKIPPED - " + param_name + ": " + reason + "\n")
                    f.write("    Parameter Value: " + param_value + "\n")
                else:
                    f.write("  SKIPPED - " + reason + "\n")
                    f.write("    URL: " + param_value + "\n")
                f.write("\n")
        except Exception as e:
            print("Skip log error: " + str(e))
    
    def log_test_attempt(self, messageInfo, param):
        if not self.verbose_testing:
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            request_info = self.helpers.analyzeRequest(messageInfo)
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            # Get parameter type name for better logging
            param_type_name = self.get_param_type_name(param_type)
            
            with open(self.test_log_path, 'a') as f:
                f.write("-" * 60 + "\n")
                f.write("TEST ATTEMPT #" + str(self.test_count) + "\n")
                f.write("Time: " + timestamp + "\n")
                f.write("Host: " + messageInfo.getHttpService().getHost() + "\n")
                f.write("URL: " + str(request_info.getUrl()) + "\n")
                f.write("Parameter: " + param_name + " = " + param_value + "\n")
                f.write("Parameter Type: " + param_type_name + " (" + str(param_type) + ")\n")
                f.write("\n")
            
        except Exception as e:
            print("Test log error: " + str(e))
    
    def get_param_type_name(self, param_type):
        """Convert parameter type number to readable name"""
        param_types = {
            0: "GET/URL",
            1: "POST/BODY", 
            2: "COOKIE",
            3: "XML",
            4: "XML_ATTR",
            5: "MULTIPART_ATTR",
            6: "JSON"
        }
        return param_types.get(param_type, "UNKNOWN")
    
    def test_sqli(self, messageInfo, param):
        try:
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            # Clean parameter value - remove any existing quotes for testing
            clean_value = param_value.replace("'", "").replace('"', "")
            
            sqli_found = False
            endpoint_safe = False
            
            for quote in ["'", '"']:
                # Test 1: Add single quote
                test_value1 = clean_value + quote
                response1 = self.send_test_request(messageInfo, param_name, test_value1, param_type)
                
                if response1:
                    status1 = self.get_status_code(response1)
                    is_error1 = self.is_error_response(response1)
                    
                    if self.verbose_testing:
                        self.log_test_detail("SQLi Step 1", param_name, quote, test_value1, status1, is_error1)
                    
                    # If single quote returns 200 OK, endpoint is likely safe
                    if status1 == 200 and not is_error1:
                        endpoint_safe = True
                        if self.verbose_testing:
                            self.log_test_result("SQLi", param_name, "SAFE - Single quote returned 200 OK (endpoint not vulnerable)")
                        break
                    
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
            
            if self.verbose_testing and not sqli_found and not endpoint_safe:
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
            
            xss_payload = "asdf'\">"
            test_value = clean_value + xss_payload
            
            response = self.send_test_request(messageInfo, param_name, test_value, param_type)
            
            if response:
                status = self.get_status_code(response)
                has_reflection = self.has_xss_reflection(response, xss_payload)
                
                if self.verbose_testing:
                    self.log_test_detail("XSS Test", param_name, xss_payload, test_value, status, has_reflection)
                
                if has_reflection:
                    self.log_xss_vuln(messageInfo, param_name, xss_payload, response, test_value)
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
    
    def log_xss_vuln(self, messageInfo, param_name, payload, response, test_value):
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
                            context = self.get_xss_context(body, "asdf")
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
    
    def has_xss_reflection(self, messageInfo, payload):
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
                if "asdf" in response_body:
                    # Check if it's properly encoded (URL encoded or HTML encoded)
                    if self.is_properly_encoded(response_body, payload):
                        return False  # Properly encoded = not vulnerable
                    else:
                        return True   # Unencoded reflection = potentially vulnerable
            
            return False
        except Exception:
            return False
    
    def is_properly_encoded(self, response_body, original_payload):
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
            dangerous_chars = ["asdf'", 'asdf"', "asdf>"]
            for char_combo in dangerous_chars:
                if char_combo in response_body:
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


