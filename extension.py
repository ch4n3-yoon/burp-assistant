# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IParameter
from javax.swing import JPanel, JTextField, JCheckBox, JLabel, JButton, JTextArea, JScrollPane, JTabbedPane
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension
from java.awt.event import ActionListener
import threading
import datetime
import hashlib
import random
import string
import time
import re
import os


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def __init__(self):
        # --- Files/flags ---
        self.log_file_path = "burp_http_log.txt"
        self.vuln_log_path = "burp_vulnerabilities.txt"
        self.test_log_path = "burp_test_results.txt"
        self.artifacts_root = "vuln_artifacts"
        self.logging_enabled = True
        self.auto_test_enabled = True
        self.verbose_testing = True

        # --- Concurrency/caches ---
        self.log_lock = threading.Lock()
        self.fs_lock = threading.Lock()
        self.request_cache = {}   # (test_key) -> (response, modified_request_bytes)
        self.test_cache = {}      # (cache_key) -> last_test_time
        self.cache_expiry = 3600  # seconds
        self.test_count = 0

        # --- Static (MIME) skipping controls ---
        self.ignore_static_enabled = True
        self.static_cache = {}            # (cache_key) -> last_seen_time
        self.static_cache_expiry = 3600   # seconds

        # --- Cookie testing policy ---
        self.skip_cookie_xss = True
        self.sqli_cookie_exclude_regexes = [
            re.compile(r'^_ga$'),
            re.compile(r'^_ga_[A-Za-z0-9]+$'),
        ]
    
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
    
    # ------------ Core HTTP hook ------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self.callbacks.TOOL_PROXY:
            return

        # Keep local toggles synced with UI if needed
        self.logging_enabled = self.enable_logging_checkbox.isSelected() if hasattr(self, 'enable_logging_checkbox') else self.logging_enabled
        self.auto_test_enabled = self.auto_test_checkbox.isSelected() if hasattr(self, 'auto_test_checkbox') else self.auto_test_enabled
        self.verbose_testing = self.verbose_test_checkbox.isSelected() if hasattr(self, 'verbose_test_checkbox') else self.verbose_testing

        now = time.time()
        cache_key = self.get_cache_key(messageInfo)

        # If we already determined (recently) that this URL is static, skip early
        if self.ignore_static_enabled and cache_key in self.static_cache:
            if now - self.static_cache[cache_key] < self.static_cache_expiry:
                # Skip both logging and testing for this message
                return
            else:
                # Expired
                del self.static_cache[cache_key]

        if messageIsRequest:
            # Log only request here; testing will be decided after response (MIME-based)
            if self.logging_enabled:
                with self.log_lock:
                    try:
                        self.write_log_entry(toolFlag, messageIsRequest, messageInfo)
                    except Exception as e:
                        print("Log error: " + str(e))
            return  # Wait for the response

        # messageIsRequest == False (RESPONSE)
        # Decide static by MIME (Content-Type) from response
        if self.ignore_static_enabled and self.should_ignore_by_mime(messageInfo):
            # Memorize so future requests to same URL are skipped at request-time
            self.static_cache[cache_key] = now
            return  # Skip logging (response) and tests

        # Not static: log response and run tests
        if self.logging_enabled:
            with self.log_lock:
                try:
                    self.write_log_entry(toolFlag, messageIsRequest, messageInfo)
                except Exception as e:
                    print("Log error: " + str(e))

        if self.auto_test_enabled:
            try:
                self.perform_security_tests(messageInfo)
            except Exception as e:
                print("Test error: " + str(e))
    
    # ------------ Logging ------------
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

    # 기존 바이너리 판별은 유지 (로깅 바디 출력 판단용)
    def is_binary_content(self, content_type):
        binary_types = ["image/", "video/", "audio/", "application/pdf", "application/zip", "application/octet-stream", "font/"]
        return any(content_type.startswith(bt) for bt in binary_types)

    # 정적 리소스 판별: MIME 기반 (패스 여부 결정용)
    def is_static_mime(self, content_type):
        if not content_type or content_type == "unknown":
            return False
        # prefix 매칭
        if content_type.startswith(("image/", "video/", "audio/", "font/")):
            return True
        # exact 매칭
        static_exact = set([
            "text/css",
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "application/wasm",
            "application/pdf",
            "application/zip",
            "application/x-zip-compressed",
            "application/octet-stream",
        ])
        return content_type in static_exact

    def should_ignore_by_mime(self, messageInfo):
        """응답의 Content-Type이 정적(이미지/JS/CSS/폰트/바이너리 등)으로 보이면 True."""
        try:
            if not messageInfo or not messageInfo.getResponse():
                return False
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            headers = response_info.getHeaders()
            ctype = self.get_content_type(headers)
            return self.is_static_mime(ctype)
        except Exception:
            return False
    
    # ------------ Testing ------------
    def perform_security_tests(self, messageInfo):
        try:
            # 가드: 혹시라도 정적이면 중복 방지
            if self.should_ignore_by_mime(messageInfo):
                return

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

                # COOKIE → XSS 미검사, SQLi는 조건부
                if param.getType() == IParameter.PARAM_COOKIE:
                    if self.verbose_testing:
                        self.log_test_result("XSS", param.getName(), "SKIPPED - Cookie parameter")

                    if self.is_tracking_cookie_for_sqli_exclusion(param.getName()):
                        if self.verbose_testing:
                            self.log_test_result("SQLi", param.getName(), "SKIPPED - Tracking cookie")
                    else:
                        self.test_sqli(messageInfo, param)

                else:
                    # 일반 파라미터: 둘 다 검사
                    self.test_sqli(messageInfo, param)
                    self.test_xss(messageInfo, param)

                self.update_status()
                
        except Exception as e:
            print("Security test error: " + str(e))

    def is_tracking_cookie_for_sqli_exclusion(self, cookie_name):
        try:
            name = cookie_name or ""
            for rgx in self.sqli_cookie_exclude_regexes:
                if rgx.match(name):
                    return True
            return False
        except Exception:
            return False
    
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

            clean_value = param_value.replace("'", "").replace('"', "")
            sqli_found = False
            
            for quote in ["'", '"']:
                # Step 1: 구문 깨뜨리기
                test_value1 = clean_value + quote
                resp1, req1_bytes = self.send_test_request(messageInfo, param_name, test_value1, param_type)
                
                if resp1:
                    status1 = self.get_status_code(resp1)
                    is_error1 = self.is_error_response(resp1)
                    
                    if self.verbose_testing:
                        self.log_test_detail("SQLi Step 1", param_name, quote, test_value1, status1, is_error1)
                    
                    if is_error1:
                        # Step 2: "복구" 시도
                        test_value2 = clean_value + quote + quote
                        resp2, req2_bytes = self.send_test_request(messageInfo, param_name, test_value2, param_type)
                        
                        if resp2:
                            status2 = self.get_status_code(resp2)
                            is_error2 = self.is_error_response(resp2)
                            
                            if self.verbose_testing:
                                self.log_test_detail("SQLi Step 2", param_name, quote + quote, test_value2, status2, is_error2)
                            
                            if not is_error2:
                                sqli_found = True
                                # 아티팩트 저장
                                self.save_sqli_artifacts(
                                    messageInfo,
                                    param_name,
                                    quote,
                                    test_value1, req1_bytes, resp1,
                                    test_value2, req2_bytes, resp2
                                )
                                # 텍스트 로그도 유지
                                self.log_sqli_vuln(messageInfo, param_name, quote, resp1, resp2, test_value1, test_value2)
                                break  # 이 파라미터에 대해 SQLi 발견 시 중단
            
            if self.verbose_testing and not sqli_found:
                self.log_test_result("SQLi", param_name, "SAFE - No SQL injection detected")
                        
        except Exception as e:
            print("SQLi test error: " + str(e))
    
    def test_xss(self, messageInfo, param):
        try:
            if param.getType() == IParameter.PARAM_COOKIE:
                if self.verbose_testing:
                    self.log_test_result("XSS", param.getName(), "SKIPPED - Cookie parameter")
                return

            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            clean_value = param_value.replace("'", "").replace('"', "").replace(">", "")

            token = self._rand_token(8)
            xss_payload = token + "'\">"
            test_value = clean_value + xss_payload
            
            resp, req_bytes = self.send_test_request(messageInfo, param_name, test_value, param_type)
            
            if resp:
                status = self.get_status_code(resp)
                has_reflection = self.has_xss_reflection(resp, token, xss_payload)
                
                if self.verbose_testing:
                    self.log_test_detail("XSS Test", param_name, xss_payload, test_value, status, has_reflection)
                
                if has_reflection:
                    # 아티팩트 저장
                    self.save_xss_artifacts(messageInfo, param_name, token, xss_payload, test_value, req_bytes, resp)
                    # 텍스트 로그도 유지
                    self.log_xss_vuln(messageInfo, param_name, token, xss_payload, resp, test_value)
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
    
    # -------- Artifact persistence (NEW) --------
    def sanitize_for_path(self, s):
        try:
            # Windows/Unix 공통적으로 문제되는 문자 제거
            return re.sub(r'[^A-Za-z0-9._\-@+=]', '_', s or '')
        except Exception:
            return "unknown"

    def ensure_dir(self, path):
        with self.fs_lock:
            if not os.path.isdir(path):
                try:
                    os.makedirs(path)
                except Exception as e:
                    print("Failed to create directory: %s (%s)" % (path, str(e)))

    def now_stamp(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def dump_bytes_to_text_or_bin(self, base_path_without_ext, data_bytes):
        """
        data_bytes를 문자열로 디코딩해 .txt 저장을 시도하고, 실패하면 .bin으로 저장.
        반환: 실제 저장된 파일 경로 (str)
        """
        try:
            # Burp helpers는 바이트를 문자열로 바꿔주나, 여기서는 원본 보존이 목적 → 우선 bytesToString 시도
            text = self.helpers.bytesToString(data_bytes)
            out_path = base_path_without_ext + ".txt"
            with open(out_path, "w") as f:
                f.write(text)
            return out_path
        except Exception:
            # 디코딩 실패 → 바이너리로 저장
            out_path = base_path_without_ext + ".bin"
            try:
                with open(out_path, "wb") as f:
                    # Jython 환경에서 bytes-like 처리
                    f.write(bytearray(data_bytes))
            except Exception as e:
                print("Failed to write binary: %s" % str(e))
            return out_path

    def save_meta_file(self, folder, meta_dict):
        try:
            meta_path = os.path.join(folder, "meta.txt")
            lines = []
            for k in sorted(meta_dict.keys()):
                v = meta_dict[k]
                lines.append("%s: %s" % (k, v))
            with open(meta_path, "w") as f:
                f.write("\n".join(lines) + "\n")
            return meta_path
        except Exception as e:
            print("Failed to write meta: %s" % str(e))
            return None

    def get_resp_bytes(self, resp_msg):
        try:
            return resp_msg.getResponse()
        except Exception:
            return None

    def save_xss_artifacts(self, original_messageInfo, param_name, token, payload, test_value, req_bytes, resp_msg):
        try:
            host = self.sanitize_for_path(original_messageInfo.getHttpService().getHost())
            url = str(self.helpers.analyzeRequest(original_messageInfo).getUrl())
            url_safe = self.sanitize_for_path(url)[:120]
            param_safe = self.sanitize_for_path(param_name)
            stamp = self.now_stamp()
            rid = self._rand_token(6)

            base_dir = os.path.join(self.artifacts_root, host)
            self.ensure_dir(base_dir)

            finding_dir_name = "%s__XSS__%s__%s" % (stamp, param_safe, rid)
            finding_dir = os.path.join(base_dir, finding_dir_name)
            self.ensure_dir(finding_dir)

            # 메타정보 저장
            meta = {
                "Type": "XSS",
                "Host": host,
                "URL": url,
                "Param": param_name,
                "Token": token,
                "Payload": payload,
                "TestValue": test_value,
                "DetectedAt": stamp,
            }
            self.save_meta_file(finding_dir, meta)

            # 요청/응답 원문 저장
            if req_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "request"), req_bytes)

            resp_bytes = self.get_resp_bytes(resp_msg)
            if resp_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "response"), resp_bytes)

            # 결과창에 경로 안내
            self.results_area.append("Artifacts saved: %s\n" % finding_dir)
        except Exception as e:
            print("save_xss_artifacts error: %s" % str(e))

    def save_sqli_artifacts(self, original_messageInfo, param_name, quote, test_value1, req1_bytes, resp1_msg, test_value2, req2_bytes, resp2_msg):
        try:
            host = self.sanitize_for_path(original_messageInfo.getHttpService().getHost())
            url = str(self.helpers.analyzeRequest(original_messageInfo).getUrl())
            url_safe = self.sanitize_for_path(url)[:120]
            param_safe = self.sanitize_for_path(param_name)
            stamp = self.now_stamp()
            rid = self._rand_token(6)

            base_dir = os.path.join(self.artifacts_root, host)
            self.ensure_dir(base_dir)

            finding_dir_name = "%s__SQLi__%s__%s" % (stamp, param_safe, rid)
            finding_dir = os.path.join(base_dir, finding_dir_name)
            self.ensure_dir(finding_dir)

            meta = {
                "Type": "SQLi(two-step heuristic)",
                "Host": host,
                "URL": url,
                "Param": param_name,
                "QuoteUsed": quote,
                "Step1_TestValue": test_value1,
                "Step2_TestValue": test_value2,
                "DetectedAt": stamp,
            }
            self.save_meta_file(finding_dir, meta)

            # Step 1 (에러 유도)
            if req1_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "request_error"), req1_bytes)
            resp1_bytes = self.get_resp_bytes(resp1_msg)
            if resp1_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "response_error"), resp1_bytes)

            # Step 2 (복구 성공)
            if req2_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "request_success"), req2_bytes)
            resp2_bytes = self.get_resp_bytes(resp2_msg)
            if resp2_bytes:
                self.dump_bytes_to_text_or_bin(os.path.join(finding_dir, "response_success"), resp2_bytes)

            self.results_area.append("Artifacts saved: %s\n" % finding_dir)
        except Exception as e:
            print("save_sqli_artifacts error: %s" % str(e))

    # -------- Request/Response helpers --------
    def send_test_request(self, original_messageInfo, param_name, new_value, param_type):
        """
        변경: (responseMessage, modified_request_bytes) 튜플을 반환.
        캐시 히트 시에도 같은 튜플 반환.
        """
        try:
            test_key = self.get_test_key(original_messageInfo, param_name, new_value)
            
            if test_key in self.request_cache:
                return self.request_cache[test_key]
            
            original_request = original_messageInfo.getRequest()
            new_param = self.helpers.buildParameter(param_name, new_value, param_type)
            modified_request = self.helpers.updateParameter(original_request, new_param)
            
            http_service = original_messageInfo.getHttpService()
            response = self.callbacks.makeHttpRequest(http_service, modified_request)
            
            result = (response, modified_request)
            self.request_cache[test_key] = result
            return result
            
        except Exception as e:
            print("Send request error: " + str(e))
            return (None, None)
    
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
                
                # 토큰이 그대로 반사되었는지 확인 (HTML/URL 엔코딩 여부 고려)
                if token in response_body:
                    if self.is_properly_encoded(response_body, token):
                        return False  # 적절히 인코딩 → 취약 아님
                    else:
                        return True   # 인코딩 없이 반사 → 잠재적 취약
            return False
        except Exception:
            return False
    
    def is_properly_encoded(self, response_body, token):
        """XSS 토큰이 적절히 인코딩되어 있는지 확인 (토큰 기준으로 동작하도록 수정)"""
        try:
            # URL 인코딩 패턴
            url_encoded_patterns = [
                token + "%27",    # ' → %27
                token + "%22",    # " → %22
                token + "%3e",    # > → %3e
                token + "%3E",    # > → %3E
            ]
            # HTML 인코딩 패턴
            html_encoded_patterns = [
                token + "&#39;",   # ' → &#39;
                token + "&#34;",   # " → &#34;
                token + "&gt;",    # > → &gt;
                token + "&quot;",  # " → &quot;
                token + "&#x27;",  # ' → &#x27;
                token + "&#x22;",  # " → &#x22;
            ]
            lower_body = response_body.lower()
            lower_patterns = [p.lower() for p in url_encoded_patterns + html_encoded_patterns]
            for p in lower_patterns:
                if p in lower_body:
                    return True  # 인코딩되어 있음

            # 위험한 생(raw) 조합이 있으면 인코딩 안 된 것으로 판단
            dangerous_raw = [token + "'", token + '"', token + ">"]
            for raw in dangerous_raw:
                if raw in response_body:
                    return False  # 인코딩 안 됨 = 취약

            # 토큰이 존재하지만 위험 문자들이 보이지 않으면 인코딩된 것으로 간주
            return True
        except Exception:
            return True  # 보수적으로 안전하다고 판단
    
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
