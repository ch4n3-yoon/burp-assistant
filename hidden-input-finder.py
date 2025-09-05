# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JLabel, JCheckBox
from java.io import PrintWriter
from java.net import URL

import re
import urllib
import json
import os
import time

EXTENSION_NAME = "Hidden Input & POST Param Reflector"

CACHE_FILE = "reflect_cache.json"   # JSON 캐시 파일
SENTINEL_PARAM = "__hifr"           # 자기요청 식별용 쿼리 파라미터
SENTINEL_HEADER = "X-HIFR"          # 자기요청 식별용 헤더
SENTINEL_VALUE = "1"


class BurpExtender(IBurpExtender, IHttpListener, ITab, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(EXTENSION_NAME)
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # state
        self.scan_results = []
        self.test_payload = "asdf'\">"
        self.cache = {}
        self._load_cache()

        # UI
        self._init_ui()
        callbacks.addSuiteTab(self)

        # HTTP listener
        callbacks.registerHttpListener(self)

        self._stdout.println("Hidden Input & POST Param Reflector loaded successfully!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Response만 처리
        if messageIsRequest:
            return
        if not self._auto_scan_checkbox.isSelected():
            return

        try:
            # 자기 자신이 만든 테스트 요청은 스킵(헤더, 쿼리 둘 다)
            req = messageInfo.getRequest()
            if not req:
                return
            req_info = self._helpers.analyzeRequest(messageInfo)
            for h in req_info.getHeaders():
                if h.lower().startswith((SENTINEL_HEADER + ":").lower()):
                    return

            url = str(messageInfo.getUrl())
            if self._has_sentinel_param(url):
                return

            self._scan_for_reflection(messageInfo)

        except Exception as e:
            self._stderr.println("Error in processHttpMessage: " + str(e))

    def getTabCaption(self):
        return EXTENSION_NAME[0:10] + "..."

    def getUiComponent(self):
        return self._panel

    def actionPerformed(self, event):
        cmd = event.getActionCommand()
        if cmd == "manual_scan":
            selected = self._callbacks.getSelectedMessages()
            if selected:
                for item in selected:
                    self._scan_for_reflection(item)
        elif cmd == "clear":
            self._results_area.setText("")
            self.scan_results = []
        elif cmd == "clear_cache":
            self.cache = {}
            self._save_cache()
            self._log_result("[CACHE] Cleared reflect_cache.json")

    def _init_ui(self):
        self._panel = JPanel(GridBagLayout())
        gc = GridBagConstraints()
        gc.gridx = 0
        gc.gridy = 0
        gc.gridwidth = 2
        gc.fill = GridBagConstraints.HORIZONTAL
        gc.insets = Insets(10, 10, 10, 10)

        title_label = JLabel("Hidden Input & POST Param Reflector")
        title_label.setFont(title_label.getFont().deriveFont(16.0))
        self._panel.add(title_label, gc)

        gc.gridy = 1
        gc.gridwidth = 1
        self._auto_scan_checkbox = JCheckBox("Auto Scan on Response", True)
        self._panel.add(self._auto_scan_checkbox, gc)

        gc.gridx = 1
        self._test_post_params_checkbox = JCheckBox("Test POST Parameters", True)
        self._panel.add(self._test_post_params_checkbox, gc)

        gc.gridx = 0
        gc.gridy = 2
        self._skip_cached_checkbox = JCheckBox("Skip Cached Tests", True)
        self._panel.add(self._skip_cached_checkbox, gc)

        gc.gridx = 1
        clear_cache_btn = JButton("Clear Cache")
        clear_cache_btn.addActionListener(self)
        clear_cache_btn.setActionCommand("clear_cache")
        self._panel.add(clear_cache_btn, gc)

        gc.gridx = 0
        gc.gridy = 3
        gc.gridwidth = 2
        scan_button = JButton("Manual Scan Selected Request")
        scan_button.addActionListener(self)
        scan_button.setActionCommand("manual_scan")
        self._panel.add(scan_button, gc)

        gc.gridy = 4
        gc.fill = GridBagConstraints.BOTH
        gc.weightx = 1.0
        gc.weighty = 1.0
        gc.insets = Insets(10, 10, 10, 10)
        self._results_area = JTextArea(20, 80)
        self._results_area.setEditable(False)
        self._panel.add(JScrollPane(self._results_area), gc)

        gc.gridy = 5
        gc.fill = GridBagConstraints.HORIZONTAL
        gc.weighty = 0
        clear_button = JButton("Clear Results")
        clear_button.addActionListener(self)
        clear_button.setActionCommand("clear")
        self._panel.add(clear_button, gc)

    def _scan_for_reflection(self, message_info):
        try:
            response = message_info.getResponse()
            request = message_info.getRequest()
            if not response or not request:
                return

            resp_info = self._helpers.analyzeResponse(response)
            body_offset = resp_info.getBodyOffset()
            resp_body = self._helpers.bytesToString(response[body_offset:])

            url = str(message_info.getUrl())
            self._log_result("=" * 80)
            self._log_result("URL: " + url)

            # 1) Hidden inputs
            hidden_inputs = self._find_hidden_inputs(resp_body)
            if hidden_inputs:
                self._log_result("\n[HIDDEN INPUTS FOUND]")
                self._log_result("Found {} hidden input(s):".format(len(hidden_inputs)))
                for inp in hidden_inputs:
                    self._log_result("  - Name: '{}', Value: '{}'".format(
                        inp['name'], inp['value'][:100]))
                self._test_hidden_input_reflection(message_info, hidden_inputs)

            # 2) POST params -> test as GET
            if self._test_post_params_checkbox.isSelected():
                post_params = self._extract_post_parameters(request)
                if post_params:
                    self._log_result("\n[POST PARAMETERS FOUND]")
                    self._log_result("Found {} POST parameter(s):".format(len(post_params)))
                    for p in post_params:
                        self._log_result("  - Name: '{}', Value: '{}'".format(p['name'], p['value'][:100]))
                    self._test_post_params_as_get(message_info, post_params)

        except Exception as e:
            self._stderr.println("Error in _scan_for_reflection: " + str(e))

    def _find_hidden_inputs(self, html_content):
        hidden_inputs = []
        patterns = [
            r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>',
            r'<input[^>]*type\s*=\s*hidden[^>]*>'
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, html_content, re.IGNORECASE):
                tag = m.group(0)
                name_m = re.search(r'name\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if not name_m:
                    name_m = re.search(r'name\s*=\s*([^\s>]*)', tag, re.IGNORECASE)
                value_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if not value_m:
                    value_m = re.search(r'value\s*=\s*([^\s>]*)', tag, re.IGNORECASE)
                if name_m:
                    hidden_inputs.append({
                        'name': name_m.group(1),
                        'value': value_m.group(1) if value_m else "",
                        'full_tag': tag
                    })
        return hidden_inputs

    def _extract_post_parameters(self, request_bytes):
        try:
            req_info = self._helpers.analyzeRequest(request_bytes)
            if req_info.getMethod() != "POST":
                return []

            content_type = ""
            for h in req_info.getHeaders():
                if h.lower().startswith("content-type:"):
                    content_type = h.lower()
                    break
            if "application/x-www-form-urlencoded" not in content_type:
                return []

            body_offset = req_info.getBodyOffset()
            body = self._helpers.bytesToString(request_bytes[body_offset:])
            params = []
            if body:
                for pair in body.split('&'):
                    if '=' in pair:
                        name, value = pair.split('=', 1)
                        params.append({
                            'name': urllib.unquote_plus(name),
                            'value': urllib.unquote_plus(value)
                        })
            return params
        except Exception as e:
            self._stderr.println("Error in _extract_post_parameters: " + str(e))
            return []

    def _test_hidden_input_reflection(self, original_message, hidden_inputs):
        try:
            base_url = str(original_message.getUrl())
            self._log_result("\n[HIDDEN INPUT REFLECTION TEST]")

            for inp in hidden_inputs:
                name = inp['name']
                orig = inp['value']
                test_value = orig + self.test_payload

                method = "GET"
                key = self._cache_key(method, base_url, name, test_value)
                if self._skip_cached_checkbox.isSelected() and key in self.cache:
                    entry = self.cache[key]
                    self._log_result("  [CACHE HIT/SKIP] {} param='{}' vuln={} tested_at={}".format(
                        method, name, entry.get("vulnerable"), entry.get("created_at")))
                    continue

                self._log_result("\nTesting hidden input: '{}'".format(name))
                self._log_result("  Original value: '{}'".format(orig))
                self._log_result("  Test value: '{}'".format(test_value))

                test_url = self._build_test_url_replace_param(
                    base_url, name, test_value, add_sentinel=True
                )

                try:
                    req_bytes = self._helpers.buildHttpRequest(URL(test_url))
                    req_info = self._helpers.analyzeRequest(req_bytes)
                    headers = list(req_info.getHeaders())
                    headers.append(SENTINEL_HEADER + ": " + SENTINEL_VALUE)
                    new_req = self._helpers.buildHttpMessage(headers, None)

                    test_resp = self._callbacks.makeHttpRequest(original_message.getHttpService(), new_req)
                    vulnerable = False

                    if test_resp and test_resp.getResponse():
                        resp_body = self._helpers.bytesToString(test_resp.getResponse())
                        if self._check_reflection(resp_body, self.test_payload):
                            vulnerable = True
                            self._log_result("  [REFLECTED] Payload found in response!")
                            self._log_result("  Test URL: {}".format(test_url))
                            ctx = self._get_reflection_context(resp_body, self.test_payload)
                            if ctx:
                                self._log_result("  Context: {}".format(ctx))
                        else:
                            self._log_result("  [NOT REFLECTED] Payload not found in response")

                    self._write_cache_entry(key, method, base_url, name, test_value, vulnerable)

                except Exception as e:
                    self._log_result("  Error testing: {}".format(str(e)))

        except Exception as e:
            self._stderr.println("Error in _test_hidden_input_reflection: " + str(e))

    def _test_post_params_as_get(self, original_message, post_params):
        try:
            full = str(original_message.getUrl())
            base_no_query = full.split('?', 1)[0]
            self._log_result("\n[POST PARAMETERS AS GET TEST]")

            for p in post_params:
                name = p['name']
                orig = p['value']
                test_value = orig + self.test_payload

                method = "GET"
                key = self._cache_key(method, base_no_query, name, test_value)
                if self._skip_cached_checkbox.isSelected() and key in self.cache:
                    entry = self.cache[key]
                    self._log_result("  [CACHE HIT/SKIP] {} param='{}' vuln={} tested_at={}".format(
                        method, name, entry.get("vulnerable"), entry.get("created_at")))
                    continue

                self._log_result("\nTesting POST param as GET: '{}'".format(name))
                self._log_result("  Original value: '{}'".format(orig))
                self._log_result("  Test value: '{}'".format(test_value))

                test_url = self._build_test_url_replace_param(
                    base_no_query, name, test_value, add_sentinel=True
                )

                try:
                    req_bytes = self._helpers.buildHttpRequest(URL(test_url))
                    req_info = self._helpers.analyzeRequest(req_bytes)
                    headers = list(req_info.getHeaders())
                    headers.append(SENTINEL_HEADER + ": " + SENTINEL_VALUE)
                    new_req = self._helpers.buildHttpMessage(headers, None)

                    test_resp = self._callbacks.makeHttpRequest(original_message.getHttpService(), new_req)
                    vulnerable = False

                    if test_resp and test_resp.getResponse():
                        resp_body = self._helpers.bytesToString(test_resp.getResponse())
                        if self._check_reflection(resp_body, self.test_payload):
                            vulnerable = True
                            self._log_result("  [REFLECTED] POST param works as GET!")
                            self._log_result("  Test URL: {}".format(test_url))
                            ctx = self._get_reflection_context(resp_body, self.test_payload)
                            if ctx:
                                self._log_result("  Context: {}".format(ctx))
                        else:
                            self._log_result("  [NOT REFLECTED] POST param doesn't work as GET")

                    self._write_cache_entry(key, method, base_no_query, name, test_value, vulnerable)

                except Exception as e:
                    self._log_result("  Error testing: {}".format(str(e)))

        except Exception as e:
            self._stderr.println("Error in _test_post_params_as_get: " + str(e))

    # ---- URL helpers ----
    def _build_test_url_replace_param(self, base_url, param_name, value, add_sentinel=True):
        """
        기존 쿼리를 파싱해 동일 파라미터는 덮어쓰고, 필요 시 센티널(__hifr=1) 추가.
        """
        if '?' in base_url:
            path, query = base_url.split('?', 1)
        else:
            path, query = base_url, ""

        pairs = []
        if query:
            for part in query.split('&'):
                if not part:
                    continue
                if '=' in part:
                    k, v = part.split('=', 1)
                else:
                    k, v = part, ""
                if urllib.unquote_plus(k) == param_name:
                    continue
                if urllib.unquote_plus(k) == SENTINEL_PARAM:
                    continue
                pairs.append((k, v))

        enc_name = urllib.quote(param_name, safe='')
        enc_val = urllib.quote(value, safe='')
        pairs.append((enc_name, enc_val))
        if add_sentinel:
            pairs.append((SENTINEL_PARAM, SENTINEL_VALUE))

        new_query = "&".join(["{}={}".format(k, v) if v != "" else k for (k, v) in pairs])
        return "{}?{}".format(path, new_query) if new_query else path

    def _has_sentinel_param(self, url_str):
        if '?' not in url_str:
            return False
        _, q = url_str.split('?', 1)
        for part in q.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
            else:
                k, v = part, ""
            if urllib.unquote_plus(k) == SENTINEL_PARAM and urllib.unquote_plus(v) == SENTINEL_VALUE:
                return True
        return False

    # ---- Reflection checks ----
    def _check_reflection(self, response_body, payload):
        if payload in response_body:
            return True
        enc = urllib.quote(payload, safe='')
        if enc in response_body:
            return True
        html_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;'),
            payload.replace('"', '&quot;').replace("'", '&#39;'),
        ]
        for v in html_variants:
            if v in response_body:
                return True
        return False

    def _get_reflection_context(self, response_body, payload):
        try:
            pos = response_body.find(payload)
            if pos == -1:
                enc = urllib.quote(payload, safe='')
                pos = response_body.find(enc)
                if pos == -1:
                    return "Context not found"
            start = max(0, pos - 50)
            end = min(len(response_body), pos + len(payload) + 50)
            ctx = response_body[start:end]
            return re.sub(r'\s+', ' ', ctx).strip()
        except Exception as e:
            return "Error extracting context: " + str(e)

    # ---- JSON cache ----
    def _cache_key(self, method, url_or_base, param, test_value):
        base = url_or_base.split('?', 1)[0]
        return "{}||{}||{}||{}".format(method.upper(), base, param, test_value)

    def _load_cache(self):
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, "r") as f:
                    self.cache = json.load(f)
            else:
                self.cache = {}
        except Exception as e:
            self.cache = {}
            try:
                os.remove(CACHE_FILE)
            except:
                pass
            self._stderr.println("Failed to load cache, reinitialized: " + str(e))

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._stderr.println("Failed to save cache: " + str(e))

    def _write_cache_entry(self, key, method, url_or_base, param, test_value, vulnerable):
        entry = {
            "method": method.upper(),
            "url": url_or_base.split('?', 1)[0],
            "parameter": param,
            "tested_value": test_value,
            "vulnerable": bool(vulnerable),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        self.cache[key] = entry
        self._save_cache()
        self._log_result("  [CACHE WRITE] {}".format(entry))

    # ---- logging ----
    def _log_result(self, message):
        current = self._results_area.getText()
        self._results_area.setText(current + message + "\n")
        self._results_area.setCaretPosition(self._results_area.getDocument().getLength())
        self._stdout.println(message)
