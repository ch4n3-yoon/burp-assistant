# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import Component, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener, ActionEvent
from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JLabel, JCheckBox
from java.io import PrintWriter
import re
import urllib
import json
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, ITab, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Extension 정보 설정
        callbacks.setExtensionName("Hidden Input & POST Param Reflector")
        
        # Output streams 설정
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # HTTP 리스너 등록
        callbacks.registerHttpListener(self)
        
        # UI 초기화
        self.initUI()
        
        # Tab 추가
        callbacks.addSuiteTab(self)
        
        # 결과 저장용
        self.scan_results = []
        
        # 테스트 페이로드
        self.test_payload = "asdf'\">"
        
        self._stdout.println("Hidden Input & POST Param Reflector loaded successfully!")
    
    def initUI(self):
        self._panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        
        # 제목
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(10, 10, 10, 10)
        title_label = JLabel("Hidden Input & POST Param Reflector")
        title_label.setFont(title_label.getFont().deriveFont(16.0))
        self._panel.add(title_label, constraints)
        
        # 설정 옵션들
        constraints.gridy = 1
        constraints.gridwidth = 1
        self._auto_scan_checkbox = JCheckBox("Auto Scan on Response", True)
        self._panel.add(self._auto_scan_checkbox, constraints)
        
        constraints.gridx = 1
        self._test_post_params_checkbox = JCheckBox("Test POST Parameters", True)
        self._panel.add(self._test_post_params_checkbox, constraints)
        
        # 수동 스캔 버튼
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 2
        scan_button = JButton("Manual Scan Selected Request")
        scan_button.addActionListener(self)
        scan_button.setActionCommand("manual_scan")
        self._panel.add(scan_button, constraints)
        
        # 결과 영역
        constraints.gridy = 3
        constraints.fill = GridBagConstraints.BOTH
        constraints.weightx = 1.0
        constraints.weighty = 1.0
        constraints.insets = Insets(10, 10, 10, 10)
        
        self._results_area = JTextArea(20, 80)
        self._results_area.setEditable(False)
        scroll_pane = JScrollPane(self._results_area)
        self._panel.add(scroll_pane, constraints)
        
        # 클리어 버튼
        constraints.gridy = 4
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weighty = 0
        clear_button = JButton("Clear Results")
        clear_button.addActionListener(self)
        clear_button.setActionCommand("clear")
        self._panel.add(clear_button, constraints)
    
    def getTabCaption(self):
        return "Reflector Scanner"
    
    def getUiComponent(self):
        return self._panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Response만 처리
        if not messageIsRequest and self._auto_scan_checkbox.isSelected():
            self.scanForReflection(messageInfo)
    
    def actionPerformed(self, event):
        command = event.getActionCommand()
        if command == "manual_scan":
            # 선택된 요청에 대해 수동 스캔
            selected_items = self._callbacks.getSelectedMessages()
            if selected_items:
                for item in selected_items:
                    self.scanForReflection(item)
        elif command == "clear":
            self._results_area.setText("")
            self.scan_results = []
    
    def scanForReflection(self, messageInfo):
        try:
            response = messageInfo.getResponse()
            request = messageInfo.getRequest()
            if not response or not request:
                return
            
            response_info = self._helpers.analyzeResponse(response)
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response[body_offset:])
            
            url = str(messageInfo.getUrl())
            self.logResult("="*80)
            self.logResult("URL: " + url)
            
            # 1. Hidden Input 스캔
            hidden_inputs = self.findHiddenInputs(response_body)
            if hidden_inputs:
                self.logResult("\n[HIDDEN INPUTS FOUND]")
                self.logResult("Found {} hidden input(s):".format(len(hidden_inputs)))
                
                for input_data in hidden_inputs:
                    self.logResult("  - Name: '{}', Value: '{}'".format(
                        input_data['name'], input_data['value'][:100]))
                
                # Hidden input 반영 테스트
                self.testHiddenInputReflection(messageInfo, hidden_inputs)
            
            # 2. POST 파라미터 스캔 (옵션이 활성화된 경우)
            if self._test_post_params_checkbox.isSelected():
                post_params = self.extractPostParameters(request)
                if post_params:
                    self.logResult("\n[POST PARAMETERS FOUND]")
                    self.logResult("Found {} POST parameter(s):".format(len(post_params)))
                    
                    for param_data in post_params:
                        self.logResult("  - Name: '{}', Value: '{}'".format(
                            param_data['name'], param_data['value'][:100]))
                    
                    # POST 파라미터를 GET으로 테스트
                    self.testPostParamsAsGet(messageInfo, post_params)
                
        except Exception as e:
            self._stderr.println("Error in scanForReflection: " + str(e))
    
    def findHiddenInputs(self, html_content):
        """HTML에서 hidden input 필드 찾기"""
        hidden_inputs = []
        
        # 다양한 패턴으로 hidden input 매치
        patterns = [
            r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>',
            r'<input[^>]*type\s*=\s*hidden[^>]*>'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                input_tag = match.group(0)
                
                # name 속성 추출
                name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if not name_match:
                    name_match = re.search(r'name\s*=\s*([^\s>]*)', input_tag, re.IGNORECASE)
                
                # value 속성 추출
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if not value_match:
                    value_match = re.search(r'value\s*=\s*([^\s>]*)', input_tag, re.IGNORECASE)
                
                if name_match:
                    name = name_match.group(1)
                    value = value_match.group(1) if value_match else ""
                    
                    hidden_inputs.append({
                        'name': name,
                        'value': value,
                        'full_tag': input_tag
                    })
        
        return hidden_inputs
    
    def extractPostParameters(self, request):
        """POST 요청에서 파라미터 추출"""
        try:
            request_info = self._helpers.analyzeRequest(request)
            
            # POST 요청인지 확인
            method = request_info.getMethod()
            if method != "POST":
                return []
            
            # Content-Type 확인
            headers = request_info.getHeaders()
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.lower()
                    break
            
            # application/x-www-form-urlencoded만 처리
            if "application/x-www-form-urlencoded" not in content_type:
                return []
            
            # POST 바디에서 파라미터 추출
            body_offset = request_info.getBodyOffset()
            body = self._helpers.bytesToString(request[body_offset:])
            
            parameters = []
            if body:
                # URL 디코딩 후 파라미터 파싱
                param_pairs = body.split('&')
                for pair in param_pairs:
                    if '=' in pair:
                        name, value = pair.split('=', 1)
                        name = urllib.unquote_plus(name)
                        value = urllib.unquote_plus(value)
                        parameters.append({
                            'name': name,
                            'value': value
                        })
            
            return parameters
            
        except Exception as e:
            self._stderr.println("Error in extractPostParameters: " + str(e))
            return []
    
    def testHiddenInputReflection(self, original_message, hidden_inputs):
        """Hidden input 반영 테스트"""
        try:
            base_url = str(original_message.getUrl())
            self.logResult("\n[HIDDEN INPUT REFLECTION TEST]")
            
            for input_data in hidden_inputs:
                param_name = input_data['name']
                original_value = input_data['value']
                
                # 원래 값에 테스트 페이로드 추가
                test_value = original_value + self.test_payload
                
                self.logResult("\nTesting hidden input: '{}'".format(param_name))
                self.logResult("  Original value: '{}'".format(original_value))
                self.logResult("  Test value: '{}'".format(test_value))
                
                # GET 요청으로 테스트
                test_url = self.buildTestURL(base_url, param_name, test_value)
                
                try:
                    # 새로운 요청 생성
                    test_request = self._helpers.buildHttpRequest(URL(test_url))
                    test_response = self._callbacks.makeHttpRequest(
                        original_message.getHttpService(), test_request)
                    
                    if test_response and test_response.getResponse():
                        response_body = self._helpers.bytesToString(
                            test_response.getResponse())
                        
                        # 페이로드가 반영되었는지 확인
                        if self.checkReflection(response_body, self.test_payload):
                            self.logResult("  [REFLECTED] Payload found in response!")
                            self.logResult("  Test URL: {}".format(test_url))
                            
                            # 반영된 부분의 컨텍스트 표시
                            context = self.getReflectionContext(response_body, self.test_payload)
                            if context:
                                self.logResult("  Context: {}".format(context))
                        else:
                            self.logResult("  [NOT REFLECTED] Payload not found in response")
                            
                except Exception as e:
                    self.logResult("  Error testing: {}".format(str(e)))
                    
        except Exception as e:
            self._stderr.println("Error in testHiddenInputReflection: " + str(e))
    
    def testPostParamsAsGet(self, original_message, post_params):
        """POST 파라미터를 GET으로 테스트"""
        try:
            base_url = str(original_message.getUrl()).split('?')[0]  # 기존 쿼리 파라미터 제거
            self.logResult("\n[POST PARAMETERS AS GET TEST]")
            
            for param_data in post_params:
                param_name = param_data['name']
                original_value = param_data['value']
                
                # 원래 값에 테스트 페이로드 추가
                test_value = original_value + self.test_payload
                
                self.logResult("\nTesting POST param as GET: '{}'".format(param_name))
                self.logResult("  Original value: '{}'".format(original_value))
                self.logResult("  Test value: '{}'".format(test_value))
                
                # GET 요청으로 테스트
                test_url = self.buildTestURL(base_url, param_name, test_value)
                
                try:
                    # 새로운 요청 생성
                    test_request = self._helpers.buildHttpRequest(URL(test_url))
                    test_response = self._callbacks.makeHttpRequest(
                        original_message.getHttpService(), test_request)
                    
                    if test_response and test_response.getResponse():
                        response_body = self._helpers.bytesToString(
                            test_response.getResponse())
                        
                        # 페이로드가 반영되었는지 확인
                        if self.checkReflection(response_body, self.test_payload):
                            self.logResult("  [REFLECTED] POST param works as GET!")
                            self.logResult("  Test URL: {}".format(test_url))
                            
                            # 반영된 부분의 컨텍스트 표시
                            context = self.getReflectionContext(response_body, self.test_payload)
                            if context:
                                self.logResult("  Context: {}".format(context))
                        else:
                            self.logResult("  [NOT REFLECTED] POST param doesn't work as GET")
                            
                except Exception as e:
                    self.logResult("  Error testing: {}".format(str(e)))
                    
        except Exception as e:
            self._stderr.println("Error in testPostParamsAsGet: " + str(e))
    
    def buildTestURL(self, base_url, param_name, value):
        """테스트용 URL 생성"""
        separator = "&" if "?" in base_url else "?"
        encoded_value = urllib.quote(value, safe='')
        return "{}{}{}={}".format(base_url, separator, param_name, encoded_value)
    
    def checkReflection(self, response_body, payload):
        """페이로드 반영 여부 확인"""
        # 직접 반영 확인
        if payload in response_body:
            return True
        
        # URL 인코딩된 버전 확인
        encoded_payload = urllib.quote(payload, safe='')
        if encoded_payload in response_body:
            return True
        
        # HTML 엔티티 인코딩된 버전 확인 (부분적으로)
        html_encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;'),
            payload.replace('"', '&quot;').replace("'", '&#39;')
        ]
        
        for encoded in html_encoded_versions:
            if encoded in response_body:
                return True
        
        return False
    
    def getReflectionContext(self, response_body, payload):
        """반영 컨텍스트 추출"""
        try:
            payload_pos = response_body.find(payload)
            if payload_pos == -1:
                # 인코딩된 버전 찾기
                encoded_payload = urllib.quote(payload, safe='')
                payload_pos = response_body.find(encoded_payload)
                if payload_pos == -1:
                    return "Context not found"
            
            # 앞뒤 50자씩 추출
            start = max(0, payload_pos - 50)
            end = min(len(response_body), payload_pos + len(payload) + 50)
            context = response_body[start:end]
            
            # 줄바꿈 제거하고 공백 정리
            context = re.sub(r'\s+', ' ', context).strip()
            
            return context
            
        except Exception as e:
            return "Error extracting context: " + str(e)
    
    def logResult(self, message):
        """결과 로깅"""
        current_text = self._results_area.getText()
        self._results_area.setText(current_text + message + "\n")
        self._results_area.setCaretPosition(self._results_area.getDocument().getLength())
        self._stdout.println(message)
