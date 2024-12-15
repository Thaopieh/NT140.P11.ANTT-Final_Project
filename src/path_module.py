import pickle
from cvss import CVSS3
import json
import requests
from prompt_class import PromptStore
from colorama import Fore, Back, Style, init
init(autoreset=True)
class Path:
    def __init__(self, state_list,port=None, service=None, cve_id=None, vulnerability=None, cvss_score=None, severity=None, description=None, cvss_vector=None, advice_list=None):
        # Ensure that all attributes are properly set
        self.state_list = state_list
        self.port = port
        self.service = service
        self.cve_id = cve_id
        self.vulnerability = vulnerability
        self.cvss_score = cvss_score
        self.severity = severity
        self.description = description
        self.advice_list = advice_list if advice_list else []
        self.cost_list = []
        self.value_list = []
        self.results = [] 
        # Debugging line to check initialization
        print(f"Path object created with port: {self.port}")

    def __str__(self):
        return f"Port: {self.port}, Service: {self.service}, CVE ID: {self.cve_id}, Vulnerability: {self.vulnerability}, CVSS Score: {self.cvss_score}, Severity: {self.severity}, Description: {self.description}, Advice List: {self.advice_list}, Cost List: {self.cost_list}, Value List: {self.value_list}"

    def __repr__(self):
        return self.__str__()

                

        
    def get_cve_id(self):
        return self.cve_id

    def get_vuln_name(self):
        return self.vulnerability

    def print_all_advice(self):
        if not self.advice_list:
            print(Fore.RED + "No advice available.")
        else:
            print(Fore.GREEN + "Advice for the vulnerability: " + Fore.RED + self.vulnerability)
            for index, advice in enumerate(self.advice_list, start=1):
                print(Fore.LIGHTYELLOW_EX + f"{index}. " + Fore.BLUE + advice)
    def get_advice(self, advisor, advisor_session_id):
        # Tạo thông điệp yêu cầu lời khuyên
        info = (
            f"Description: {self.description}\n"
            f"Base Score: {self.cvss_score}\n"
            f"Here is the summary of the path used to exploit the vulnerability: {self.summary}\n"
            "Please provide remediation advice as a list, "
            "where each piece of advice is labeled as 'advice[number]'.\n"
            "Format example: [\"advice1\", \"advice2\", \"advice3\", ...]."
        )
        # Gửi yêu cầu và nhận dữ liệu trả về
        advice = advisor.send_message(info, advisor_session_id)
        
        # Xử lý và ghi lời khuyên vào danh sách
        self.append_advice(advice)
        return self.advice_list

    def append_advice(self, advice):
        # Đảm bảo 'advice_list' tồn tại
        if not hasattr(self, 'advice_list'):
            self.advice_list = []
        
        # Nếu dữ liệu trả về là một chuỗi, cố gắng phân tích thành danh sách
        if isinstance(advice, str):
            try:
                # Kiểm tra nếu advice trả về ở dạng Python list
                import ast
                parsed_advice = ast.literal_eval(advice)
                if isinstance(parsed_advice, list):
                    self.advice_list.extend(parsed_advice)
                else:
                    # Nếu không phải danh sách, thêm trực tiếp vào advice_list
                    self.advice_list.append(advice)
            except (ValueError, SyntaxError):
                # Nếu không thể phân tích, ghi trực tiếp
                self.advice_list.append(advice)
        elif isinstance(advice, list):
            # Nếu trả về sẵn là danh sách, thêm trực tiếp
            self.advice_list.extend(advice)
        else:
            # Trường hợp khác (dictionary hoặc object khác)
            self.advice_list.append(advice)
        
        return self.advice_list

    def get_cvss_score(self):
        return self.cvss_score

    def get_vul(self,extractor, session_id):
        prefix = "Please specify the vulnerability used in the path in one line (e.g., CVE-2021-1234 and the name of the backdoor used). \
        If the CVE ID is not available, please write CVE-NA. "
        vul = extractor.send_message(prefix + str(self), session_id)
        self.vulnerability = vul.split(":")[1].strip()
        return vul
    
    def summarize(self, extractor, extractor_id):
        # Implement the logic for summarizing the vulnerability
        return f"Vulnerability summary: {self.vulnerability} on port {self.port} with severity {self.severity}."

    def get_info(self, estimator, session_id):
        # Call the estimate_score method to get the CVSS score and send all relevant information
        res = self.estimate_score(estimator, session_id)
        return res

    def estimate_score(self, estimator, session_id):
        # Ensure that all vulnerability information is passed to the estimator
        vuln_data = {}
    
        if hasattr(self, 'port'):
            vuln_data["port"] = self.port
        if hasattr(self, 'service'):
            vuln_data["service"] = self.service
        if hasattr(self, 'cve_id'):
            vuln_data["cve_id"] = self.cve_id
        if hasattr(self, 'vulnerability'):
            vuln_data["vulnerability"] = self.vulnerability
        if hasattr(self, 'cvss_vector'):
            vuln_data["cvss_vector"] = self.cvss_vector
        if hasattr(self, 'severity'):
            vuln_data["severity"] = self.severity
        if hasattr(self, 'description'):
            vuln_data["description"] = self.description
        vuln_data_str = (
        f"Port: {vuln_data.get('port', 'N/A')}\n"
        f"Service: {vuln_data.get('service', 'N/A')}\n"
        f"CVE ID: {vuln_data.get('cve_id', 'N/A')}\n"
        f"Vulnerability: {vuln_data.get('vulnerability', 'N/A')}\n"
        f"CVSS Vector: {vuln_data.get('cvss_vector', 'N/A')}\n"
        f"Severity: {vuln_data.get('severity', 'N/A')}\n"
        f"Description: {vuln_data.get('description', 'N/A')}")
        # Send the vulnerability data to the estimator
        res = estimator.send_message(vuln_data_str, session_id)
        res = res.replace("\n", "").strip()
        if self.cve_id == "CVE-NA":
            self.cvss_vector = res
            cvss = CVSS3(str(res))
            self.cvss_score = cvss.base_score
            self.summary()
        return res
    
  
    def fetch_cve_details(self):
        if self.cve_id == "CVE-NA":
            print("No CVE ID provided.")
            return None

        # Define the NVD API URL
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={self.cve_id}"
        
        try:
            # Make the API request
            response = requests.get(url)
            response.raise_for_status()
            cve_data = response.json()
            
            # Parse and store relevant details
            if cve_data.get("vulnerabilities"):
                vulnerability = cve_data["vulnerabilities"][0]
                cve_details = vulnerability["cve"]

                if not self.vulnerability:  # Nếu self.vulnerability chưa có giá trị
                    self.vulnerability = cve_details.get("descriptions", [{}])[0].get("value", "No description available")
                else:  # Nếu đã có giá trị, thêm mô tả mới vào cuối
                    new_vulnerability = cve_details.get("descriptions", [{}])[0].get("value", "No description available")
                    if new_vulnerability not in self.vulnerability:  # Tránh thêm trùng lặp
                        self.vulnerability += f" | {new_vulnerability}"
                self.cvss_vector = cve_details.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString")
                self.cvss_score = cve_details.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                self.severity = cve_details.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity")
                self.description = self.vulnerability
                self.summary()

            else:
                print(f"No data found for CVE ID: {self.cve_id}")

        except requests.RequestException as e:
            print(f"Error fetching CVE details: {e}")

          
    def summary(self):
        summary_parts = []
        if hasattr(self, 'port') and self.port is not None:
            summary_parts.append(f"Port: {self.port}")
        if hasattr(self, 'service') and self.service is not None:
            summary_parts.append(f"Service: {self.service}")
        if hasattr(self, 'cve_id') and self.cve_id is not None:
            summary_parts.append(f"CVE ID: {self.cve_id}")
        if hasattr(self, 'vulnerability') and self.vulnerability is not None:
            summary_parts.append(f"Vulnerability: {self.vulnerability}")
        if hasattr(self, 'cvss_score') and self.cvss_score is not None:
            summary_parts.append(f"CVSS: {self.cvss_score}")
        if hasattr(self, 'severity') and self.severity is not None:
            summary_parts.append(f"Severity: {self.severity}")
        if hasattr(self, 'description') and self.description is not None:
            summary_parts.append(f"Description: {self.description}")
        if hasattr(self, 'cvss_vector') and self.cvss_vector is not None:
            summary_parts.append(f"CVSS Vector: {self.cvss_vector}")
        colors = [Fore.BLUE, Fore.RED, Fore.YELLOW, Fore.MAGENTA]
    
    # Print each part on a new line with different colors
        for i, part in enumerate(summary_parts):
            color = colors[i % len(colors)]
            print(color + part )
        print("\n\n\n")

    def get_all_info(self):
        self.get_cve_id()
        self.get_info()
        self.summarize()
        self.get_advice()



    def summarize(self, summarizer, session_id):
        # summarize the path
        prefix = "Here is the path for you to summarize: "
        summary = summarizer.send_message(prefix + str(self), session_id)
        self.summary = summary
        return summary
    

    def get_cost(self, cost_evaluator, cost_evaluator_id):
        for advice in self.advice_list:
            content = f"Please evaluate the cost of the following advice: {advice}"
            content += f"\nThe background of the attack is: {self.summary}"
            cost = cost_evaluator.send_message(content, cost_evaluator_id)
            cost = cost.replace("\n", "")  # Remove newline characters
            self.cost_list.append(cost)
            print(Fore.BLUE + f"Evaluated cost for advice: {cost}")  # Log the cost

    def get_value(self, value_evaluator, value_evaluator_id):
        for advice in self.advice_list:
            content = f"Please evaluate the value of the following advice: {advice}"
            content += f"\nThe background of the attack is: {self.summary}"
            value = value_evaluator.send_message(content, value_evaluator_id)
            value = value.replace("\n", "")  # Remove newline characters
            self.value_list.append(value)
            print(Fore.GREEN + f"Evaluated value for advice: {value}")  # Log the value

        
    
