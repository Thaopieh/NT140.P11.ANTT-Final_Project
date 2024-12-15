import requests
from cvss import CVSS3
class attackState:
    def __init__(self, attack_plan="", target="", prev_command="", prev_result="", 
                 successful_exploits=None):  # Add parameters
        self.attack_plan = attack_plan
        self.target = target
        self.prev_command = prev_command
        self.prev_result = prev_result
        self.successful_exploits = successful_exploits if successful_exploits is not None else []

    def __str__(self):
        return f"Attack Plan: {self.attack_plan}, Target: {self.target}, Command: {self.prev_command}, Result: {self.prev_result}, Successful Exploits: {self.successful_exploits}"


