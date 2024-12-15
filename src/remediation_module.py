import pickle
import os
import time
import json
from prompt_class import PromptStore
from gemini_api import LLMAPI, GeminiConfig
from rag import RAG_module
from path_module import Path
from dotenv import load_dotenv
from group_knapsack import group_knapsack_with_tracking
from colorama import Fore, Back, Style, init
init(autoreset=True)
class RemediationModule:
    def __init__(self, reasoning_model="gemini-1.5-pro", parsing_model="gemini-1.5-pro", instructor_dir="../docs", log_dir="../logs", api_key=os.getenv("API_KEY")):
        self.log_dir = log_dir 

        # Initialize API clients for different tasks
        self.advisor = LLMAPI(GeminiConfig(model=reasoning_model, api_key=api_key))
        self.estimator = LLMAPI(GeminiConfig(model=reasoning_model, api_key=api_key))
        self.extractor = LLMAPI(GeminiConfig(model=reasoning_model, api_key=api_key))
        self.cost_evaluator = LLMAPI(GeminiConfig(model=reasoning_model, api_key=api_key))
        self.value_evaluator = LLMAPI(GeminiConfig(model=reasoning_model, api_key=api_key))
        
        self.prompts = PromptStore()
        self.history = {"penheal": [], "console": [], "user": []}

        self.all_paths = []  # Initialize all_paths
        self.counterfactual_prompt = ""

        print("Remediation Module initializing")
        # Load the paths from the file
        log_path = os.path.join(self.log_dir, "raw.pkl")

        print(f"Loading paths from {log_path}")
       
        with open(log_path, "rb") as file:
            loaded_data = pickle.load(file)
            # Ensure that loaded_data is a list of Path objects
            self.all_paths = [Path(**data) if isinstance(data, dict) else data for data in loaded_data]
        print("Paths loaded successfully")
    def print_all_advise(self):
        if not self.all_paths:
            print("No paths available.")
        else:
            for path in self.all_paths:
                path.print_all_advice()    
    def initialize(self):
        self.estimator_session_id = self.estimator.send_new_message(self.prompts.estimator_prompt)[1]
        self.advisor_session_id = self.advisor.send_new_message(self.prompts.advisor_session_init)[1]
        self.extractor_id = self.extractor.send_new_message(self.prompts.extractor_prompt)[1] 

    def main(self):
        # Get the CVE id for each path and estimate scores if needed
        for path in self.all_paths:
            cve_id = path.get_cve_id()
            if cve_id=="CVE-NA":
                path.get_info(self.estimator, self.estimator_session_id)  # Estimate the score for the paths
            else:
                path.fetch_cve_details()
                time.sleep(1)  # Sleep for 1 second to avoid rate limiting
            
        for path in self.all_paths:
            advice = path.get_advice(self.advisor, self.advisor_session_id)
        
        log_path = os.path.join(self.log_dir, "advised.pkl")
        with open(log_path, "wb") as f:
            pickle.dump(self.all_paths, f)

        # Load the paths from the file
        with open(log_path, "rb") as f:
            self.all_paths = pickle.load(f)
        self.print_all_advise()
        # Sort the paths based on the base score, handling None values
        self.all_paths.sort(key=lambda x: x.cvss_score if x.cvss_score is not None else 0, reverse=True)
        print("Here is the advice for remediation in a decreasing order of severity: ")
        for path in self.all_paths:
            print(Fore.BLUE + path.summarize(self.extractor, self.extractor_id))

        # Ask if the user wants to set customized rubrics
        decision = input(Fore.RED + "Do you want to set customized rubrics for the remediation? (yes/no): ").strip().lower()
        if "y" in decision:
            self.cost_rubrics = input("Enter the cost rubrics: ")
            self.value_rubrics = input("Enter the value rubrics: ")
        else:
            self.cost_rubrics = self.prompts.default_cost_rubrics
            self.value_rubrics = self.prompts.default_value_rubrics

        # Get the budget for remediation
        self.budget = int(input(Fore.RED + "Enter the budget for the remediation (or press enter to set automatically): ").strip() or 4 * len(self.all_paths))

        # Send the rubrics to the evaluator APIs
        (_, self.cost_evaluator_id) = self.cost_evaluator.send_new_message(self.prompts.counterfactual_prompt + self.prompts.cost_evaluator_prompt + self.cost_rubrics )
        (_, self.value_evaluator_id) = self.value_evaluator.send_new_message(self.prompts.counterfactual_prompt +self.prompts.value_evaluator_prompt + self.value_rubrics)

        # Get the cost and value for each path
        for path in self.all_paths:
            print(Fore.RED + "Getting cost for path: " + path.get_vuln_name())
            path.get_cost(self.cost_evaluator, self.cost_evaluator_id)
            print(Fore.RED + "Getting value for path: " + path.get_vuln_name())
            path.get_value(self.value_evaluator, self.value_evaluator_id)
        log_path = os.path.join(self.log_dir, "evaluator.pkl")
        with open(log_path, "wb") as f:
            pickle.dump(self.all_paths, f)

        # Load the paths from the file
        with open(log_path, "rb") as f:
            self.all_paths = pickle.load(f)
        # Optimize the paths based on the cost and value using knapsack
        groups = []
        for path in self.all_paths:
            cost_value_pairs = []
            for i in range(len(path.cost_list)):
                try:
                    advice = path.advice_list[i]
                    cost = int(path.cost_list[i])
                    value = float(path.value_list[i])
                    cost_value_pairs.append((advice, cost, value))
                except ValueError:
                    print(f"Skipping invalid cost or value: cost={path.cost_list[i]}, value={path.value_list[i]}")
                    continue
            groups.append(cost_value_pairs)

        max_value, item_list = group_knapsack_with_tracking(groups, self.budget)
        print("The maximum value achievable is: " + str(max_value) + Fore.RED + " with the following remediation plan: ")
        
        colors = [Fore.BLUE, Fore.RED, Fore.YELLOW, Fore.MAGENTA]
        for i, advice in enumerate(item_list):
            color = colors[i % len(colors)]
            cost = groups[0][item_list.index(advice)][1]
            value = groups[0][item_list.index(advice)][2]
            print(color + advice + " with cost: " + str(cost) + " and value: " + str(value) + "\n")
        print("Remediation complete")
        
        return item_list


if __name__ == "__main__":
    remediation_module = RemediationModule(reasoning_model="gemini-1.5-pro", parsing_model="gemini-1.5-pro", log_dir="../logs")
    remediation_module.initialize()  # Call initialize method
    remediation_module.main()