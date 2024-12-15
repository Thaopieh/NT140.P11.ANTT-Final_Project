# NT140.P11.ANTT: PenHeal: An Agent-based LLM Framework for Automated Pentesting and Optimal Remediation

## Introduction

Remake implementation for the paper "PenHeal: An Agent-based LLM Framework for Automated Pentesting and Optimal Remediation".
We are Group 15 from University of Information Technology, and we are remaking this project for the course project NT140.P11.ANTT.

## Getting Started

1. Set up the target machine Metasploitable2:

   - Download Metasploitable2 from [here](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/). Obtain its IP address using `ifconfig`.
   - Set up the virtual machines using [VMware](https://www.vmware.com/products/workstation-player.html).

2. Set up the attack machine

   - Install [Kali Linux](https://www.kali.org/downloads/).
   - Set up the virtual machines using [VMware](https://www.vmware.com/products/workstation-player.html).

3. Install with:

   - `git clone https://github.com/Thaopieh/NT140.P11.ANTT-Final_Project.git`
   - `cd NT140.P11.ANTT-Final_Project`
   - `pip3 install -r requirements.txt`

4. Set up Gemini API

   - Create an account on [Google](https://ai.google.dev/) if you don't have one.
   - Get API_KEY on (https://aistudio.google.com/apikey).
   - Create .env variable: `API_KEY=<API_KEY>`

5. Run:
   - cd src
   - `python3 pentest_module.py`
   - When prompted to enter the target IP address, enter the IP address of the target machine.
   - `python3 remediation_module.py`
