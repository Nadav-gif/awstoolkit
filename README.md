# awstoolkit

AWS Toolkit (`awstoolkit`) is a Python-based utility designed to help you interact with AWS Identity and Access Management (IAM) policies. It provides tools for analyzing who can perform specific actions on your AWS resources, checking if a specific identity can perform an action, and comparing two policies to find their differences.

## Features

1. **`who-can`**: 
   - Provides a list of AWS identities (users, roles, groups) that are authorized to perform a given AWS action.
   - It also shows on which resources the action can be performed.

2. **`can-do`**: 
   - Checks if a specific AWS identity (user, role, group) can perform a particular AWS action on a resource.
   
3. **`policy-diff`**: 
   - Compares two AWS policies and returns the differences, helping you quickly spot changes or discrepancies between them.

## Installation

To install `awstoolkit`, clone the repository and install the required dependencies:

```bash
git clone https://github.com/your-repo/awstoolkit.git
cd awstoolkit
pip install -r requirements.txt
