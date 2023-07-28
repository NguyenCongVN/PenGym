
# PenGym: Pentesting Training Framework for Reinforcement Learning Agents

PenGym is a framework for creating and managing realistic environments
used for the training of **Reinforcement Learning** (RL) agents for
penetration testing purposes. PenGym uses the same API with the
[Gymnasium](https://github.com/Farama-Foundation/Gymnasium) fork of
the OpenAI **Gym** library, thus making it possible to employ PenGym
with all the RL agents that follow those specifications. PenGym is
being developed by [Japan Advanced Institute of Science and
Technology](https://www.jaist.ac.jp/english/) (JAIST) in collaboration
with [KDDI Research, Inc.](https://www.kddi-research.jp/english)

_**NOTE:** PenGym was created and is intended only for research
activities. You should only use PenGym in your own local network
environment and at your own risk. Any other kind of use, in particular
with network environments that do not belong to you, may be considered
an attack and lead to your legal liability. PenGym implements several
penetration testing actions that may affect target hosts, namely
network scanning via nmap, and exploit and privilege escalation via
Metasploit. Consequently, PenGym should always be used with due care
in real network environments._

An overview of PenGym is shown in the figure below. The core component
is the **Action/State Module**, which: (i) converts the actions
generated by the RL agent into real actions that are executed in a
**Cyber Range** (an actual network environment used for cybersecurity
training purposes); (ii) interprets the outcome of the actions and
returns the state of the environment and the reward to the agent, so
that processing can continue. Another important component is the
module in charge of creating the cyber range, which is the [Cyber
Range Instantiation System](https://github.com/crond-jaist/cyris)
(**CyRIS**) previously developed at JAIST. CyRIS uses the descriptions
in the **RangeDB** database to create cyber ranges that were
specifically designed for RL agent training. Currently, CyRIS must be
executed manually to create the cyber range, but in the future this
process will be automated.

<div align=center><img src='images/pengym_overview.png'></div>


## Prerequisites

PenGym has several prerequisites that must be installed before using
it, as it will be explained next.

1. **NASim**: The Action/State module implementation in PenGym is
   based on extending the functionality of the [Network Attack
   Simulator](https://github.com/Jjschwartz/NetworkAttackSimulator)
   (NASim).  You can install NASim from the PyPi Python package index
   via the `pip3` command, which will also install all its
   dependencies, such as `gymnasium` itself:

   ```
   $ sudo pip3 install nasim
   ```

   Depending on your system, you may also need to install the
   `tkinter` Python3 interface to Tcl/Tk:

   ```
   sudo apt install python3-tk
   ```

2. **CyRIS**: In order to create cyber ranges, the cyber range
   instantiation system CyRIS is recommended. Follow the instructions
   on the [CyRIS page](https://github.com/crond-jaist/cyris) for this
   purpose. Alternatively, cyber ranges could also be created by any
   other means you are familiar with, but then you need to configure
   them yourself. Note that for the current version of PenGym, the
   operating system of VMs in the cyber range should be Ubuntu 20.04
   LTS. When using CyRIS, such VMs can be created by following the
   CyRIS User Guide, in particular the Appendix "Guest VM Base Image
   Preparation".

4. **Nmap**: The Action/State module implementation uses `nmap` for
   actions such as port and network scanning. To install `nmap` and
   the corresponding Python module `python-nmap` run the following:

   ```
   sudo apt install nmap
   sudo pip3 install python-nmap
   ```

5. **Metasploit**: The Action/State module implementation uses the
   Metasploit framework for actions such as Exploit. To install
   Metasploit follow the instructions on the corresponding [Metasploit
   page](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/).
   Then also install the corresponding Python module `pymetasploit3`:

   ```
   sudo pip3 install pymetasploit3
   ```

   Once Metasploit is installed, you should start the RPC daemon by
   running the command below (if you change the password or the msfrpc
   client port, you will also need to update the file
   `pengym/CONFIG.yaml`).

   ```
   msfrpcd -P my_password
   ```

## Setup

Once the prerequisite installation is complete, to set up the most
recent version of PenGym you only need to obtain its source code,
either from the most recent release or by using the `git clone`
command.

Currently, PenGym supports all the features of the `tiny` scenario
defined in NASim. However, PenGym uses the `pkexec` package for
privilege escalation instead of `tomcat`, hence the **pe_pkexec**
action is implemented instead of **pe_tomcat**.


## Quick Start

In order to see PenGym in action, you must first create the cyber
range, then run the included demo script. The example cyber range is
based on the `tiny` scenario in NASim, and is defined in the file
`cyris-pengym-tiny.yaml`; this file may need to be changed depending
on your CyRIS setup, so check it before proceeding. The example agent
is currently a deterministic agent that can reach the scenario goals
in 14 steps; its implementation and default action sequence are
included in the file `run.py`.

The two commands that must be run are as follows (we assume you are
located in the PenGym directory):

1. Run CyRIS by providing the path to the directory where it is
   installed:

   ```
   <PATH_TO_CYRIS>/main/cyris.py database/tiny/cyris-pengym-tiny.yaml <PATH_TO_CYRIS>/CONFIG
   ```

   If you modify the cyber range settings, such as the **range_id**
   value in the CyRIS scenario file, you also need to update the
   settings in the file `pengym/utilities.py`, in particular the IP
   addresses in **host_map** and bridge names in **bridge_map**.

2. Run the PenGym demo script with the configuration file as argument:

   ```
   python3 run.py ./pengym/CONFIG.yaml
   ```

   **NOTE:** You can use the option `-h` to find out more about the
   command-line arguments of the demo script. For example, enabling
   the NASIM simulation mode and disabling cyber range execution
   (options `-n -d`) may be useful if you want to quickly test an
   agent without creating a cyber range.

   The output of PenGym should be similar to that shown below.

   ```
   #########################################################################
   PenGym: Pentesting Training Framework for Reinforcement Learning Agents
   #########################################################################
   * Execution parameters:
     - Agent type: deterministic
     - PenGym cyber range execution enabled: True
     - NASim simulation execution enabled: False
   * Read configuration from './pengym/CONFIG.yaml'...
   * Initialize MSF RPC client...
   * Initialize Nmap Scanner...
   * Create environment using scenario 'tiny'...
     Successfully created environment using scenario 'tiny'
   * Execute pentesting using a DETERMINISTIC agent...
   - Step 1: OSScan: target=(1, 0), cost=1.00, prob=1.00, req_access=USER
     Host (1, 0) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 4.205273
   - Step 2: ServiceScan: target=(1, 0), cost=1.00, prob=1.00, req_access=USER
     Host (1, 0) Action 'service_scan' SUCCESS: services={'ssh': 1.0} Execution Time: 0.241904
   - Step 3: Exploit: target=(1, 0), cost=1.00, prob=0.80, req_access=USER, os=linux, service=ssh, access=1
     Host (1, 0) Action 'e_ssh' SUCCESS: access=USER services={'ssh': 1.0} os={'linux': 1.0} Execution Time: 1.054823
   - Step 4: SubnetScan: target=(1, 0), cost=1.00, prob=1.00, req_access=USER
     Host (1, 0) Action 'subnet_scan' SUCCESS: discovered={(1, 0): True, (2, 0): True, (3, 0): True} newly_discovered={(1, 0): False, (2, 0): True, (3, 0): True} Execution Time: 2.452376
   - Step 5: OSScan: target=(3, 0), cost=1.00, prob=1.00, req_access=USER
     Host (3, 0) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 4.179169
   - Step 6: ServiceScan: target=(3, 0), cost=1.00, prob=1.00, req_access=USER
     Host (3, 0) Action 'service_scan' SUCCESS: services={'ssh': 1.0} Execution Time: 0.285325
   - Step 7: Exploit: target=(3, 0), cost=1.00, prob=0.80, req_access=USER, os=linux, service=ssh, access=1
     Host (3, 0) Action 'e_ssh' SUCCESS: access=USER services={'ssh': 1.0} os={'linux': 1.0} Execution Time: 0.736583
   - Step 8: ProcessScan: target=(3, 0), cost=1.00, prob=1.00, req_access=USER
     Host (3, 0) Action 'process_scan' SUCCESS: processes={'tomcat': 1.0} access=USER Execution Time: 1.417039
   - Step 9: PrivilegeEscalation: target=(3, 0), cost=1.00, prob=1.00, req_access=USER, os=linux, process=tomcat, access=2
     Host (3, 0) Action 'pe_tomcat' SUCCESS: access=ROOT processes={'tomcat': 1.0} os={'linux': 1.0} Execution Time: 18.134254
   - Step 10: OSScan: target=(2, 0), cost=1.00, prob=1.00, req_access=USER
     Host (2, 0) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 6.818980
   - Step 11: ServiceScan: target=(2, 0), cost=1.00, prob=1.00, req_access=USER
     Host (2, 0) Action 'service_scan' SUCCESS: services={'ssh': 1.0} Execution Time: 0.651496
   - Step 12: Exploit: target=(2, 0), cost=1.00, prob=0.80, req_access=USER, os=linux, service=ssh, access=1
     Host (2, 0) Action 'e_ssh' SUCCESS: access=USER services={'ssh': 1.0} os={'linux': 1.0} Execution Time: 3.850929
   - Step 13: ProcessScan: target=(2, 0), cost=1.00, prob=1.00, req_access=USER
     Host (2, 0) Action 'process_scan' SUCCESS: processes={'tomcat': 1.0} access=USER Execution Time: 1.403138
   - Step 14: PrivilegeEscalation: target=(2, 0), cost=1.00, prob=1.00, req_access=USER, os=linux, process=tomcat, access=2
     Host (2, 0) Action 'pe_tomcat' SUCCESS: access=ROOT processes={'tomcat': 1.0} os={'linux': 1.0} Execution Time: 18.143280
   * NORMAL execution: 14 steps
   * Clean up MSF RPC client...
   ```
