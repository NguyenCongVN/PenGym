#############################################################################
# Run demo of PenGym functionality
#############################################################################

import time
import pengym
import numpy
import logging
import sys
import getopt
import pengym.utilities as utils
from pengym.storyboard import Storyboard

storyboard = Storyboard()

#############################################################################
# Constants
#############################################################################

# Action names/targets
SUBNET_SCAN = 'SubnetScan'
OS_SCAN = 'OSScan'
SERVICE_SCAN = 'ServiceScan'
EXPLOIT_SSH = 'Exploit_Ssh'
EXPLOIT_FTP = 'Exploit_Ftp'
EXPLOIT_SAMBA = 'Exploit_Samba'
EXPLOIT_SMTP = 'Exploit_Smtp'
EXPLOIT_HTTP = 'Exploit_Http'
PROCESS_SCAN = 'ProcessScan'
PRIVI_ESCA_TOMCAT = 'PrivilegeEscalation_Tomcat'
PRIVI_ESCA_PROFTPD = 'PrivilegeEscalation_Proftpd'
PRIVI_ESCA_CRON = 'PrivilegeEscalation_Cron'

ACTION_NAMES = {SUBNET_SCAN: "subnet_scan", OS_SCAN: "os_scan", SERVICE_SCAN: "service_scan", PROCESS_SCAN: "process_scan",
                EXPLOIT_SSH: "e_ssh",  EXPLOIT_FTP: "e_ftp", EXPLOIT_SAMBA: "e_samba", EXPLOIT_SMTP: "e_smtp", EXPLOIT_HTTP: "e_http", 
                PRIVI_ESCA_TOMCAT: "pe_tomcat", PRIVI_ESCA_PROFTPD: "pe_daclsvc", PRIVI_ESCA_CRON: "pe_schtask"}

HOST1_0 = 'host1-0'
HOST2_0 = 'host2-0'
HOST3_0 = 'host3-0'
HOST3_1 = 'host3-1'
HOST4_0 = 'host4-0'

ACTION_TARGETS = {
    HOST1_0: (1, 0),  # First subnet, single host
    HOST2_0: (2, 0),  # Second subnet, single host
    HOST3_0: (3, 0),  # Third subnet, first host
    HOST3_1: (3, 1),  # Third subnet, second host
    HOST4_0: (4, 0)   # Fourth subnet, single host
}


# Agent types
AGENT_TYPE_RANDOM = "random"
AGENT_TYPE_DETERMINISTIC = "deterministic"
DEFAULT_AGENT_TYPE = AGENT_TYPE_DETERMINISTIC

# Other constants
MAX_STEPS = 150 # Max number of pentesting steps (sys.maxsize to disable)
RENDER_OBS_STATE = False

#############################################################################
# Functions
#############################################################################

# Select an action from the action space based on its name
# 'action_name' and its target 'action_target'
def select_action(action_space, action_name, action_target):
    for i in range(0, action_space.n):
        action = action_space.get_action(i)
        if action.name == action_name and action.target == action_target:
            return action

#############################################################################
# Run pentesting with a random agent in the environment 'env'
def run_random_agent(env):

    # Initialize variables
    done = False # Indicate that execution is done
    truncated = False # Indicate that execution is truncated
    step_count = 0 # Count the number of execution steps

    # Loop while the experiment is not finished (pentesting goal not reached)
    # and not truncated (aborted because of exceeding maximum number of steps)
    while not done and not truncated:

        # Sample a random action from the action space of this environment
        action = env.action_space.sample()

        # Increment step count and execute action
        step_count = step_count + 1
        print(f"- Step {step_count}: {env.action_space.get_action(action)}")
        observation, reward, done, truncated, info = env.step(action)
        if RENDER_OBS_STATE:
            env.render() # render most recent observation
            env.render_state() # render most recent state

        # Conditional exit (for debugging purposes)
        if step_count >= MAX_STEPS:
            logging.warning(f"Abort execution after {step_count} steps")
            break

    return done, truncated, step_count

#############################################################################
# Run pentesting with a deterministic agent in the environment 'env'
def run_deterministic_agent(env, deterministic_path):

    # Initialize variables
    done = False # Indicate that execution is done
    truncated = False # Indicate that execution is truncated
    step_count = 0 # Count the number of execution steps
    total_reward = 0 # Tổng reward nhận được trong quá trình thực thi
    
    print("\n===== BẮT ĐẦU CHẠY DETERMINISTIC AGENT =====")
    print(f"[DEBUG] Tổng số bước trong deterministic path: {len(deterministic_path)}")
    print(f"[DEBUG] Chi tiết đường dẫn: {deterministic_path}")

    # Loop while the experiment is not finished (pentesting goal not reached)
    # and not truncated (aborted because of exceeding maximum number of steps)
    while not done and not truncated:
        # Exit if there are no more steps in the deterministic path
        if step_count >= len(deterministic_path):
            print("[DEBUG] Đã hết các bước trong deterministic path")
            break
        
        # Retrieve the next action to be executed
        action_tuple = deterministic_path[step_count]
        action = select_action(env.action_space, ACTION_NAMES[action_tuple[1]], ACTION_TARGETS[action_tuple[0]])
        
        print(f"\n[DEBUG] ----- THỰC THI BƯỚC {step_count + 1}/{len(deterministic_path)} -----")
        print(f"[DEBUG] Action tuple: {action_tuple}")
        print(f"[DEBUG] Tên hành động: {ACTION_NAMES[action_tuple[1]]}")
        print(f"[DEBUG] Mục tiêu: {ACTION_TARGETS[action_tuple[0]]}")
        print(f"[DEBUG] Action đã chuyển đổi: {action}")

        # Increment step count and execute action
        step_count = step_count + 1
        
        print(f"- Step {step_count}: {action}")
        
        # Bắt đầu đo thời gian thực thi
        import time
        start_time = time.time()
          
        observation, reward, done, truncated, info = env.step(action)
        
        # Kết thúc đo thời gian thực thi
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Cập nhật tổng reward
        total_reward += reward
        
        print(f"[DEBUG] Thời gian thực thi: {execution_time:.4f} giây")
        print(f"[DEBUG] Reward: {reward} (Tổng: {total_reward})")
        print(f"[DEBUG] Done: {done}, Truncated: {truncated}")
        print(f"[DEBUG] Info: {info}")
        
        # Hiển thị một phần của observation để debug
        if hasattr(observation, "shape"):  # Nếu observation là array hoặc tensor
            print(f"[DEBUG] Observation shape: {observation.shape}")
            # Hiển thị observation nếu là tensor
            if len(observation.shape) > 1:
                print(f"[DEBUG] Observation: {observation[:5]}")
            else:
                print(f"[DEBUG] Observation: {observation}")
        else:  # Nếu observation là dict hoặc cấu trúc khác
            print(f"[DEBUG] Observation type: {type(observation)}")
            
        if RENDER_OBS_STATE:
            print("[DEBUG] Rendering observation and state...")
            env.render() # render most recent observation
            env.render_state() # render most recent state

        # Conditional exit (for debugging purposes)
        if step_count >= MAX_STEPS:
            print(f"[DEBUG] CẢNH BÁO: Vượt quá số bước tối đa ({MAX_STEPS})")
            logging.warning(f"Abort execution after {step_count} steps")
            break

    # In thông tin tổng kết sau khi hoàn thành
    print("\n===== KẾT QUẢ THỰC THI =====")
    print(f"[DEBUG] Tổng số bước đã thực hiện: {step_count}/{len(deterministic_path)}")
    print(f"[DEBUG] Tổng reward: {total_reward}")
    print(f"[DEBUG] Hoàn thành mục tiêu: {done}")
    print(f"[DEBUG] Bị truncate: {truncated}")
    print(f"[DEBUG] Lý do kết thúc: {'Đạt mục tiêu' if done else 'Hết bước' if step_count >= len(deterministic_path) else 'Vượt quá số bước tối đa' if step_count >= MAX_STEPS else 'Bị truncate'}")
    print("================================\n")

    return done, truncated, step_count




# Create PenGym environment using scenario 'scenario_name'
def create_pengym_environment(scenario_name):
    env = pengym.create_environment(scenario_name)

    # Initialize seed for numpy (used to determine exploit success/failure) and
    # for the environment action space (used to determine order of random actions)
    seed = 1 # NORMAL: No e_ssh failure during pentesting path
    #seed = 300 # INCOMPLETE: Cause e_ssh failure during pentesting path
    numpy.random.seed(seed)
    env.action_space.seed(1)

    return env

# Create PenGym environment using custom scenario
def create_pengym_custom_environment(scenario_path):
    env = pengym.load(scenario_path)

    seed = 1
    numpy.random.seed(seed)
    env.action_space.seed(1)

    return env

# Print usage information
def usage():
    print("\nOVERVIEW: Run demo of the PenGym training framework for pentesting agents\n")
    print("USAGE: python3 run.py [options] <CONFIG_FILE> \n")
    print("OPTIONS:")
    print("-h, --help                     Display this help message and exit")
    print("-a, --agent_type <AGENT_TYPE>  Agent type (random/deterministic)")
    print("-d, --disable_pengym           Disable PenGym execution in cyber range")
    print("-n, --nasim_simulation         Enable NASim simulation execution")

#############################################################################
# Main program
#############################################################################
def main(args):

    # Configure logging
    logging.basicConfig(level=logging.INFO,
                        format='* %(levelname)s: %(filename)s: %(message)s')


    print("#########################################################################")
    print("PenGym: Pentesting Training Framework for Reinforcement Learning Agents")
    print("#########################################################################")

    # Default argument values
    agent_type = DEFAULT_AGENT_TYPE
    config_path = None

    # Parse command line arguments
    try:
        # Make sure to add ':' for short-form and '=' for long-form options that require an argument
        opts, trailing_args = getopt.getopt(args, "ha:dn",
                                            ["help", "agent_type=", "disable_pengym", "nasim_simulation"])
    except getopt.GetoptError as err:
        logging.error(f"Command-line argument error: {str(err)}")
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-a", "--agent"):
            agent_type = arg
        elif opt in ("-d", "--disable_pengym"):
            utils.ENABLE_PENGYM = False
        elif opt in ("-n", "--nasim_simulation"):
            utils.ENABLE_NASIM = True
        else:
            # Nothing to do, since unrecognized options are caught by
            # the getopt.GetoptError exception above
            pass

    # Get path of configuration file
    try:
        config_path = trailing_args[0]
    except Exception as e:
        logging.error(f"Configuration file is not specified")
        usage()
        sys.exit(2)

    # Print parameters
    print(f"* Execution parameters:")
    print(f"  - Agent type: {agent_type}")
    print(f"  - PenGym cyber range execution enabled: {utils.ENABLE_PENGYM}")
    print(f"  - NASim simulation execution enabled: {utils.ENABLE_NASIM}")

    # Check execution parameters
    if not (utils.ENABLE_PENGYM or utils.ENABLE_NASIM):
        logging.error("Either PenGym or NASim must be enabled")
        usage()
        sys.exit(2)

    print(f"* Read configuration from '{config_path}'...")
    utils.init_config_info(config_path)

    # Create an experiment environment using scenario path
    scenario_path = utils.replace_file_path(utils.config_info, storyboard.SCENARIO_FILE)
    print(f"* Create environment using custom scenario from '{scenario_path}'...")
    env = create_pengym_custom_environment(scenario_path)

    if utils.ENABLE_PENGYM:
        print(f"* Read configuration from '{config_path}'...")
        utils.init_config_info(config_path)
        
        print("* Initialize MSF RPC client...")
        try:
            utils.init_msfrpc_client()
        except Exception as e:
            logging.error(f"Failed to initialize MSF RPC client: {e}")
            print("* Cannot continue without Metasploit RPC connection.")
            print("* Please ensure Metasploit is running and RPC settings are correct in CONFIG.yml.")
            print("* Check if msfrpcd is running with: ps aux | grep msfrpcd")
            print("* Start it with: msfrpcd -P yourpassword -S -a 127.0.0.1")
            sys.exit(2)
        
        print("* Initialize Nmap Scanner...")
        utils.init_nmap_scanner()
        
        utils.init_host_map()

        # Initialize map of service ports
        utils.init_service_port_map()

        # Deactivate bridge that not connected to Internet
        utils.init_bridge_setup()

    # Run experiment using a random agent
    if agent_type == AGENT_TYPE_RANDOM:
        print("* Perform pentesting using a RANDOM agent...")
        done, truncated, step_count = run_random_agent(env)

    # Run experiment using a deterministic agent
    elif agent_type == AGENT_TYPE_DETERMINISTIC:

        # Set up deterministic path

        # Optimal path for scenario "tiny-small" according to "tiny-small.yml"
        # (e_http, (1, 0)) -> subnet_scan -> (e_ssh, (2, 0)) -> (pe_tomcat, (2,0)) -> (e_http, (3, 1))
        #       -> subnet_scan -> (e_ftp, (4, 0))
        # deterministic_path = [(HOST1_0, EXPLOIT_HTTP), (HOST1_0, SUBNET_SCAN),
        #                     (HOST2_0, EXPLOIT_SSH), (HOST2_0, PRIVI_ESCA_TOMCAT),
        #                     (HOST3_1, EXPLOIT_HTTP), (HOST3_1, SUBNET_SCAN),
        #                     (HOST4_0, EXPLOIT_FTP)]

        # Pentesting path for scenario "tiny-small" including scanning operations
        # deterministic_path = [(HOST1_0, OS_SCAN), (HOST1_0, SERVICE_SCAN), (HOST1_0, EXPLOIT_HTTP), (HOST1_0, SUBNET_SCAN),
        #                     (HOST2_0, OS_SCAN), (HOST2_0, SERVICE_SCAN), (HOST2_0, EXPLOIT_SSH), (HOST2_0, PROCESS_SCAN), (HOST2_0, PRIVI_ESCA_TOMCAT),
        #                     (HOST3_1, OS_SCAN), (HOST3_1, SERVICE_SCAN), (HOST3_1, EXPLOIT_HTTP), (HOST3_1, SUBNET_SCAN),
        #                     (HOST4_0, OS_SCAN), (HOST4_0, SERVICE_SCAN), (HOST4_0, EXPLOIT_FTP)]
        
        deterministic_path = [(HOST1_0, PROCESS_SCAN)]

        print("* Execute pentesting using a DETERMINISTIC agent...")
        done, truncated, step_count = run_deterministic_agent(env, deterministic_path)

    else:
        logging.error(f"Unrecognized agent type: '{agent_type}'")
        usage()
        sys.exit(1)

    # Print execution status
    if done:
        # All the goals in the scenario file were reached
        print(f"* NORMAL execution: {step_count} steps")
    elif truncated:
        # Execution was truncated before reaching all the goals (for random agents, etc.)
        print(f"* TRUNCATED execution: {step_count} steps")
    else:
        # Execution finished before reaching all the goals (for deterministic agents)
        print(f"* INCOMPLETE execution: {step_count} steps")

    if utils.ENABLE_PENGYM:
        print("* Clean up MSF RPC client...")
        utils.cleanup_msfrpc_client()

        print("* Restore the to intial state of the firewalls for all hosts...")
        utils.save_restore_firewall_rules_all_hosts(flag=storyboard.RESTORE)

#############################################################################
# Run program
if __name__ == "__main__":
    start = time.time()
    main(sys.argv[1:])
    end = time.time()
    #print(f"Execution Time: {end-start:1.6f}s")
