# Import libraries
from nasim.envs.state import State # type: ignore
from nasim.scenarios.scenario import Scenario # type: ignore
import numpy as np
import psutil
from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
from pengym.storyboard import Storyboard
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union
import sys
import nmap
import subprocess
import yaml

from logger import logger

# Định nghĩa chi tiết về kiểu dữ liệu của các giá trị trong host_map
class HostMapDict(TypedDict, total=True):
    # Định nghĩa kiểu dữ liệu cho mỗi trường trong host_map
    host_ip: List[str]                # Danh sách địa chỉ IP của host (ví dụ: ["192.168.100.10"])
    subnet_ip: str                    # Địa chỉ subnet dạng CIDR (ví dụ: "192.168.100.0/24")
    kvm_domain: str                   # Tên domain trong KVM (ví dụ: "subnet1-host0")
    bridge_up: bool                   # Trạng thái bridge (True/False)
    shell: Optional[Any]       # Đối tượng shell từ Metasploit (hoặc None nếu chưa có shell)
    os: Optional[Dict[str, bool]]     # Thông tin OS được phát hiện (hoặc None nếu chưa scan)
    services: Optional[Dict[str, bool]]  # Thông tin dịch vụ được phát hiện (hoặc None nếu chưa scan)
    processes: Optional[Dict[str, bool]]  # Thông tin tiến trình được phát hiện (hoặc None nếu chưa scan)
    subnet: Optional[int]             # ID của subnet mà host thuộc về (hoặc None nếu chưa xác định)
    pe_shell: Dict[str, Any]   # Từ điển lưu các shell đã thực hiện privilege escalation
    exploit_access: Dict[str, int]    # Từ điển lưu các giá trị truy cập của exploit
    access: float                     # Mức độ truy cập (0.0 = không có quyền, các giá trị khác tương ứng với AccessLevel)
    default_gw: Optional[bool]        # Trạng thái default gateway (hoặc None nếu chưa xác định)
    service_scan_state: bool          # Trạng thái quét dịch vụ (True = có thể quét)
    os_scan_state: bool               # Trạng thái quét OS (True = có thể quét)
    service_exploit_state: bool       # Trạng thái khai thác dịch vụ (True = có thể khai thác)

# Định nghĩa kiểu dữ liệu tổng thể cho host_map
HostMapType = Dict[Tuple[int, int], HostMapDict]

# Declare global variables
global config_info
global scenario
scenario: Optional[Scenario] = None
global host_map
host_map: HostMapType = {}
global bridge_map
global service_port_map
global host_is_discovered
global msfrpc_client
global nmap_scanner
global current_state
global ENABLE_PENGYM
global ENABLE_NASIM
global PENGYM_ERROR

# Declare constant values from pengym board
storyboard = Storyboard()

# Declare discovered host list
host_is_discovered : List[Tuple[int, int]] = list()

# Declare Metasploit and Nmap objects
msfrpc_client = None
nmap_scanner = None
service_port_map: Optional[Dict[str, int]] = None
current_state: Optional[State] = None

# Default values regarding default PenGym/NASim execution
ENABLE_PENGYM = True
PENGYM_ERROR = False
ENABLE_NASIM = False

def load_yaml_file(file_path):
    """Load YAML file to dictionary
    
    Args:
        file_pathh (str): directory of yaml file
    """
    try:
        with open(file_path, 'r') as file:
            return yaml.load(file, Loader=yaml.FullLoader)
    except Exception as e:
        print(f"* ERROR: Failed to load the {file_path} file: {e}", file=sys.stderr)
        sys.exit(2)

def execute_script(command):
    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Check the return code
    if result.returncode == 0:
        return True
    else:
        print("Error: ", result.stderr)
        raise Exception(f"Command failed: {result.stderr}")

def init_config_info(config_path):
    """Parse the config file into config information

    Args:
        config_path (str): directory of config file
    """
    global config_info
    config_info = load_yaml_file(config_path)

def init_msfrpc_client():
    """Initialize the Metasploit client with automatic proxy configuration
    """
    my_password = config_info[storyboard.MSFRPC_CONFIG][storyboard.MSFRPC_CLINET_PWD]
    
    # Get host value, default is 127.0.0.1
    host = "127.0.0.1"
    if storyboard.MSFRPC_HOST in config_info[storyboard.MSFRPC_CONFIG]:
        host = config_info[storyboard.MSFRPC_CONFIG][storyboard.MSFRPC_HOST]
    
    port = config_info[storyboard.MSFRPC_CONFIG][storyboard.MSFRPC_PORT] 
    
    # Get SSL setting from config file without overriding
    ssl = False  # Default value
    if storyboard.SSL in config_info[storyboard.MSFRPC_CONFIG]:
        ssl = config_info[storyboard.MSFRPC_CONFIG][storyboard.SSL]
    
    # Automatically check for proxy settings and update no_proxy environment variable if needed
    import os
    proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
    proxy_in_use = any(var in os.environ for var in proxy_vars)
    
    if proxy_in_use:
        old_no_proxy = os.environ.get('no_proxy', '')
        # Check if host is already in no_proxy
        if host not in old_no_proxy.split(','):
            os.environ['no_proxy'] = f"{host},{old_no_proxy}" if old_no_proxy else host
            os.environ['NO_PROXY'] = os.environ['no_proxy']  # Set both upper and lowercase versions
            print(f"  Proxy detected: Adding {host} to no_proxy environment variable")
    
    # Add timeout values with defaults
    connection_timeout = 5  # Default timeout in seconds
    if 'connection_timeout' in config_info[storyboard.MSFRPC_CONFIG]:
        connection_timeout = config_info[storyboard.MSFRPC_CONFIG]['connection_timeout']

    try:
        global msfrpc_client
        print(f"  Connecting to MSF RPC server at {host}:{port} (timeout: {connection_timeout}s, SSL: {ssl})...")
        
        # Use a timeout mechanism to prevent hanging
        import socket
        socket.setdefaulttimeout(connection_timeout)
        
        # Debugging: First test a raw TCP connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            print(f"  Successfully established TCP connection to {host}:{port}")
            s.close()
        except Exception as e:
            print(f"  TCP connection test failed: {e}")
            raise
        
        # Now try the actual MSF RPC connection
        msfrpc_client = MsfRpcClient(my_password, server=host, port=port, ssl=ssl)
        print("  Successfully connected to MSF RPC server")
        
        # Reset default timeout
        socket.setdefaulttimeout(None)
        
    except socket.timeout:
        print(f"* ERROR: Connection to MSF RPC server at {host}:{port} timed out after {connection_timeout} seconds", file=sys.stderr)
        raise TimeoutError(f"MSF RPC connection timed out after {connection_timeout} seconds")
    except Exception as e:
        print(f"* ERROR: Failed to connect to MSF RPC client at {host}:{port}: {e}", file=sys.stderr)
        print("* Try these troubleshooting steps:")
        print("  1. Verify Metasploit RPC server is running: ps aux | grep msfrpcd")
        print(f"  2. Test connection manually: echo -n | nc -v {host} {port}")
        print(f"  3. If you're using a proxy, check your proxy settings and make sure {host} is in no_proxy")
        print(f"  4. Confirm the password is correct in CONFIG.yml")
        print(f"  5. Start msfrpcd with: msfrpcd -P <password> -S true -a {host} -p {port}")
        raise

def cleanup_msfrpc_client():
    """Clean up the Metasploit client, and close sessions after the agent finishes running 
    """
    global msfrpc_client

    if msfrpc_client:
        logger.info("[CLEANUP] Bắt đầu dọn dẹp Metasploit client")
        
        # Lấy số lượng jobs và sessions ban đầu để theo dõi
        initial_job_count = len(msfrpc_client.jobs.list)
        initial_session_count = len(msfrpc_client.sessions.list)
        logger.info(f"[CLEANUP] Số lượng jobs hiện có: {initial_job_count}, sessions: {initial_session_count}")
        
        # Đếm số vòng lặp để phòng trường hợp lặp vô hạn
        cleanup_iterations = 0
        max_iterations = 10  # Giới hạn số vòng lặp 
        
        while (len(msfrpc_client.jobs.list) != 0 or len(msfrpc_client.sessions.list) != 0):
            cleanup_iterations += 1
            logger.debug(f"[CLEANUP] Vòng lặp dọn dẹp thứ {cleanup_iterations}")
            
            # Dọn dẹp jobs
            if len(msfrpc_client.jobs.list) > 0:
                logger.info(f"[CLEANUP] Đang dừng {len(msfrpc_client.jobs.list)} jobs...")
                for job_id, job_info in msfrpc_client.jobs.list.items():
                    try:
                        logger.debug(f"[CLEANUP] Đang dừng job {job_id}: {job_info}")
                        msfrpc_client.jobs.stop(job_id)
                        logger.debug(f"[CLEANUP] Đã dừng job {job_id}")
                    except Exception as e:
                        logger.warning(f"[CLEANUP] Lỗi khi dừng job {job_id}: {e}")
            
            # Dọn dẹp sessions
            if len(msfrpc_client.sessions.list) > 0:
                logger.info(f"[CLEANUP] Đang dừng {len(msfrpc_client.sessions.list)} sessions...")
                for session_key, session_details in msfrpc_client.sessions.list.items():
                    try:
                        logger.debug(f"[CLEANUP] Đang dừng session {session_key}: {session_details}")
                        msfrpc_client.sessions.session(session_key).stop()
                        logger.debug(f"[CLEANUP] Đã dừng session {session_key}")
                    except Exception as e:
                        logger.warning(f"[CLEANUP] Lỗi khi dừng session {session_key}: {e}")
            
            # Kiểm tra nếu đã quá số vòng lặp tối đa
            if cleanup_iterations >= max_iterations:
                logger.warning(f"[CLEANUP] Đã đạt đến giới hạn {max_iterations} vòng lặp. Có thể còn jobs/sessions không thể dừng.")
                break
            
            # Tạm dừng để tránh sử dụng quá nhiều CPU
            import time
            time.sleep(0.5)
        
        # Báo cáo kết quả
        jobs_remaining = len(msfrpc_client.jobs.list)
        sessions_remaining = len(msfrpc_client.sessions.list)
        logger.info(f"[CLEANUP] Hoàn thành dọn dẹp sau {cleanup_iterations} vòng lặp.")
        logger.info(f"[CLEANUP] Jobs đã dừng: {initial_job_count - jobs_remaining}/{initial_job_count}")
        logger.info(f"[CLEANUP] Sessions đã dừng: {initial_session_count - sessions_remaining}/{initial_session_count}")
        
        if jobs_remaining > 0 or sessions_remaining > 0:
            logger.warning(f"[CLEANUP] Vẫn còn {jobs_remaining} jobs và {sessions_remaining} sessions chưa được dọn dẹp.")
    else:
        logger.debug("[CLEANUP] Không có Metasploit client nào cần dọn dẹp")

def init_nmap_scanner():
    """Initialize the nmap scanner for scanning actions
    """
    try:
        global nmap_scanner
        nmap_scanner = nmap.PortScanner()
    except Exception as e:
        print(f"* WARNING: Failed to initialize NMap: {e}", file=sys.stderr)
        sys.exit(2)

def extract_network_info(range_details_file):
    """Extract network informatiion from the cyber range detail yaml file

    Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS

    Returns:
        network(dict): network information dictionary
    """
    
    yaml_dict = load_yaml_file(range_details_file)
    network = list()

    # Get the list of instances
    instance_list = yaml_dict[storyboard.HOSTS][0][storyboard.INSTANCES]

    for instance in instance_list:

        instance_dict = dict()
        subnet_list = list()
        host_list = list()

        
        instance_dict[storyboard.INSTANCE] = instance[storyboard.INSTANCE_INDEX]
        
        for guest in instance[storyboard.GUESTS]:
            
            host = dict()
            host_ip = list()
            host_subnet = list()
            
            host[storyboard.NAME] = guest[storyboard.GUEST_ID]
            host[storyboard.KVM_DOMAIN] = guest[storyboard.KVM_DOMAIN]
            
            # Get the ip and subnet address of each host
            for _, value in guest[storyboard.IP_ADDRESSES].items():
                host_ip.append(value)
                subnet = value[:-1] + "0/24"
                if subnet not in host_subnet:
                    host_subnet.append(subnet)
                    if subnet not in subnet_list:
                        subnet_list.append(subnet)
            
            for _, value in guest[storyboard.GATEWAYS].items():
                host[storyboard.GATEWAYS] = value
            
            host[storyboard.SUBNET] = host_subnet
            host[storyboard.HOST_IP] = host_ip
            host_list.append(host)
        
        instance_dict[storyboard.SUBNET_INSTANCE] = subnet_list
        instance_dict[storyboard.HOSTS] = host_list
        
        network.append(instance_dict)

    return network

def create_host_map(range_details_file, instance_index):
    """Create host_map dictionary to map NASim host address 
    to PenGym host address and information. 
    
    Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS
        
        instance_index (int): instance number of network in clone setting 
        that compatible with CyRIS scenario

    Returns:
        map: host_map dictionary
    """
    map = dict()
    subnet = dict()
    network = extract_network_info(range_details_file)

    for instance in network:
        if instance[storyboard.INSTANCE] == instance_index:
            hosts = instance[storyboard.HOSTS]
            break

    for host in hosts:
        map_info = dict()
        subnet_id = host[storyboard.NAME].split('-')[1]
        subnet_ip = ' '.join(host[storyboard.SUBNET])

        # Get the index of host in the subnet
        if subnet_id in subnet:
            host_id = subnet[subnet_id] + 1
        else:
            host_id = 0

        subnet[subnet_id] = host_id
        
        map_info[storyboard.HOST_IP] = host[storyboard.HOST_IP] # List of IP of this host
        map_info[storyboard.SUBNET_IP] = subnet_ip # All subnet addresses of this network
        map_info[storyboard.KVM_DOMAIN] = host[storyboard.KVM_DOMAIN]
        map_info[storyboard.BRIDGE_UP] = False # Flag to turn on/off the bridge
        map_info[storyboard.SHELL] = None # Shell object after obtaining the shell
        map_info[storyboard.OS] = None # OS value after executing OS Scan
        map_info[storyboard.SERVICES] = None # Services value after executing service scan
        map_info[storyboard.PROCESSES] = None # Process value after executing process scan
        map_info[storyboard.SUBNET] = None # Subnet value after executing subnet scan
        map_info[storyboard.PE_SHELL] = dict() # Root shell object after obtaining the shell
        map_info[storyboard.EXPLOIT_ACCESS] = dict() # Access value of exploit action
        map_info[storyboard.ACCESS] = 0.0 # Access level of current host
        map_info[storyboard.DEFAULT_GW] = None # Status of default gateway in current VM
        map_info[storyboard.SERVICE_SCAN_STATE] = True # State of service scan
        map_info[storyboard.OS_SCAN_STATE] = True # State of OS Scan
        map_info[storyboard.SERVICE_EXPLOIT_STATE] = True # State of sevice exploit action

        key = (int(subnet_id),host_id)
        map[key] = map_info

    return map

def create_bridge_map():
    """Create bridge_map dictionary to map NASim subnet link to name of bridge. 
    
    Args:
        network_path (str): path of folder contains range detail 
        information yaml file after creating by CyRIS

        instance_index (int): instance number of network in clone setting 
        that compatible with CyRIS scenario

    Returns:
        bridge_map: bridge_map dictionary
    """
    # Bỏ qua tham số range_details_file và tạo bridge_map cố định
    bridge_map = {
        'link01': ['virbr1', '192.168.100.1', False],  # Internet đến Subnet 1
        'link12': ['virbr2', '172.18.1.1', False],     # Subnet 1 đến Subnet 2
        'link23': ['virbr3', '10.0.0.1', False],       # Subnet 2 đến Subnet 3
        'link34': ['virbr4', '10.0.1.1', False]        # Subnet 3 đến Subnet 4
    }
    return bridge_map

def init_host_map():
    """Khởi tạo thủ công host_map cho môi trường có sẵn
    
    Args:
        range_details_file: Không sử dụng, giữ để tương thích API
        instance_index: Không sử dụng, giữ để tương thích API
    """
    global host_map
    host_map = {}
    
    # Tạo cấu trúc cho host tại (1, 0) - Subnet 1, Host 0
    host_map[(1, 0)] = {
        storyboard.HOST_IP: ["192.168.100.10"],             # IP của host
        storyboard.SUBNET_IP: "192.168.100.0/24",           # Subnet
        storyboard.KVM_DOMAIN: "subnet1-host0",              # Tên domain trong KVM
        storyboard.BRIDGE_UP: False,                        # Trạng thái bridge
        storyboard.SHELL: None,                             # Shell object
        storyboard.OS: None,                                # OS value
        storyboard.SERVICES: None,                          # Services
        storyboard.PROCESSES: None,                         # Processes
        storyboard.SUBNET: None,                            # Subnet
        storyboard.PE_SHELL: dict(),                        # Root shell objects
        storyboard.EXPLOIT_ACCESS: dict(),                  # Exploit access values
        storyboard.ACCESS: 0.0,                             # Access level
        storyboard.DEFAULT_GW: None,                        # Default gateway status
        storyboard.SERVICE_SCAN_STATE: True,                # Service scan state
        storyboard.OS_SCAN_STATE: True,                     # OS scan state
        storyboard.SERVICE_EXPLOIT_STATE: True              # Service exploit state
    }
    
    # Tạo cấu trúc cho host tại (2, 0) - Subnet 2, Host 0
    host_map[(2, 0)] = {
        storyboard.HOST_IP: ["172.18.1.10"],
        storyboard.SUBNET_IP: "172.18.1.0/24",
        storyboard.KVM_DOMAIN: "subnet2-host0",
        storyboard.BRIDGE_UP: False,
        storyboard.SHELL: None,
        storyboard.OS: None,
        storyboard.SERVICES: None,
        storyboard.PROCESSES: None,
        storyboard.SUBNET: None,
        storyboard.PE_SHELL: dict(),
        storyboard.EXPLOIT_ACCESS: dict(),
        storyboard.ACCESS: 0.0,
        storyboard.DEFAULT_GW: None,
        storyboard.SERVICE_SCAN_STATE: True,
        storyboard.OS_SCAN_STATE: True,
        storyboard.SERVICE_EXPLOIT_STATE: True
    }
    
    # Tạo cấu trúc cho host tại (3, 0) - Subnet 3, Host 0
    host_map[(3, 0)] = {
        storyboard.HOST_IP: ["10.0.0.10"],
        storyboard.SUBNET_IP: "10.0.0.0/24",
        storyboard.KVM_DOMAIN: "subnet3-host0",
        storyboard.BRIDGE_UP: False,
        storyboard.SHELL: None,
        storyboard.OS: None,
        storyboard.SERVICES: None,
        storyboard.PROCESSES: None,
        storyboard.SUBNET: None,
        storyboard.PE_SHELL: dict(),
        storyboard.EXPLOIT_ACCESS: dict(),
        storyboard.ACCESS: 0.0,
        storyboard.DEFAULT_GW: None,
        storyboard.SERVICE_SCAN_STATE: True,
        storyboard.OS_SCAN_STATE: True,
        storyboard.SERVICE_EXPLOIT_STATE: True
    }
    
    # Tạo cấu trúc cho host tại (3, 1) - Subnet 3, Host 1
    host_map[(3, 1)] = {
        storyboard.HOST_IP: ["10.0.0.60"],
        storyboard.SUBNET_IP: "10.0.0.0/24",
        storyboard.KVM_DOMAIN: "subnet3-host1",
        storyboard.BRIDGE_UP: False,
        storyboard.SHELL: None,
        storyboard.OS: None,
        storyboard.SERVICES: None,
        storyboard.PROCESSES: None,
        storyboard.SUBNET: None,
        storyboard.PE_SHELL: dict(),
        storyboard.EXPLOIT_ACCESS: dict(),
        storyboard.ACCESS: 0.0,
        storyboard.DEFAULT_GW: None,
        storyboard.SERVICE_SCAN_STATE: True,
        storyboard.OS_SCAN_STATE: True,
        storyboard.SERVICE_EXPLOIT_STATE: True
    }
    
    # T��o cấu trúc cho host tại (4, 0) - Subnet 4, Host 0
    host_map[(4, 0)] = {
        storyboard.HOST_IP: ["10.0.1.10"],
        storyboard.SUBNET_IP: "10.0.1.0/24",
        storyboard.KVM_DOMAIN: "subnet4-host0",
        storyboard.BRIDGE_UP: False,
        storyboard.SHELL: None,
        storyboard.OS: None,
        storyboard.SERVICES: None,
        storyboard.PROCESSES: None,
        storyboard.SUBNET: None,
        storyboard.PE_SHELL: dict(),
        storyboard.EXPLOIT_ACCESS: dict(),
        storyboard.ACCESS: 0.0,
        storyboard.DEFAULT_GW: None,
        storyboard.SERVICE_SCAN_STATE: True,
        storyboard.OS_SCAN_STATE: True,
        storyboard.SERVICE_EXPLOIT_STATE: True
    }
    
    return host_map

def reset_host_map():
    """Reset the neccessary attribute of host map
    """
    global host_map

    for address in host_map.keys():
        host_map[address][storyboard.BRIDGE_UP] = False
        host_map[address][storyboard.SHELL] = None
        host_map[address][storyboard.OS] = None
        host_map[address][storyboard.SERVICES] = None
        host_map[address][storyboard.PROCESSES] = None
        host_map[address][storyboard.SUBNET] = None
        host_map[address][storyboard.PE_SHELL] = dict()
        host_map[address][storyboard.EXPLOIT_ACCESS] = dict()
        host_map[address][storyboard.ACCESS] = 0.0
        host_map[address][storyboard.DEFAULT_GW] = None
        host_map[address][storyboard.SERVICE_SCAN_STATE] = True
        host_map[address][storyboard.OS_SCAN_STATE] = True
        host_map[address][storyboard.SERVICE_EXPLOIT_STATE] = True

def init_bridge_setup():
    """Create bridge map, init the setup of bridges
        De-activate hosts that are not connected to the Internet
        
        Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS
        
        instance_index (int, optional): instance number of network in clone setting 
        that compatible with CyRIS scenario (Default = 1)
    """
    try:
        global bridge_map
        bridge_map = create_bridge_map()
    except Exception as e:
        print(f"* WARNING: Failed to create bridge map: {e}", file=sys.stderr)

    if scenario is None:
        raise ValueError("Scenario is not initialized. Please initialize the scenario before calling init_bridge_setup.")

    conntected_subnet = list()
    internet = scenario.topology[0]

    for idx in range(1, len(internet)):
        if internet[idx] == 1:
            subnet_name = f'link0{idx}'
            conntected_subnet.append(subnet_name)

    # Deactivate bridge of hosts that are not connected to the Internet
    for link in bridge_map.keys():
        if link not in conntected_subnet:
            bridge_name = bridge_map[link][0]
            print(f"  Deactivate bridge {bridge_name}...")
            deactivate_bridge(bridge_name)

def init_service_port_map():
    """Create the service port map
    """
    # Khai báo sử dụng biến toàn cục service_port_map
    global service_port_map 
    
    # Gán giá trị từ cấu hình cho biến toàn cục
    service_port_map = config_info[storyboard.SERVICE_PORT]
    
    if service_port_map is None:
        raise ValueError("Service port map is not initialized. Please initialize the service port map before calling init_service_port_map.")
    
    # Debug: In ra thông tin về service_port_map
    logger.debug(f"[DEBUG] Đã khởi tạo service_port_map")
    logger.debug(f"[DEBUG] Số lượng dịch vụ trong map: {len(service_port_map)}")
    
    # Debug: In chi tiết các dịch vụ và cổng tương ứng
    print("[DEBUG] Chi tiết mapping dịch vụ-cổng:")
    for service, port in service_port_map.items():
        logger.debug(f"[DEBUG]  - {service}: {port}")
    
    # Debug: Kiểm tra một số dịch vụ quan trọng
    important_services = ["ssh", "http", "https", "ftp", "smb"]
    print("[DEBUG] Kiểm tra các dịch vụ quan trọng:")
    for service in important_services:
        if service.upper() in service_port_map:
            logger.debug(f"[DEBUG]  - {service.upper()}: {service_port_map[service.upper()]}")
        else:
            logger.debug(f"[DEBUG]  - {service.upper()}: Không có trong map")

def map_result_list_to_dict(resultValues, scenarioValues, bool=False):
    """Transform the result values from PenGym format (list) to NASim format (dictionary of all values in scenario with True/False)
    Example: PenGym format ['ssh']
    -> NASim format {'ssh': 1.0, 'tcp': 0.0}, where 1.0 means True, 0.0 means False (Default)
       OR
    -> NASim format {'ssh': True, 'tcp': False}, in case the bool flag is on

    Args:
        resultValues (list): List of result values from PenGym actions
        scenarioValues (list): List of all values from scenario (list of all processes/os/services from scenario)
        bool (bool, optional): True/False value flag. Defaults to False

    Returns:
        value_dict(dict): Dictionary format of resultValues
    """
    value_dict = dict()

    for value in scenarioValues:
        if bool:
            value_dict[value] = value in resultValues
        else:
            value_dict[value] = value_dict[value] = np.float32(any(value in service for service in resultValues))

    return value_dict

def map_dict_values_to_list(dictValues):
    """Transform the dictionary values to list 
    Example: 
    {'ssh': True, 'ftp': False}
    -> ['ssh']

    Args:
        dictValues (dict): Dictionary of values
        scenarioValues (list): List of all values from scenario (list of all processes/os/services from scenario)
        bool (bool, optional): True/False value flag. Defaults to False

    Returns:
        value_dict(dict): Dictionary format of resultValues
    """
    value_list = list()

    for value, status in dictValues.items():
        if status:
           value_list.append(value)

    return value_list

def map_host_address_to_IP_address(host_map: HostMapType, host: Tuple[int, int], subnet = False) -> Union[str, List[str]]:
    """Mapping host key address of NASim host to a list of IP addresses of corresponding PenGym host
    A list of subnet IP addresses of the PenGym host is returned if the subnet flag is on

    Args:
        host_map (dict): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
        host (tuple): Host key address of NASim host
        subnet (bool, optional): Subnet flag
        True if want to return list of subnet IP addresses. Defaults to False

    Returns:
        (list): List of subnet ip addresses or host IP addresses of corresponding host
    """
    if subnet:
        return host_map[host][storyboard.SUBNET_IP]
    else:
        return host_map[host][storyboard.HOST_IP]

def map_IP_adress_to_host_address(host_map, ip_list):
    """Mapping list of IP addresses of PenGym hosts to each host key address of corresponding NASim hosts

    Args:
        host_map (dict): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
        ip_list (list): List of IP addresses of PenGym hosts

    Returns:
        (list): list of corresponding host key address of NASim hosts
    """
    host_address_list = list()

    for ip in ip_list:
        for key, value in host_map.items():
            if ip in value[storyboard.HOST_IP]:
                if (not key in host_address_list): # Check to avoid duplicate host key value. 
                    host_address_list.append(key)

    return host_address_list

def print_failure(action, observation, context, exec_time):
    """Print out the error types of actions on current host
       There are 3 kinds of error: connection error, permission error and undefined error

    Args:
        action (Action): The current action is executed 
        observation (ActionResult): The result information of the action
        context (str): pengym/nasim
        exec_time (double): Execution time
    """
    logger.error(f"  Host {action.target} Action '{action.name}' FAILURE:"
                  f"{' connection_error=TRUE' if observation.connection_error else ''}"
                  f"{' permission_error=TRUE' if observation.permission_error else ''}"
                  f"{' undefined_error=TRUE'  if observation.undefined_error  else ''}"
                  f" Execution Time: {exec_time:1.6f}[{context}]")

def check_bridge_status (bridge_name):
    """Kiểm tra trạng thái của bridge (bật/tắt)
    Hàm này kiểm tra xem bridge mạng có đang hoạt động hay không bằng cách
    tìm bridge theo tên trong danh sách các giao diện mạng và kiểm tra trạng thái.
        bridge_name (str): Tên của bridge cần kiểm tra trạng thái
    Returns:
        bool: True nếu bridge đang hoạt động, False nếu không tìm thấy hoặc không hoạt động
    Ví dụ:
        >>> check_bridge_status("br0")
        True
    # Duyệt qua các giao diện mạng và thông tin chi tiết của chúng
        # Nếu tìm thấy giao diện trùng với tên bridge cần kiểm tra
            # Trả về trạng thái hoạt động của bridge
    # Trả về False nếu không tìm thấy bridge
    return False
    """
    for iface, details in psutil.net_if_stats().items():
        if (iface == bridge_name):
            return details.isup
        
def activate_bridge(bridge_name):
    """Activate the bridge

    Args:
        bridge_name (str): The name of bridge that need to activate
    """
    command = f"sudo ifconfig {bridge_name} up"

    execute_script(command)


def deactivate_bridge(bridge_name):
    """De-activate the bridge

    Args:
        bridge_name (str): The name of bridge that need to de-activated 
    """
    command = f"sudo ifconfig {bridge_name} down"
    
    # Execute script
    execute_script(command)

def activate_host_bridge(host):
    """Activate all the bridges of host when it is compromised
    
    Args:
        host (tuple): Current host address (e.g. (1,0))
    
    Returns:
        activate_link_list (list): List of activate link (key in bridge_map, e.g., link01)
    """
    prefix_link = f"{host[0]}"
    activate_link_list = []

    for link in bridge_map.keys():
        if prefix_link in link:
            bridge_name = bridge_map[link][0]
            bridge_state = bridge_map[link][2]
            if not bridge_state:
                activate_bridge(bridge_name)
                bridge_map[link][2] = True
                activate_link_list.append(link)

    return activate_link_list

def check_host_compromised_within_subnet(subnet_id):
    """Check if there is any host be compromised in the current subnet

    Args:
        subnet_id (int): subnet index
    """
    for host_id, host_item in host_map.items():
        if host_id[0] == subnet_id:
            if host_item[storyboard.SHELL] is not None:
                return True
    
    return False

def update_host_service_scan_state(current_subnet, has_host_compromised, activate_link_list):
    """Update the service scan state of hosts that need to reexecute the service scan.
        When a host within a subnet becomes compromised, 
        the state of the hosts within this subnet and the connected subnets changes.
        
        Args:
            current_subnet (str): Current subnet of the current host
            has_host_compromised (bool): Check value if there is any host has been compromised in currrent subnet
            activate_link_list (list): List of activated link after current host be compromised
    """
    update_flag = False
    for link in activate_link_list:

        for host_idx, _ in host_map.items():
            subnet_id = host_idx[0]
            
            if str(subnet_id) in link:
                if (subnet_id == current_subnet) and (not has_host_compromised):
                        update_flag = True
                elif (subnet_id != current_subnet) and (not check_host_compromised_within_subnet(subnet_id)):
                        update_flag = True

            if update_flag:
                host_map[host_idx][storyboard.SERVICE_SCAN_STATE] = True
                host_map[host_idx][storyboard.SERVICE_EXPLOIT_STATE] = True
                host_map[host_idx][storyboard.OS_SCAN_STATE] = True
                update_flag = False # reset the flag after updating

def save_restore_firewall_rules (script_path, vm_name, flag):
    """Save/Restore firewall rule of a single host

    Args:
        script_path (str): address of add firewall rule script
        vm_name (str): name of virtual machine
        flag (str): save or restore option
    """
    
    command = f"expect {script_path} {vm_name} {flag}"

    # Execute script
    execute_script(command)

def save_restore_firewall_rules_all_hosts(flag):
    """Save/Restore firewall rule of all hosts

    Args:
        vm_name (str): name of virtual machine
        network_id (id): the index of cyberrange
        flag (str): save or restore option
    """

    if scenario is None:
        raise ValueError("Scenario is not initialized. Please initialize the scenario before calling save_restore_firewall_rules_all_hosts.")

    script_path = 'pengym/envs/scripts/save_restore_firewall_rule.exp'
    
    hosts = list(scenario.hosts.keys())

    for host in hosts:
        vm_name = host_map[host][storyboard.KVM_DOMAIN]
        save_restore_firewall_rules(script_path, vm_name, flag)

def add_firewall_rules (script_path, vm_name, bridge_IP):
    """Add firewall rule to allow traffic from bridge point to a host

    Args:
        script_path (str): address of add firewall rule script
        vm_name (str): name of virtual machine
        bridge_IP (str): the IP address of bridge point
    """
    
    command = f"expect {script_path} {vm_name} {bridge_IP}"

    execute_script(command)

def add_firewall_rules_all_hosts (subnet_id):
    """Add firewall rules to allow traffic from bridge point to whole hosts in a subnet 
    when one of host within subnet is compromised

    Args:
        subnet_id (int): subnet index
    """

    if scenario is None:
        raise ValueError("Scenario is not initialized. Please initialize the scenario before calling add_firewall_rules_all_hosts.")

    script_path = 'pengym/envs/scripts/add_firewall_rule.exp'
    
    hosts = list(scenario.hosts.keys())

    for host in hosts:
        if host[0] == subnet_id:
            vm_name = host_map[host][storyboard.KVM_DOMAIN]

            for link, bridge_info in bridge_map.items():
                if str(subnet_id) in link:
                    bridge_ip = bridge_info[1]
                    add_firewall_rules(script_path, vm_name, bridge_ip)

def open_firewall_rule_e_samba(host):
    """Open the firewall of current host for executing samba-based exploit action
    It is used as a temporary solution because of an unknown port that the Metasploit module uses to execute actions using the samba service

    Args:
        host (tuple): Current host address
    """
    script_path = 'pengym/envs/scripts/open_firewall_rule.exp'
    
    vm_name = host_map[host][storyboard.KVM_DOMAIN]
    add_firewall_rules(script_path, vm_name, None)

def update_default_gw(target_host, bridge_ip):
    """Update the active default gw of a host

    Args:
        target_host (tuple): host need to update gw
        bridge_ip (str): ip address of bridge that is active
    """
    # In thông tin đầu vào
    logger.debug(f"[DEBUG GW] Bắt đầu cập nhật default gateway cho host {target_host}")
    logger.debug(f"[DEBUG GW] Sử dụng bridge IP: {bridge_ip}")

    script_path = 'pengym/envs/scripts/del_add_default_gw.exp'
    vm_name = host_map[target_host][storyboard.KVM_DOMAIN]
    
    # In thông tin các biến được sử dụng
    logger.debug(f"[DEBUG GW] Đường dẫn script: {script_path}")
    logger.debug(f"[DEBUG GW] Tên máy ảo: {vm_name}")
    
    command = f'expect {script_path} {vm_name} {bridge_ip}'
    logger.debug(f"[DEBUG GW] Lệnh thực thi: {command}")

    # Kiểm tra xem máy ảo có đang chạy không
    try:
        check_vm_cmd = f"virsh domstate {vm_name}"
        result = subprocess.run(check_vm_cmd, shell=True, capture_output=True, text=True)
        logger.debug(f"[DEBUG GW] Trạng thái máy ảo: {result.stdout.strip()}")
        
        if "running" not in result.stdout:
            logger.debug(f"[DEBUG GW] CẢNH BÁO: Máy ảo {vm_name} không ở trạng thái running")
    except Exception as e:
        logger.debug(f"[DEBUG GW] Lỗi khi kiểm tra trạng thái máy ảo: {e}")

    # Execute script
    try:
        logger.debug(f"[DEBUG GW] Bắt đầu thực thi script...")
        execute_script(command)
        logger.debug(f"[DEBUG GW] Đã thực thi script thành công")
    except Exception as e:
        logger.debug(f"[DEBUG GW] Lỗi khi thực thi script: {e}")
        raise  # Truyền lỗi lên cấp cao hơn

    logger.debug(f"[DEBUG GW] Hoàn thành cập nhật default gateway cho host {target_host}")
    
def check_and_update_available_gw(target_host):
    """Check if the current default gw of the currennt host is active or not; 
    Update the default gw of the current host to active address 
    It is used to check the pre condition of exploit action

    Args:
        target_host (tuple): host need to update gw
    """
    logger.debug(f"[DEBUG GW] Bắt đầu kiểm tra và cập nhật gateway cho host {target_host}")
    subnet = target_host[0]
    logger.debug(f"[DEBUG GW] Subnet ID của host: {subnet}")
    
    # Lấy thông tin host hiện tại để debug
    vm_name = host_map[target_host][storyboard.KVM_DOMAIN]
    logger.debug(f"[DEBUG GW] Máy ảo: {vm_name}")
    logger.debug(f"[DEBUG GW] Trạng thái DEFAULT_GW hiện tại: {host_map[target_host][storyboard.DEFAULT_GW]}")
    
    # Hiển thị thông tin bridge_map để debug
    logger.debug(f"[DEBUG GW] Danh sách bridge_map: {bridge_map}")
    
    # Get list of connected bridge to this host
    found_bridge = False
    for link, bridge_info in bridge_map.items():
        logger.debug(f"[DEBUG GW] Kiểm tra link: {link}, bridge_info: {bridge_info}")
        if str(subnet) in link:
            logger.debug(f"[DEBUG GW] Tìm thấy link phù hợp với subnet {subnet}: {link}")
            bridge_name = bridge_info[0]
            logger.debug(f"[DEBUG GW] Tên bridge: {bridge_name}")
            
            # Kiểm tra trạng thái bridge
            bridge_status = check_bridge_status(bridge_name)
            logger.debug(f"[DEBUG GW] Trạng thái bridge {bridge_name}: {'UP' if bridge_status else 'DOWN'}")
            
            if bridge_status:
                logger.debug(f"[DEBUG GW] Bridge {bridge_name} đang hoạt động, cập nhật gateway cho host {target_host}")
                logger.debug(f"[DEBUG GW] Sử dụng IP bridge: {bridge_info[1]}")
                
                # Thêm try-except để bắt lỗi khi cập nhật gateway
                try:
                    update_default_gw(target_host, bridge_info[1])
                    host_map[target_host][storyboard.DEFAULT_GW] = True
                    logger.debug(f"[DEBUG GW] Đã cập nhật thành công gateway cho host {target_host}")
                    found_bridge = True
                    break
                except Exception as e:
                    logger.debug(f"[DEBUG GW] Lỗi khi cập nhật gateway: {e}")
                    raise Exception(f"Lỗi khi cập nhật gateway cho host {target_host}: {e}")
    
    if not found_bridge:
        logger.debug(f"[DEBUG GW] Không tìm thấy bridge hoạt động cho subnet {subnet}")
        raise Exception(f"Không tìm thấy bridge hoạt động cho subnet {subnet}")
    
    logger.debug(f"[DEBUG GW] Trạng thái DEFAULT_GW sau khi cập nhật: {host_map[target_host][storyboard.DEFAULT_GW]}")

def map_services_to_ports(services: Dict[str, bool], subnet=False):
    """Mapping list of services to list of corresponding ports
    Args:
        services (Dict[str, bool]): list of services
        subnet (bool, optional): Subnet flag
        True if want to return list of subnet IP addresses. Defaults to False

    Returns:
        port_list (list): list of corresponding ports
    """
    
    if service_port_map is None:
        raise Exception("Service port map is not initialized. Please initialize the service port map before calling map_services_to_ports.")
    
    port_list = list()

    for service in services:
        if (subnet):
            port = service_port_map[service]
            port_list.append(port)
        else:
            if services[service] == True:
                port = service_port_map[service]
                port_list.append(port)
    
    return port_list

def replace_file_path(database, file_name):
    """Replace the file name by corresponding path that pre-defined in config file
    
    Args:
        database (dict): database that get from config file
        file_name (str): name of file

    Returns:
        (str): file path that is replaced scenario value and pengym_source value
    """
    # Lấy đường dẫn cơ bản từ database
    path = database[storyboard.FILE_PATH][file_name]
    
    # Chỉ thay thế các pattern cần thiết
    if storyboard.SCENARIO_NAME in database:
        path = path.replace(storyboard.SCENARIO_NAME_PATTERN, database[storyboard.SCENARIO_NAME])
    
    if storyboard.PENGYM_SOURCE in database:
        path = path.replace(storyboard.PENGYM_SOURCE_PATTERN, database[storyboard.PENGYM_SOURCE])
    
    if storyboard.RANGE_ID in database:
        path = path.replace(storyboard.RANGE_ID_PATTERN, str(database[storyboard.RANGE_ID]))
    
    # Loại bỏ hoàn toàn CYBER_RANGE_DIR_PATTERN (nếu có)
    path = path.replace(storyboard.CYBER_RANGE_DIR_PATTERN, "")
    
    return path