# Import libraries
import pengym.utilities as utils
import logging
import time

from nasim.envs.network import Network
from nasim.envs.action import ActionResult
from pengym.storyboard import Storyboard

storyboard = Storyboard()

class PenGymNetwork(Network):
    """The network for a given scenario. The PenGymNetwork class is derived from the NASim Network one.

    Args:
        Network: Network Class of NASim
    """

    def perform_action(self, state, action):
        """Perform the given action against the network.

        Args:
            state (State): the current state of the network
            action (Action): the action to perform

        Returns:
            State: the state of the host after the action is performed
            ActionObservation: the result of the action
        """
        utils.current_state = state # Get the current state of the network

        start = time.time()
        next_state, obs = super().perform_action(state, action)
        end = time.time()
        # Catch actions that did not succeed in the superclass function
        # PENGYM_ERROR is used to check if this error comes from PenGym or not; consequently we do not print a failure
        # that occured in the super function if the error has already been printed in a PenGym function
        if not obs.success and not utils.PENGYM_ERROR:
            utils.print_failure(action, obs, storyboard.TAG_NASIM_PENGYM, end-start)

        return next_state, obs

    def _perform_subnet_scan(self, next_state, action):
        """Perform subnet scan on this network. This function overrides _perform_subnet_scan() in NASim Network.

        Args:
            next_state (PenGymState): the current state of the network
            action (Action): the action to perform

        Returns:
            PenGymHostVector: the state of the host after the action is performed
            ActionObervation: the result of the action
        """

        # Set tags to differentiate between PenGym and NASim actions
        # only if both of them are enabled
        if utils.ENABLE_PENGYM and utils.ENABLE_NASIM:
            tag_pengym = storyboard.TAG_PENGYM
            tag_nasim = storyboard.TAG_NASIM
        else:
            tag_pengym = ""
            tag_nasim = ""

        utils.PENGYM_ERROR = False # Reset the value of PenGym Error

        # PenGym execution
        if utils.ENABLE_PENGYM:
            start = time.time()
            # Check if host is compromised from NAsim
            if not next_state.host_compromised(action.target):
                result = ActionResult(False, connection_error=True) # NASim code: ActionResult(False, 0.0, connection_error=True)
                utils.PENGYM_ERROR = True
                end = time.time()
                utils.print_failure(action, result, storyboard.PENGYM, end-start)

            else:

                # Map host address to IP address
                subnet_ips = utils.map_host_address_to_IP_address(utils.host_map, action.target, subnet=True)

                #Get list of available port in current network environment
                scenario_services = utils.scenario.services
                ports = utils.map_services_to_ports(scenario_services, subnet=True)

                # Get list of hosts in scenario
                scenario_hosts = list(utils.scenario.hosts.keys())

                # Update discovered host list
                if (action.target not in utils.host_is_discovered):
                    utils.host_is_discovered.append(action.target)

                # Do subnet scan
                subnet_scan_result = utils.host_map[action.target][storyboard.SUBNET]

                if (subnet_scan_result is None):
                    subnet_scan_result = self.do_subnet_scan(subnet_ips, ports)
                    utils.host_map[action.target][storyboard.SUBNET] = subnet_scan_result

                # Map the discovered IP address to host address
                discovered_list = utils.map_IP_adress_to_host_address(utils.host_map, subnet_scan_result)
                discovered_dict = utils.map_result_list_to_dict(discovered_list, scenario_hosts, bool=True)

                end = time.time()

                # Update the state of host 
                if subnet_scan_result:
                    discovered2 = {}
                    newly_discovered2 = {}
                    discovery_reward = 0
                    target_subnet = action.target[0]

                    for h_addr in self.address_space:
                        newly_discovered2[h_addr] = False
                        discovered2[h_addr] = False

                        if self.subnets_connected(target_subnet, h_addr[0]):
                            host = next_state.get_host(h_addr)
                            discovered2[h_addr] = True

                            if not host.discovered:
                                newly_discovered2[h_addr] = True
                                host.discovered = True
                                discovery_reward += host.discovery_value

                    # Print the result
                    result = ActionResult(True, value=discovery_reward, discovered=discovered_dict,
                                          newly_discovered=self.define_newly_discovered_hosts(discovered_list))
                    print(f"  Host {action.target} Action '{action.name}' SUCCESS: discovered={result.discovered} newly_discovered={result.newly_discovered} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_subnet_scan(): {subnet_scan_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, end-start)

                # Update host_is_discovered list
                self.update_host_is_discovered_list(discovered_list)

        # NASim execution
        # NOTE: This may not work correctly when both PenGym and NASim are active,
        # since the update state function is duplicated
        if utils.ENABLE_NASIM:
            start = time.time()
            next_state, result = super()._perform_subnet_scan(next_state, action)
            end = time.time()
            if result.success:
                print(f"  Host {action.target} Action '{action.name}' SUCCESS: discovered={result.discovered} newly_discovered={result.newly_discovered} Execution Time: {end-start:1.6f}{tag_nasim}")
            else:
                utils.print_failure(action, result, storyboard.NASIM, end-start)

        return next_state, result

    # # Override function in NASim
    # def traffic_permitted(self, state, host_addr, service):
    #     """Checks whether the subnet and host firewalls permits traffic to a
    #     given host using this service, based on current set of compromised hosts on
    #     network.
        
    #     Args:
    #         state (State): the current state of environment
    #         host_addr (tuple): host address
    #         service (str): service name
    #     """
    #     for src_addr in self.address_space:
    #         src_compromised = state.host_compromised(src_addr)
    #         if not state.host_compromised(src_addr) and \
    #            not self.subnet_public(src_addr[0]):
    #             continue
    #         if not self.subnet_traffic_permitted(
    #                 src_addr[0], host_addr[0], service, src_compromised
    #         ):
    #             continue
    #         if self.host_traffic_permitted(src_addr, host_addr, service):
    #             return True
    #     return False
    
    def traffic_permitted(self, state, host_addr, service):
        """Checks whether traffic is permitted based on iptables rules
        """
        # Trong môi trường NAT với iptables, các quy tắc đã được cấu hình
        # nên chúng ta chỉ cần kiểm tra liệu luồng lưu lượng có được cho phép 
        # dựa trên mô hình scenario
        return self.subnet_traffic_permitted(host_addr[0], self._target[0], service, True)
    
    # Revise for issue in NASim (since with current version of python, nasim is updated an can not modify)
    def subnet_traffic_permitted(self, src_subnet, dest_subnet, service, src_compromised=True):
        """Checks whether the subnet firewalls permits traffic to a specific service
        
        Args:
            src_subnet (int): source subnet
            dest_subnet (int): destination subnet
            service (str): service name
            src_compromised (bool, optional): True if there is a compromised host within source subnet
        """
        if src_subnet == dest_subnet:
            
            # NOTE: After new version of NASim release -> Change: Check in case internet and subnet 1 (for example exploit any host in subnet1 that firewall is not allowed)
            if src_compromised:
                return True

            if self.subnet_public(src_subnet) and not service in self.firewall[(0, dest_subnet)]:
                return False
            
            # in same subnet so permitted
            return True
        if not self.subnets_connected(src_subnet, dest_subnet):
            return False
        return service in self.firewall[(src_subnet, dest_subnet)]
    
    def has_required_remote_permission(self, state, action):
        """Checks attacker has necessary permissions for remote action 
        
        Args:
            state (State): the current state of the network
            action (Action): the action to perform
        """

        if self.subnet_public(action.target[0]):
            return True

        # NOTE: Add new check same host in exploit_remote
        for src_addr in self.address_space:
            if not state.host_compromised(src_addr):
                continue
            if action.is_scan() and \
               not self.subnets_connected(src_addr[0], action.target[0]):
                continue
           
            if action.is_exploit() and \
               (not self.subnet_traffic_permitted(
                   src_addr[0], action.target[0], action.service)
                or src_addr == action.target):
                continue
            
            if state.host_has_access(src_addr, action.req_access):
                return True
        
        return False

    def do_subnet_scan(self, subnet_address, ports=False):
        """Perform the subnet scan using db_nmap

        Args:
            subnet_address (str): string of subnet address
            ports (list): list of ports to be scanned

        Returns:
            hosts_list (list): list of hosts in connected subnet
        """
        # Sử dụng db_nmap qua MSF RPC
        args = "-Pn -n -sS -T5 --min-parallelism 100 --max-parallelism 100"
        
        # Chuyển danh sách cổng nếu có
        ports_str = None
        if ports:
            if isinstance(ports, list):
                ports_str = ','.join(str(port) for port in ports)
            else:
                ports_str = ports
        
        # Chạy quét qua MSF
        result = utils.run_db_nmap(subnet_address, ports_str, args)
        
        if result is None:
            return []
        
        # Phân tích hosts từ kết quả MSF
        hosts_list = []
        host_lines = result['hosts'].strip().split('\n')
        for line in host_lines[2:]:  # Bỏ qua dòng tiêu đề
            parts = line.split()
            if len(parts) >= 1:
                host_ip = parts[0]
                hosts_list.append(host_ip)
                    
        return hosts_list

    def define_newly_discovered_hosts(self, discovery_host_list):
        """Define the list of newly discovered hosts from list of discovered hosts

        Args:
            discovery_host_list (list): list of host discovered via the subnet scan

        Returns:
            newly_discovered (list): list of newly discovered hosts
        """
        total_host_list = utils.host_map.keys()

        newly_discovered = dict()

        for host in total_host_list:
            newly_discovered[host] = (host not in utils.host_is_discovered) and (host in discovery_host_list)

        return newly_discovered

    def update_host_is_discovered_list(self, discovery_host_list):
        """Update the list of discovered host

        Args:
            discovery_host_list (list): list of hosts discovered after the subnet scan
        """
        for host in discovery_host_list:
            if host not in utils.host_is_discovered:
                utils.host_is_discovered.append(host)
