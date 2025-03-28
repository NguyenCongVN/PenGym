def test_metasploit_execution(host_vector, msfrpc_client, target_host):
    """
    Kiểm tra kết quả thực thi tấn công SSH qua Metasploit
    
    Args:
        host_vector: Đối tượng PenGymHostVector
        msfrpc_client: Kết nối tới Metasploit RPC
        target_host: Địa chỉ IP của máy chủ mục tiêu
        
    Returns:
        bool: True nếu tấn công thành công, False nếu thất bại
    """
    # Thực hiện tấn công SSH
    result = host_vector.do_e_ssh(msfrpc_client, target_host)
    
    print("=== KẾT QUẢ THỰC THI ===")
    print(f"Trạng thái: {'THÀNH CÔNG' if result.get('success', False) else 'THẤT BẠI'}")
    
    # Kiểm tra lỗi
    if "error" in result and result["error"]:
        print(f"Lỗi: {result.get('error_message', 'Không xác định')}")
    
    # Hiển thị thông tin về job 
    print(f"Job ID: {result.get('job_id', 'Không có')}")
    
    # Kiểm tra thời gian chờ
    if result.get("timed_out", False):
        print(f"Đã hết thời gian chờ ({result.get('timeout', 60)} giây)")
    
    # Hiển thị thông tin về session
    if "new_sessions" in result and result["new_sessions"]:
        print(f"Sessions mới tạo: {', '.join(map(str, result['new_sessions']))}")
        
        # Hiển thị chi tiết session
        for session_id in result["new_sessions"]:
            session_info = result["session_details"].get(session_id, {})
            print(f"  - Session {session_id}: {session_info.get('type')} tới {session_info.get('target_host')}")
    
    # Hiển thị credentials (nếu có)
    if "credentials_found" in result and result["credentials_found"]:
        print("\n=== CREDENTIALS TÌM THẤY ===")
        for cred in result["credentials_found"]:
            print(f"Username: {cred.get('user')}, Password: {cred.get('pass')}")
    
    # Hiển thị output từ console
    if "console_output" in result and result["console_output"]:
        print("\n=== OUTPUT TỪ CONSOLE ===")
        print(result["console_output"])
    
    # Trả về kết quả thành công hay thất bại
    return result.get("success", False)

# Một ví dụ về cách sử dụng hàm kiểm tra
def run_metasploit_test():
    """Chạy kiểm tra một tấn công SSH bằng Metasploit"""
    
    from pymetasploit3.msfrpc import MsfRpcClient
    import time
    
    # Kết nối tới Metasploit RPC
    try:
        # Thay đổi thông tin kết nối nếu cần
        msfrpc_client = MsfRpcClient('password', server='127.0.0.1', port=55553)
        print("Đã kết nối thành công tới Metasploit RPC")
    except Exception as e:
        print(f"Lỗi kết nối tới Metasploit RPC: {str(e)}")
        return False
    
    # Khởi tạo đối tượng host_vector
    # Giả sử PenGymHostVector đã được import
    host_vector = PenGymHostVector(...)  # Khởi tạo đối tượng theo cấu trúc của bạn
    
    # Thực hiện kiểm tra với một địa chỉ IP mục tiêu
    target_host = "192.168.1.100"  # Thay đổi IP này thành mục tiêu thực tế
    
    # Bắt đầu thời gian
    start_time = time.time()
    
    # Chạy test
    success = test_metasploit_execution(host_vector, msfrpc_client, target_host)
    
    # Kết thúc thời gian và tính toán
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\nTổng thời gian thực thi: {elapsed_time:.2f} giây")
    print(f"Kết quả thực thi: {'THÀNH CÔNG' if success else 'THẤT BẠI'}")
    
    return success

# Chạy test khi script được thực thi trực tiếp
if __name__ == "__main__":
    run_metasploit_test()