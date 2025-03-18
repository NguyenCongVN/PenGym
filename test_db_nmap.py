import time
import sys
import pengym.utilities as utils
from pengym.storyboard import Storyboard

def test_db_nmap_functionality(config_path, target_host="127.0.0.1"):
    """
    Kiểm tra chức năng db_nmap thông qua kết nối MSF RPC
    
    Args:
        config_path: Đường dẫn đến file cấu hình
        target_host: Địa chỉ IP để quét thử (mặc định 127.0.0.1)
    
    Returns:
        bool: True nếu db_nmap hoạt động tốt, False nếu không
    """
    print("=== Kiểm tra db_nmap thông qua MSF RPC ===")
    
    # Khởi tạo cấu hình
    print(f"* Đọc cấu hình từ '{config_path}'...")
    utils.init_config_info(config_path)
    
    # Kết nối đến MSF RPC
    try:
        print("* Kết nối đến MSF RPC...")
        utils.init_msfrpc_client()
    except Exception as e:
        print(f"* LỖI: Không thể kết nối đến MSF RPC: {e}")
        return False
    
    # Kiểm tra kết nối tới cơ sở dữ liệu Metasploit
    try:
        print("* Kiểm tra kết nối tới cơ sở dữ liệu Metasploit...")
        # Tạo console mới để gửi lệnh
        console_id = utils.msfrpc_client.consoles.console().cid
        console = utils.msfrpc_client.consoles.console(console_id)
        
        # Gửi lệnh kiểm tra trạng thái DB
        console.write('db_status\n')
        
        # Đợi lệnh hoàn tất
        while console.is_busy():
            time.sleep(0.5)
        
        # Đọc kết quả
        output = console.read()
        
        # Kiểm tra các chuỗi thông báo kết nối thành công
        db_connected = any(phrase in output['data'].lower() for phrase in [
            "postgresql connected",
            "connected to msf",
            "connection type: postgresql"
        ])
        
        if db_connected:
            print("* CƠ SỞ DỮ LIỆU: PostgreSQL đã kết nối")
        else:
            print(f"* CẢNH BÁO: Cơ sở dữ liệu không được kết nối hoặc trả về trạng thái không xác định")
            print(f"* Kết quả: {output['data']}")
            if "database not connected" in output['data'].lower():
                print("* Hãy đảm bảo PostgreSQL đang chạy và đã được kết nối với Metasploit")
                print("* Gợi ý: Chạy 'msfdb init' để khởi tạo cơ sở dữ liệu")
                utils.msfrpc_client.consoles.destroy(console_id)
                return False
    except Exception as e:
        print(f"* LỖI: Không thể kiểm tra trạng thái cơ sở dữ liệu: {e}")
        if hasattr(utils.msfrpc_client, 'consoles'):
            try:
                utils.msfrpc_client.consoles.destroy(console_id)
            except:
                pass
        return False
    
    # Xóa dữ liệu cũ của host mục tiêu (nếu có)
    try:
        print(f"* Xóa dữ liệu cũ về host {target_host} (nếu có)...")
        delete_cmd = f"hosts -d {target_host}\n"
        console.write(delete_cmd)
        while console.is_busy():
            time.sleep(0.5)
        console.read()  # Đọc và bỏ qua kết quả
    except Exception as e:
        print(f"* CẢNH BÁO: Không thể xóa dữ liệu cũ: {e}")
        # Tiếp tục thực hiện quét - không phải lỗi nghiêm trọng
    
    # Thực hiện quét db_nmap
    try:
        print(f"\n* Thực hiện quét db_nmap trên {target_host}...")
        db_nmap_cmd = f"db_nmap -sV -p 22,80,443 {target_host}\n"
        print(f"  Lệnh: {db_nmap_cmd.strip()}")
        
        # Gửi lệnh db_nmap
        console.write(db_nmap_cmd)
        
        # Đợi lệnh hoàn thành
        print("  Đang quét... ", end="", flush=True)
        dots = 0
        max_dots = 3
        while console.is_busy():
            time.sleep(1)
            dots = (dots + 1) % (max_dots + 1)
            print("\r  Đang quét" + "." * dots + " " * (max_dots - dots), end="", flush=True)
        
        print("\r  Quét hoàn tất!                      ")
        
        # Đọc kết quả quét db_nmap
        output = console.read()
        scan_output = output['data']
        
        print("\n=== Kết quả quét db_nmap ===")
        print(scan_output)
        
        # Kiểm tra xem quét có thành công không
        if "nmap scan report for" not in scan_output.lower():
            print("* CẢNH BÁO: Không thấy báo cáo quét db_nmap trong kết quả")
            
    except Exception as e:
        print(f"\n* LỖI: Không thể thực hiện quét db_nmap: {e}")
        utils.msfrpc_client.consoles.destroy(console_id)
        return False
    
    # Truy vấn kết quả từ cơ sở dữ liệu
    try:
        print("\n* Lấy dữ liệu host từ cơ sở dữ liệu...")
        # Lấy danh sách hosts
        console.write("hosts\n")
        while console.is_busy():
            time.sleep(0.5)
        hosts_output = console.read()
        
        # Lấy danh sách services
        console.write("services\n")
        while console.is_busy():
            time.sleep(0.5)
        services_output = console.read()
        
        # Hiển thị danh sách hosts và services từ cơ sở dữ liệu
        print("\n=== Hosts đã lưu trong cơ sở dữ liệu ===")
        print(hosts_output['data'])
        
        print("\n=== Services đã lưu trong cơ sở dữ liệu ===")
        print(services_output['data'])
        
        # Kiểm tra thành công dựa trên kết quả từ cơ sở dữ liệu
        success = target_host in hosts_output['data']
        
        # Thử truy vấn kết quả thông qua các lệnh console thay vì API trực tiếp
        print("\n* Kiểm tra thêm thông tin về host...")
        try:
            # Lấy thêm thông tin về host cụ thể
            console.write(f"hosts -c address,os_name,state -S {target_host}\n")
            while console.is_busy():
                time.sleep(0.5)
            host_details = console.read()
            
            if target_host in host_details['data']:
                print(f"  Host {target_host} đã được lưu trong cơ sở dữ liệu")
                print(f"  Chi tiết:\n{host_details['data']}")
                success = True
            else:
                print(f"  Không tìm thấy thông tin chi tiết về host {target_host}")
                
        except Exception as cmd_error:
            print(f"  CẢNH BÁO: Không thể lấy thông tin chi tiết về host: {cmd_error}")
            
    except Exception as e:
        print(f"* LỖI: Không thể truy vấn cơ sở dữ liệu: {e}")
        success = False
    
    # Xóa console để giải phóng tài nguyên
    try:
        utils.msfrpc_client.consoles.destroy(console_id)
    except Exception as e:
        print(f"* CẢNH BÁO: Không thể hủy console: {e}")
    
    return success

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Sử dụng: python test_db_nmap.py <CONFIG_FILE> [TARGET_HOST]")
        sys.exit(1)
    
    config_path = sys.argv[1]
    target_host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    
    result = test_db_nmap_functionality(config_path, target_host)
    
    if result:
        print("\n✅ TEST THÀNH CÔNG: db_nmap hoạt động tốt qua MSF RPC!")
        sys.exit(0)
    else:
        print("\n❌ TEST THẤT BẠI: db_nmap không hoạt động qua MSF RPC!")
        sys.exit(1)