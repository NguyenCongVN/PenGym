import logging
import os
from datetime import datetime

# Tạo thư mục logs nếu chưa tồn tại
if not os.path.isdir('./logs'):
    os.makedirs('./logs', exist_ok=True)

# Tạo logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Logger gốc giữ mức DEBUG để bắt tất cả

# Tạo handlers
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)

# Tạo tên file log với timestamp
timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
debug_log_filename = f"./logs/app_debug_{timestamp}.log"
info_log_filename = f"./logs/app_info_{timestamp}.log"  # File mới cho mức INFO trở lên

# Handler cho file debug (lưu tất cả các log từ DEBUG trở lên)
debug_file_handler = logging.FileHandler(debug_log_filename, encoding='utf-8')
debug_file_handler.setLevel(logging.DEBUG)

# Handler cho file info (chỉ lưu từ INFO trở lên)
info_file_handler = logging.FileHandler(info_log_filename, encoding='utf-8')
info_file_handler.setLevel(logging.INFO)  # Chỉ ghi log từ mức INFO trở lên

# Tạo formatters
console_formatter = logging.Formatter('%(levelname)s: %(message)s')
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s: %(message)s')

# Gán formatters cho handlers
console_handler.setFormatter(console_formatter)
debug_file_handler.setFormatter(file_formatter)
info_file_handler.setFormatter(file_formatter)  # Dùng chung định dạng với file debug

# Thêm handlers vào logger
logger.addHandler(console_handler)
logger.addHandler(debug_file_handler)
logger.addHandler(info_file_handler)  # Thêm handler mới vào logger

# Ví dụ sử dụng
def main() -> None:
    logger.info("Ứng dụng bắt đầu")
    logger.debug("Thông tin debug chi tiết")  # Chỉ xuất hiện trong file debug
    try:
        result = 10 / 0
    except Exception as e:
        logger.error(f"Lỗi xảy ra: {e}")  # Xuất hiện ở cả hai file
    logger.warning("Đây là cảnh báo")  # Xuất hiện ở cả hai file
    logger.info("Ứng dụng kết thúc")

if __name__ == "__main__":
    main()