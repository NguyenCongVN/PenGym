import random
import numpy as np
import time
from collections import defaultdict
import pickle
import os

import torch
from torch.utils.tensorboard import SummaryWriter

from logger import logger

class TabularQFunction:
    """Bảng Q-Function cho Q-Learning
    
    Lưu trữ giá trị Q(s,a) trong một dictionary, giúp tối ưu việc tra cứu
    cho không gian trạng thái lớn và rời rạc.
    """

    def __init__(self, num_actions):
        # Sử dụng defaultdict để tự động khởi tạo giá trị cho các trạng thái mới
        self.q_table = defaultdict(lambda: np.zeros(num_actions, dtype=np.float32))
        self.num_actions = num_actions

    def __call__(self, state):
        """Tra cứu giá trị Q cho một trạng thái"""
        return self.forward(state)

    def forward(self, state):
        """Lấy giá trị Q cho state được cho"""
        # Chuyển đổi state thành key cho dictionary
        state_key = self._get_state_key(state)
        return self.q_table[state_key]

    def _get_state_key(self, state):
        """Chuyển đổi state thành key để lưu trong dictionary"""
        if isinstance(state, np.ndarray):
            # Sử dụng str của array làm key
            return str(state.astype(np.int_))
        return str(state)

    def update(self, state, action, delta):
        """Cập nhật giá trị Q(s,a) với delta"""
        state_key = self._get_state_key(state)
        self.q_table[state_key][action] += delta

    def get_action(self, state):
        """Lấy hành động tốt nhất cho state dựa trên giá trị Q"""
        return int(self.forward(state).argmax())

    def save(self, path):
        """Lưu Q-table vào file"""
        # Chuyển defaultdict thành dict thường để lưu
        q_dict = dict(self.q_table)
        with open(path, 'wb') as f:
            pickle.dump(q_dict, f)
        logger.info(f"Đã lưu Q-table với {len(q_dict)} trạng thái vào {path}")

    def load(self, path):
        """Tải Q-table từ file"""
        if os.path.exists(path):
            with open(path, 'rb') as f:
                q_dict = pickle.load(f)
                # Chuyển từ dict thành defaultdict
                self.q_table = defaultdict(lambda: np.zeros(self.num_actions, dtype=np.float32))
                for k, v in q_dict.items():
                    self.q_table[k] = v
            logger.info(f"Đã tải Q-table với {len(q_dict)} trạng thái từ {path}")
            return True
        else:
            logger.error(f"Không tìm thấy file Q-table: {path}")
            return False


class TabularQLearningAgent:
    """Agent học tăng cường sử dụng thuật toán Q-Learning với bảng Q"""

    def __init__(self, env,
                 learning_rate=0.1,
                 gamma=0.99,
                 epsilon_start=1.0,
                 epsilon_end=0.05,
                 epsilon_decay=0.995,
                 seed=None):
        """Khởi tạo Q-Learning agent
        
        Parameters:
        -----------
        env : pengym.PenGymEnv
            Môi trường PenGym
        learning_rate : float
            Tốc độ học (alpha trong công thức cập nhật Q-value)
        gamma : float
            Hệ số chiết khấu cho phần thưởng tương lai
        epsilon_start : float
            Giá trị epsilon ban đầu cho chính sách ε-greedy
        epsilon_end : float
            Giá trị epsilon tối thiểu
        epsilon_decay : float
            Tốc độ giảm epsilon
        seed : int
            Hạt giống cho sinh số ngẫu nhiên
        """
        # Thiết lập môi trường
        self.env = env
        self.num_actions = self.env.action_space.n
        self.obs_dim = self.env.observation_space.shape
        
        # Thiết lập các tham số học
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        
        # Thiết lập seed nếu có
        self.seed = seed
        if self.seed is not None:
            np.random.seed(self.seed)
            random.seed(self.seed)
        
        # Khởi tạo Q-function
        self.q_function = TabularQFunction(self.num_actions)
        
        # Khởi tạo tensorboard writer
        self.writer = SummaryWriter(comment=f"_QL_lr{learning_rate}_g{gamma}")
        
        # Theo dõi số bước đã thực hiện
        self.steps = 0
        
        logger.info(f"Khởi tạo Q-Learning agent với {self.num_actions} hành động")
        logger.info(f"Tham số: lr={learning_rate}, gamma={gamma}, epsilon={epsilon_start}->{epsilon_end}")

    def select_action(self, state, eval_mode=False):
        """Chọn hành động dựa trên chính sách ε-greedy
        
        Parameters:
        -----------
        state : numpy.ndarray
            Trạng thái hiện tại
        eval_mode : bool
            Nếu True, sử dụng epsilon thấp hơn cho đánh giá
            
        Returns:
        --------
        int
            Chỉ số hành động được chọn
        """
        # Đặt epsilon thấp hơn trong chế độ đánh giá
        epsilon = 0.01 if eval_mode else self.epsilon
        
        # Chọn hành động ngẫu nhiên với xác suất epsilon
        if random.random() < epsilon:
            return random.randrange(self.num_actions)
        
        # Chọn hành động tốt nhất dựa trên Q-values
        return self.q_function.get_action(state)

    def update_q_value(self, state, action, reward, next_state, done):
        """Cập nhật Q-value sử dụng công thức Q-Learning
        
        Parameters:
        -----------
        state : numpy.ndarray
            Trạng thái hiện tại
        action : int
            Hành động đã thực hiện
        reward : float
            Phần thưởng nhận được
        next_state : numpy.ndarray
            Trạng thái tiếp theo
        done : bool
            Cờ đánh dấu kết thúc
            
        Returns:
        --------
        float
            TD error (sai số khác biệt thời gian)
        """
        # Lấy giá trị Q hiện tại cho cặp (state, action)
        current_q = self.q_function.forward(state)[action]
        
        # Lấy giá trị Q tối đa có thể đạt được ở trạng thái tiếp theo
        next_max_q = np.max(self.q_function.forward(next_state)) if not done else 0
        
        # Tính toán giá trị mục tiêu sử dụng công thức Bellman
        target_q = reward + self.gamma * next_max_q
        
        # Tính toán sai số TD
        td_error = target_q - current_q
        
        # Cập nhật Q-value
        delta = self.learning_rate * td_error
        self.q_function.update(state, action, delta)
        
        return td_error

    def train(self, num_episodes, max_steps_per_episode=1000, DEBUG_STEP=False):
        """Huấn luyện agent sử dụng Q-Learning
        
        Parameters:
        -----------
        num_episodes : int
            Số lượng tập huấn luyện
        max_steps_per_episode : int
            Số bước tối đa cho mỗi tập
        DEBUG_STEP : bool
            Nếu True, sẽ chạy từng bước và đợi người dùng nhấn Enter để tiếp tục
            
        Returns:
        --------
        list
            Danh sách phần thưởng cho mỗi tập
        """
        episode_rewards = []
        total_steps = 0
        
        logger.info(f"Bắt đầu huấn luyện Q-Learning trong {num_episodes} tập...")
        if DEBUG_STEP:
            logger.info("Chế độ DEBUG_STEP được bật. Nhấn Enter để thực hiện từng bước.")
        start_time = time.time()
        
        for episode in range(num_episodes):
            # Reset môi trường
            state, _ = self.env.reset()
            total_reward = 0
            done = False
            truncated = False
            
            logger.info(f'***** Tập {episode + 1}/{num_episodes} *****')
            logger.info(f"Epsilon hiện tại: {self.epsilon:.4f}")
            
            for step in range(max_steps_per_episode):
                # Lấy giá trị Q hiện tại cho tất cả hành động
                if DEBUG_STEP:
                    current_q_values = self.q_function.forward(state)
                    logger.debug("\n---------- DEBUG STEP ----------")
                    logger.debug(f"Bước {step + 1}")
                    logger.debug(f"Giá trị Q hiện tại cho tất cả hành động:")
                    for a in range(self.num_actions):
                        action_obj = self.env.action_space.get_action(a)
                        logger.debug(f"  Hành động {a} ({action_obj}): Q = {current_q_values[a]:.4f}")
                    input("Nhấn Enter để chọn hành động...")
                
                # Chọn hành động
                action = self.select_action(state)
                
                # Lấy giá trị Q hiện tại cho hành động được chọn (trước khi cập nhật)
                if DEBUG_STEP:
                    current_q = self.q_function.forward(state)[action]
                    action_obj = self.env.action_space.get_action(action)
                    logger.debug(f"Đã chọn hành động {action} ({action_obj})")
                    logger.debug(f"Q hiện tại của hành động: {current_q:.4f}")
                    input("Nhấn Enter để thực hiện hành động...")
                
                # Log thông tin hành động
                action_obj = self.env.action_space.get_action(action)
                logger.info(f"Tập {episode + 1} - Bước {step + 1}: Thực hiện {action_obj}")
                
                # Thực hiện hành động
                next_state, reward, done, truncated, info = self.env.step(action)

                if DEBUG_STEP:
                    logger.debug(f"Nhận được phần thưởng: {reward}")
                    logger.debug(f"Trạng thái kết thúc? {done}")
                    logger.debug(f"Trạng thái bị cắt? {truncated}")
                    
                    # Kiểm tra sự thay đổi trạng thái
                    state_changed = False
                    if isinstance(state, np.ndarray) and isinstance(next_state, np.ndarray):
                        state_changed = not np.array_equal(state, next_state)
                    else:
                        state_changed = (state != next_state)
                    
                    logger.debug(f"Trạng thái có thay đổi? {state_changed}")
                    
                    if state_changed:
                        # Hiển thị chi tiết sự thay đổi nếu trạng thái là mảng numpy
                        if isinstance(state, np.ndarray) and isinstance(next_state, np.ndarray):
                            try:
                                # Tìm vị trí các phần tử khác nhau
                                diff_indices = np.where(state != next_state)
                                if len(diff_indices[0]) > 0:
                                    logger.debug("Chi tiết thay đổi trạng thái:")
                                    for idx in range(len(diff_indices[0])):
                                        pos = tuple(d[idx] for d in diff_indices)
                                        logger.debug(f"  Vị trí {pos}: {state[pos]} -> {next_state[pos]}")
                                        
                                        # Giới hạn số lượng thay đổi hiển thị để không quá nhiều
                                        if idx >= 10:
                                            logger.debug(f"  ... và {len(diff_indices[0]) - 10} thay đổi khác")
                                            break
                            except Exception as e:
                                logger.debug(f"Không thể hiển thị chi tiết thay đổi: {e}")
                    
                    input("Nhấn Enter để cập nhật giá trị Q...")

                # Cập nhật Q-values
                td_error = self.update_q_value(state, action, reward, next_state, done)
                
                # Hiển thị giá trị Q sau khi cập nhật
                if DEBUG_STEP:
                    updated_q = self.q_function.forward(state)[action]
                    logger.debug(f"Q sau khi cập nhật: {updated_q:.4f}")
                    logger.debug(f"TD Error: {td_error:.4f}")
                    logger.debug(f"Thay đổi: {updated_q - current_q:.4f}")
                    logger.debug("Nhấn Enter để tiếp tục sang bước tiếp theo...")
                
                # Cập nhật trạng thái và phần thưởng
                state = next_state
                total_reward += reward
                self.steps += 1
                total_steps += 1
                
                # Ghi log
                self.writer.add_scalar("td_error", td_error, self.steps)
                self.writer.add_scalar("reward", reward, self.steps)
                
                # Kiểm tra điều kiện kết thúc
                if done or truncated:
                    if DEBUG_STEP:
                        logger.debug("Tập huấn luyện kết thúc!")
                        logger.debug(f"Tổng phần thưởng: {total_reward:.2f}")
                        input("Nhấn Enter để tiếp tục tập mới...")
                    break
            
            # Giảm epsilon
            self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
            
            # Ghi log kết quả tập
            episode_rewards.append(total_reward)
            self.writer.add_scalar("episode_reward", total_reward, episode)
            self.writer.add_scalar("episode_length", step + 1, episode)
            self.writer.add_scalar("epsilon", self.epsilon, episode)
            
            # In thông tin sau mỗi tập
            logger.info(f"Tập {episode + 1}/{num_episodes} - Reward: {total_reward:.2f}, Bước: {step + 1}")
            
            # In thống kê mỗi 10 tập
            if (episode + 1) % 10 == 0:
                avg_reward = sum(episode_rewards[-10:]) / 10
                elapsed_time = time.time() - start_time
                logger.info(f"Thống kê sau {episode + 1} tập:")
                logger.info(f"  Reward TB (10 tập): {avg_reward:.2f}")
                logger.info(f"  Epsilon: {self.epsilon:.4f}")
                logger.info(f"  Thời gian: {elapsed_time/60:.1f} phút")
        
        # Kết thúc huấn luyện
        training_time = time.time() - start_time
        logger.info("===== Tổng kết huấn luyện =====")
        logger.info(f"Tổng số tập: {num_episodes}")
        logger.info(f"Tổng số bước: {total_steps}")
        logger.info(f"Reward trung bình: {sum(episode_rewards)/len(episode_rewards):.2f}")
        logger.info(f"Reward cao nhất: {max(episode_rewards):.2f}")
        logger.info(f"Thời gian huấn luyện: {training_time/60:.1f} phút")
        logger.info(f"Epsilon cuối: {self.epsilon:.4f}")
        
        self.writer.close()
        return episode_rewards

    def evaluate(self, num_episodes=5):
        """Đánh giá agent đã huấn luyện
        
        Parameters:
        -----------
        num_episodes : int
            Số lượng tập đánh giá
            
        Returns:
        --------
        tuple
            (avg_reward, success_rate): Phần thưởng trung bình và tỷ lệ thành công
        """
        episode_rewards = []
        successes = 0
        
        logger.info(f"Đánh giá Q-Learning agent trong {num_episodes} tập...")
        
        for episode in range(num_episodes):
            state, _ = self.env.reset()
            total_reward = 0
            done = False
            truncated = False
            step_count = 0
            
            while not done and not truncated:
                # Chọn hành động (ở chế độ đánh giá)
                action = self.select_action(state, eval_mode=True)
                action_obj = self.env.action_space.get_action(action)
                
                logger.info(f"- Bước {step_count + 1}: {action_obj}")
                
                # Thực hiện hành động
                next_state, reward, done, truncated, _ = self.env.step(action)
                
                # Cập nhật trạng thái và phần thưởng
                state = next_state
                total_reward += reward
                step_count += 1
                
                # Dừng nếu vượt quá số bước tối đa
                if step_count >= 150:  # MAX_STEPS từ run.py
                    logger.warning(f"Vượt quá số bước tối đa (150)")
                    break
            
            episode_rewards.append(total_reward)
            if done:
                successes += 1
                
            logger.info(f"Tập {episode + 1}/{num_episodes}, Reward: {total_reward:.2f}, Steps: {step_count}, Done: {done}")
        
        avg_reward = sum(episode_rewards) / num_episodes
        success_rate = successes / num_episodes
        
        logger.info(f"Kết quả đánh giá: Reward TB: {avg_reward:.2f}, Tỷ lệ thành công: {success_rate:.2f}")
        
        return avg_reward, success_rate

    def save(self, path):
        """Lưu mô hình Q-Learning
        
        Parameters:
        -----------
        path : str
            Đường dẫn file lưu mô hình
        """
        # Lưu Q-table
        self.q_function.save(path)
        
        # Lưu các tham số khác (epsilon, lr, gamma)
        params_path = f"{path}_params"
        with open(params_path, 'wb') as f:
            params = {
                'epsilon': self.epsilon,
                'learning_rate': self.learning_rate,
                'gamma': self.gamma,
                'steps': self.steps
            }
            pickle.dump(params, f)
        
        logger.info(f"Đã lưu tham số agent vào {params_path}")

    def load(self, path):
        """Tải mô hình Q-Learning đã lưu
        
        Parameters:
        -----------
        path : str
            Đường dẫn file mô hình
        """
        # Tải Q-table
        if not self.q_function.load(path):
            return False
        
        # Tải các tham số khác
        params_path = f"{path}_params"
        if os.path.exists(params_path):
            with open(params_path, 'rb') as f:
                params = pickle.load(f)
                self.epsilon = params['epsilon']
                self.learning_rate = params['learning_rate']
                self.gamma = params['gamma']
                self.steps = params['steps']
            logger.info(f"Đã tải tham số agent từ {params_path}")
            return True
        else:
            logger.warning(f"Không tìm thấy file tham số: {params_path}")
            return True  # Vẫn trả về True vì Q-table đã tải thành công

# Hàm chạy Q-Learning agent trong PenGym
def run_ql_agent(env, train=False, load_path=None, save_path=None, 
                num_train_episodes=90000, num_eval_episodes=5):
    """Chạy Q-Learning agent trong môi trường PenGym
    
    Parameters:
    -----------
    env : pengym.PenGymEnv
        Môi trường PenGym
    train : bool
        Có huấn luyện agent hay không
    load_path : str
        Đường dẫn file để tải mô hình (nếu có)
    save_path : str
        Đường dẫn file để lưu mô hình sau khi huấn luyện (nếu có)
    num_train_episodes : int
        Số lượng tập huấn luyện (nếu train=True)
    num_eval_episodes : int
        Số lượng tập đánh giá
        
    Returns:
    --------
    tuple
        (done, truncated, step_count): Trạng thái kết thúc và số bước đã thực hiện
    """
    # Khởi tạo Q-Learning agent
    agent = TabularQLearningAgent(
        env=env,
        learning_rate=0.1,
        gamma=0.99,
        epsilon_start=1.0,
        epsilon_end=0.05,
        epsilon_decay=0.995
    )
    
    # Tải mô hình nếu có
    if load_path:
        logger.info(f"Tải mô hình Q-Learning từ {load_path}...")
        agent.load(load_path)
    
    # Huấn luyện nếu yêu cầu
    if train:
        logger.info(f"Huấn luyện Q-Learning agent trong {num_train_episodes} tập...")
        agent.train(num_train_episodes)
        
        # Lưu mô hình nếu có đường dẫn
        if save_path:
            logger.info(f"Lưu mô hình Q-Learning vào {save_path}...")
            agent.save(save_path)
    
    # Đánh giá agent
    logger.info("Thực thi pentesting bằng Q-Learning agent...")
    avg_reward, success_rate = agent.evaluate(num_eval_episodes)
    
    # Kiểm tra kết quả
    done = success_rate > 0  # Đã hoàn thành ít nhất một lần
    truncated = success_rate < 1  # Không hoàn thành tất cả các lần
    step_count = 150 if not done else 75  # Giả lập số bước
    
    # Ghi log kết quả đánh giá chi tiết
    logger.debug(f"Kết quả Q-Learning agent: success_rate={success_rate:.2f}, avg_reward={avg_reward:.2f}, steps={step_count}")
    
    return done, truncated, step_count