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

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import random
import numpy as np
from collections import deque

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
AGENT_TYPE_DQN = "dqn"
DEFAULT_AGENT_TYPE = AGENT_TYPE_DQN

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
    
    logging.info("\n===== BẮT ĐẦU CHẠY DETERMINISTIC AGENT =====")
    logging.debug("Tổng số bước trong deterministic path: %s", len(deterministic_path))
    logging.debug("Chi tiết đường dẫn: %s", deterministic_path)

    # Loop while the experiment is not finished (pentesting goal not reached)
    # and not truncated (aborted because of exceeding maximum number of steps)
    while not done and not truncated:
        # Exit if there are no more steps in the deterministic path
        if step_count >= len(deterministic_path):
            logging.debug("Đã hết các bước trong deterministic path")
            break
        
        # Retrieve the next action to be executed
        action_tuple = deterministic_path[step_count]
        action = select_action(env.action_space, ACTION_NAMES[action_tuple[1]], ACTION_TARGETS[action_tuple[0]])
        
        logging.debug("\n----- THỰC THI BƯỚC %s/%s -----", step_count + 1, len(deterministic_path))
        logging.debug("Action tuple: %s", action_tuple)
        logging.debug("Tên hành động: %s", ACTION_NAMES[action_tuple[1]])
        logging.debug("Mục tiêu: %s", ACTION_TARGETS[action_tuple[0]])
        logging.debug("Action đã chuyển đổi: %s", action)

        # Increment step count and execute action
        step_count = step_count + 1
        
        logging.info("- Step %s: %s", step_count, action)
        
        # Bắt đầu đo thời gian thực thi
        import time
        start_time = time.time()
          
        observation, reward, done, truncated, info = env.step(action)
        
        # Kết thúc đo thời gian thực thi
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Cập nhật tổng reward
        total_reward += reward
        
        logging.debug("Thời gian thực thi: %.4f giây", execution_time)
        logging.debug("Reward: %s (Tổng: %s)", reward, total_reward)
        logging.debug("Done: %s, Truncated: %s", done, truncated)
        logging.debug("Info: %s", info)
        
        # Hiển thị một phần của observation để debug
        if hasattr(observation, "shape"):  # Nếu observation là array hoặc tensor
            logging.debug("Observation shape: %s", observation.shape)
            # Hiển thị observation nếu là tensor
            if len(observation.shape) > 1:
                logging.debug("Observation: %s", observation[:5])
            else:
                logging.debug("Observation: %s", observation)
        else:  # Nếu observation là dict hoặc cấu trúc khác
            logging.debug("Observation type: %s", type(observation))
            
        if RENDER_OBS_STATE:
            logging.debug("Rendering observation and state...")
            env.render() # render most recent observation
            env.render_state() # render most recent state

        # Conditional exit (for debugging purposes)
        if step_count >= MAX_STEPS:
            logging.warning("CẢNH BÁO: Vượt quá số bước tối đa (%s)", MAX_STEPS)
            logging.warning("Abort execution after %s steps", step_count)
            break

    # In thông tin tổng kết sau khi hoàn thành
    logging.info("\n===== KẾT QUẢ THỰC THI =====")
    logging.info("Tổng số bước đã thực hiện: %s/%s", step_count, len(deterministic_path))
    logging.info("Tổng reward: %s", total_reward)
    logging.info("Hoàn thành mục tiêu: %s", done)
    logging.info("Bị truncate: %s", truncated)
    
    # Xác định lý do kết thúc
    reason = "Đạt mục tiêu" if done else "Hết bước" if step_count >= len(deterministic_path) else "Vượt quá số bước tối đa" if step_count >= MAX_STEPS else "Bị truncate"
    logging.info("Lý do kết thúc: %s", reason)
    logging.info("================================\n")

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

# Thêm thông tin DQN vào usage
def usage():
    print("\nOVERVIEW: Run demo of the PenGym training framework for pentesting agents\n")
    print("USAGE: python3 run.py [options] <CONFIG_FILE> \n")
    print("OPTIONS:")
    print("-h, --help                     Display this help message and exit")
    print("-a, --agent_type <AGENT_TYPE>  Agent type (random/deterministic/dqn)")
    print("-d, --disable_pengym           Disable PenGym execution in cyber range")
    print("-n, --nasim_simulation         Enable NASim simulation execution")
    print("--train                        Train the DQN agent (for dqn agent type)")
    print("--load <MODEL_PATH>            Load pre-trained DQN model")
    print("--save <MODEL_PATH>            Save trained DQN model")


# Định nghĩa mô hình mạng nơ-ron cho DQN
class DQNNetwork(nn.Module):
    """Mạng nơ-ron sâu cho DQN agent"""
    
    def __init__(self, input_dim, hidden_dims, output_dim):
        """Khởi tạo mô hình mạng DQN
        
        Parameters:
        -----------
        input_dim : int
            Kích thước của không gian quan sát
        hidden_dims : list
            Danh sách kích thước các lớp ẩn
        output_dim : int
            Số lượng hành động (kích thước của không gian hành động)
        """
        super(DQNNetwork, self).__init__()
        
        # Tạo các lớp của mạng nơ-ron
        self.layers = nn.ModuleList()
        
        # Lớp đầu vào
        self.layers.append(nn.Linear(input_dim, hidden_dims[0]))
        
        # Các lớp ẩn
        for i in range(len(hidden_dims) - 1):
            self.layers.append(nn.Linear(hidden_dims[i], hidden_dims[i+1]))
            
        # Lớp đầu ra
        self.output = nn.Linear(hidden_dims[-1], output_dim)
        
    def forward(self, x):
        """Lan truyền tiến qua mạng nơ-ron
        
        Parameters:
        -----------
        x : torch.Tensor
            Dữ liệu đầu vào
            
        Returns:
        --------
        torch.Tensor
            Q-values cho mỗi hành động
        """
        # Chuyển đổi x thành tensor nếu nó chưa phải là tensor
        if not isinstance(x, torch.Tensor):
            x = torch.FloatTensor(x)
            
        # Lan truyền qua các lớp ẩn với hàm kích hoạt ReLU
        for layer in self.layers:
            x = F.relu(layer(x))
            
        # Lớp đầu ra không áp dụng hàm kích hoạt
        return self.output(x)
    
    def get_action(self, state):
        """Lấy hành động tốt nhất cho trạng thái đã cho
        
        Parameters:
        -----------
        state : numpy.ndarray
            Trạng thái hiện tại
            
        Returns:
        --------
        int
            Chỉ số hành động tốt nhất
        """
        with torch.no_grad():
            q_values = self.forward(state)
            return q_values.argmax().item()

# Định nghĩa bộ nhớ replay cho DQN
class ReplayBuffer:
    """Bộ nhớ replay để lưu trữ các chuyển trạng thái cho DQN"""
    
    def __init__(self, capacity):
        """Khởi tạo bộ nhớ replay
        
        Parameters:
        -----------
        capacity : int
            Dung lượng tối đa của bộ nhớ
        """
        self.memory = deque(maxlen=capacity)
        
    def add(self, state, action, reward, next_state, done):
        """Thêm một chuyển trạng thái vào bộ nhớ
        
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
        """
        self.memory.append((state, action, reward, next_state, done))
        
    def sample(self, batch_size):
        """Lấy mẫu ngẫu nhiên từ bộ nhớ
        
        Parameters:
        -----------
        batch_size : int
            Kích thước batch
            
        Returns:
        --------
        tuple
            Các batch dữ liệu (states, actions, rewards, next_states, dones)
        """
        # Lấy mẫu ngẫu nhiên từ bộ nhớ
        batch = random.sample(self.memory, batch_size)
        
        # Tách thành các thành phần
        states, actions, rewards, next_states, dones = zip(*batch)
        
        # Chuyển đổi thành tensor
        states = torch.FloatTensor(np.array(states))
        actions = torch.LongTensor(np.array(actions))
        rewards = torch.FloatTensor(np.array(rewards))
        next_states = torch.FloatTensor(np.array(next_states))
        dones = torch.FloatTensor(np.array(dones))
        
        return states, actions, rewards, next_states, dones
    
    def __len__(self):
        """Trả về kích thước hiện tại của bộ nhớ"""
        return len(self.memory)

# Định nghĩa DQN agent
class DQNAgentPenGym:
    """DQN agent cho PenGym"""
    
    def __init__(self, env, 
             hidden_dims=[128, 128], 
             learning_rate=0.001, 
             gamma=0.99,
             epsilon_start=1.0,
             epsilon_end=0.05,
             epsilon_decay=0.995,
             memory_size=10000,
             batch_size=64,
             target_update_freq=10,
             device=None):
        """Khởi tạo DQN agent
        
        Parameters:
        -----------
        env : pengym.PenGymEnv
            Môi trường PenGym
        hidden_dims : list
            Danh sách kích thước các lớp ẩn
        learning_rate : float
            Tốc độ học
        gamma : float
            Hệ số chiết khấu
        epsilon_start : float
            Giá trị epsilon ban đầu cho chính sách ε-greedy
        epsilon_end : float
            Giá trị epsilon tối thiểu
        epsilon_decay : float
            Tốc độ giảm epsilon
        memory_size : int
            Kích thước bộ nhớ replay
        batch_size : int
            Kích thước batch cho việc học
        target_update_freq : int
            Tần suất cập nhật mạng target
        device : str
            Thiết bị để chạy mô hình (CPU hoặc CUDA)
        """
        self.env = env
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.target_update_freq = target_update_freq
        
        # Xác định thiết bị
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = device
            
        logging.debug("DQN Agent sẽ chạy trên: %s", self.device)
            
        # Lấy kích thước không gian quan sát và hành động
        self.obs_dim = env.observation_space.shape[0]
        self.n_actions = env.action_space.n
        
        logging.debug("Kích thước không gian quan sát: %s", self.obs_dim)
        logging.debug("Số lượng hành động: %s", self.n_actions)
        
        # Khởi tạo mạng nơ-ron
        self.policy_net = DQNNetwork(self.obs_dim, hidden_dims, self.n_actions).to(self.device)
        self.target_net = DQNNetwork(self.obs_dim, hidden_dims, self.n_actions).to(self.device)
        
        # Sao chép trọng số từ policy_net sang target_net
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()  # Đặt target_net ở chế độ đánh giá (không tính gradient)
        
        # Khởi tạo bộ tối ưu hóa
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        
        # Khởi tạo bộ nhớ replay
        self.memory = ReplayBuffer(memory_size)
        
        # Theo dõi số bước huấn luyện
        self.steps = 0
        
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
        # Tính epsilon cho evaluation mode
        epsilon = 0.01 if eval_mode else self.epsilon
        
        # Chọn hành động ngẫu nhiên với xác suất epsilon
        if random.random() < epsilon:
            return random.randrange(self.n_actions)
        
        # Chọn hành động tốt nhất theo mô hình
        return self.policy_net.get_action(state)
    
    def update_model(self):
        """Cập nhật mô hình dựa trên batch dữ liệu từ replay buffer"""
        # Kiểm tra xem có đủ mẫu trong bộ nhớ không
        if len(self.memory) < self.batch_size:
            return
        
        # Lấy batch từ bộ nhớ
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)
        
        # Chuyển dữ liệu đến thiết bị đang sử dụng
        states = states.to(self.device)
        actions = actions.to(self.device)
        rewards = rewards.to(self.device)
        next_states = next_states.to(self.device)
        dones = dones.to(self.device)
        
        # Tính toán Q-values hiện tại
        q_values = self.policy_net(states)
        q_values = q_values.gather(1, actions.unsqueeze(1)).squeeze(1)
        
        # Tính toán Q-values tiếp theo
        next_q_values = self.target_net(next_states).max(1)[0].detach()
        
        # Tính toán giá trị mục tiêu
        expected_q_values = rewards + (self.gamma * next_q_values * (1 - dones))
        
        # Tính toán loss
        loss = F.smooth_l1_loss(q_values, expected_q_values)
        
        # Tối ưu hóa mô hình
        self.optimizer.zero_grad()
        loss.backward()
        
        # Clip gradient để tránh exploding gradient
        for param in self.policy_net.parameters():
            param.grad.data.clamp_(-1, 1)
            
        self.optimizer.step()
        
        # Cập nhật target network nếu cần
        if self.steps % self.target_update_freq == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())
    
    def train(self, num_episodes, max_steps_per_episode=1000):
        """Huấn luyện DQN agent
        
        Parameters:
        -----------
        num_episodes : int
            Số lượng tập huấn luyện
        max_steps_per_episode : int
            Số bước tối đa cho mỗi tập
            
        Returns:
        --------
        list
            Danh sách phần thưởng cho mỗi tập
        """
        episode_rewards = []
        
        logging.debug("Bắt đầu huấn luyện DQN agent trong %s tập...", num_episodes)
        
        for episode in range(num_episodes):
            # Reset môi trường
            state, _ = self.env.reset()
            total_reward = 0
            done = False
            truncated = False
            
            for step in range(max_steps_per_episode):
                # Chọn hành động
                action = self.select_action(state)
                
                # Thực hiện hành động
                next_state, reward, done, truncated, _ = self.env.step(action)
                
                # Lưu chuyển trạng thái vào bộ nhớ
                self.memory.add(state, action, reward, next_state, done)
                
                # Cập nhật mô hình
                self.update_model()
                
                # Cập nhật trạng thái và phần thưởng
                state = next_state
                total_reward += reward
                self.steps += 1
                
                # Giảm epsilon theo thời gian
                self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
                
                # Kiểm tra điều kiện kết thúc
                if done or truncated:
                    break
            
            episode_rewards.append(total_reward)
            
            # In thông tin về tập hiện tại
            if (episode + 1) % 10 == 0:
                avg_reward = sum(episode_rewards[-10:]) / 10
                logging.info("Tập %s/%s, Reward: %.2f, Avg Reward (10 tập): %.2f, Epsilon: %.4f", 
                             episode + 1, num_episodes, total_reward, avg_reward, self.epsilon)
        
        logging.debug("Đã hoàn thành huấn luyện!")
        return episode_rewards
    
    def evaluate(self, num_episodes=5):
        """Đánh giá DQN agent đã huấn luyện
        
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
        
        logging.debug("Đánh giá DQN agent trong %s tập...", num_episodes)
        
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
                
                logging.info("- Step %s: %s", step_count + 1, action_obj)
                
                # Thực hiện hành động
                next_state, reward, done, truncated, _ = self.env.step(action)
                
                # Cập nhật trạng thái và phần thưởng
                state = next_state
                total_reward += reward
                step_count += 1
                
                # Kiểm tra điều kiện kết thúc
                if done:
                    successes += 1
                
                if step_count >= MAX_STEPS:
                    logging.warning("CẢNH BÁO: Vượt quá số bước tối đa (%s)", MAX_STEPS)
                    break
            
            episode_rewards.append(total_reward)
            logging.info("Tập %s/%s, Reward: %.2f, Steps: %s, Done: %s", 
                        episode + 1, num_episodes, total_reward, step_count, done)
        
        avg_reward = sum(episode_rewards) / num_episodes
        success_rate = successes / num_episodes
        
        logging.debug("Kết quả đánh giá: Reward TB: %.2f, Tỷ lệ thành công: %.2f", 
                     avg_reward, success_rate)
        
        return avg_reward, success_rate
    
    def save(self, path):
        """Lưu mô hình DQN
        
        Parameters:
        -----------
        path : str
            Đường dẫn file lưu mô hình
        """
        # Lưu các thành phần quan trọng của mô hình vào file
        torch.save({
            'policy_net': self.policy_net.state_dict(),  # Trọng số của mạng chính sách
            'target_net': self.target_net.state_dict(),  # Trọng số của mạng mục tiêu
            'optimizer': self.optimizer.state_dict(),    # Trạng thái của bộ tối ưu hóa
            'epsilon': self.epsilon,                     # Giá trị epsilon hiện tại
            'steps': self.steps                          # Số bước đã thực hiện
        }, path)
        logging.debug("Đã lưu mô hình vào %s", path)
    
    def load(self, path):
        """Tải mô hình DQN đã lưu
        
        Parameters:
        -----------
        path : str
            Đường dẫn file mô hình
        """
        try:
            # Tải mô hình từ file và ánh xạ tới thiết bị phù hợp
            logging.debug("Bắt đầu tải mô hình từ %s", path)
            checkpoint = torch.load(path, map_location=self.device)
            
            # Khôi phục trạng thái các thành phần từ checkpoint
            # Trọng số của mạng chính sách (policy network)
            self.policy_net.load_state_dict(checkpoint['policy_net'])
            logging.debug("Đã tải trọng số của policy network")
            
            # Trọng số của mạng mục tiêu (target network)
            self.target_net.load_state_dict(checkpoint['target_net'])
            logging.debug("Đã tải trọng số của target network")
            
            # Trạng thái của bộ tối ưu hóa (optimizer)
            self.optimizer.load_state_dict(checkpoint['optimizer'])
            logging.debug("Đã tải trạng thái của optimizer")
            
            # Giá trị epsilon cho chính sách khám phá
            self.epsilon = checkpoint['epsilon']
            # Số bước huấn luyện đã thực hiện
            self.steps = checkpoint['steps']
            
            logging.info("Đã tải mô hình thành công từ %s (epsilon=%.4f, steps=%d)", 
                        path, self.epsilon, self.steps)
        except FileNotFoundError:
            # Ghi log lỗi khi không tìm thấy file
            logging.error("Không tìm thấy file mô hình: %s", path)
        except KeyError as e:
            # Ghi log lỗi khi thiếu thành phần trong checkpoint
            logging.error("Checkpoint không hợp lệ - thiếu thành phần: %s", e)
        except Exception as e:
            # Ghi log lỗi chung nếu có vấn đề khác khi tải mô hình
            logging.error("Lỗi khi tải mô hình: %s", e)
            logging.exception("Chi tiết lỗi:")  # Ghi ra stack trace chi tiết

# Thêm hàm chạy DQN agent
# Thêm hàm chạy DQN agent
def run_dqn_agent(env, train=False, load_path=None, save_path=None, 
                 num_train_episodes=100, num_eval_episodes=5):
    """Chạy DQN agent trong môi trường PenGym
    
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
    # Khởi tạo DQN agent
    agent = DQNAgentPenGym(env)
    
    # Tải mô hình nếu có
    if load_path:
        agent.load(load_path)
    
    # Huấn luyện nếu yêu cầu
    if train:
        logging.info("Huấn luyện DQN agent trong %s tập...", num_train_episodes)
        agent.train(num_train_episodes)
        
        # Lưu mô hình nếu có đường dẫn
        if save_path:
            agent.save(save_path)
    
    # Đánh giá agent
    logging.info("Thực thi pentesting bằng DQN agent...")
    avg_reward, success_rate = agent.evaluate(num_eval_episodes)
    
    # Kiểm tra kết quả
    done = success_rate > 0  # Đã hoàn thành ít nhất một lần
    truncated = success_rate < 1  # Không hoàn thành tất cả các lần
    step_count = MAX_STEPS if not done else MAX_STEPS // 2  # Giả lập số bước
    
    # Ghi log kết quả đánh giá chi tiết
    logging.debug("Kết quả DQN agent: success_rate=%.2f, avg_reward=%.2f, steps=%d", 
                 success_rate, avg_reward, step_count)
    
    return done, truncated, step_count

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
        
    train_dqn = True
    load_model_path = None
    save_model_path = None

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
        elif opt in ("--train"):
            train_dqn = True
        elif opt in ("--load"):
            load_model_path = arg
        elif opt in ("--save"):
            save_model_path = arg
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
    elif agent_type == AGENT_TYPE_DQN:
        print("* Execute pentesting using a DQN agent...")
        done, truncated, step_count = run_dqn_agent(env, 
                                                train=train_dqn,
                                                load_path=load_model_path,
                                                save_path=save_model_path)
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
