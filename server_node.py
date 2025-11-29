import asyncio
import websockets
import json
import hashlib
import time
import threading
import uuid
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread
import queue

# 사용자 정보 저장 (username: password)
users = {}
users_lock = threading.Lock()

# 네트워크 환경 설정
MY_IP = "192.168.100.10"  # 자신의 IP로 수정
MY_PORT = 8765
websockets_set = set()
msg_queue = asyncio.Queue()
loop_for_network = None
app_instance = None
loop_ready = threading.Event()  # 이벤트 루프 준비 상태 확인

# GUI 작업 큐
gui_task_queue = queue.Queue()

# 블록 구조
class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'data': self.data,
            'hash': self.hash
        }

def calculate_hash(index, previous_hash, timestamp, data):
    value = f"{index}{previous_hash}{timestamp}{json.dumps(data, sort_keys=True)}".encode()
    return hashlib.sha256(value).hexdigest()

def create_genesis_block():
    return Block(0, "0", int(time.time()), "Genesis Block", "0")

blockchain = [create_genesis_block()]
blockchain_lock = threading.Lock()

# 스마트컨트랙트
class SmartContract:
    def __init__(self):
        self.pending = {}
        self.lock = threading.Lock()

    def create(self, sender, receiver, terms, expiration_min=5):
        contract_id = str(uuid.uuid4())
        with self.lock:
            self.pending[contract_id] = {
                'sender': sender,
                'receiver': receiver,
                'terms': terms,
                'status': 'pending',
                'expires': datetime.now() + timedelta(minutes=expiration_min)
            }
        return contract_id

    def accept(self, contract_id):
        with self.lock:
            if contract_id in self.pending:
                self.pending[contract_id]['status'] = 'accepted'
                return True
        return False

    def reject(self, contract_id):
        with self.lock:
            if contract_id in self.pending:
                self.pending[contract_id]['status'] = 'rejected'
                return True
        return False

smart_contract = SmartContract()

# 블록체인 검증
def is_valid_chain(chain):
    for i in range(1, len(chain)):
        if not is_valid_new_block(chain[i], chain[i-1]):
            return False
    return True

def get_latest_block():
    with blockchain_lock:
        return blockchain[-1]

def is_valid_new_block(new_block, previous_block):
    # 인덱스 검증 (오차 허용)
    if abs((previous_block.index + 1) - new_block.index) > 1:
        print(f"인덱스 불일치: {previous_block.index+1} vs {new_block.index}")
        return False
    
    # 해시 검증 (이전 블록과 연결성 확인)
    if previous_block.hash != new_block.previous_hash:
        print(f"해시 불일치: {previous_block.hash} vs {new_block.previous_hash}")
        return False
    
    # 재계산 해시 검증
    recalculated_hash = calculate_hash(
        new_block.index,
        new_block.previous_hash,
        new_block.timestamp,
        new_block.data
    )
    if recalculated_hash != new_block.hash:
        print(f"해시 계산 오류: {recalculated_hash} vs {new_block.hash}")
        return False
    
    return True

def add_block(new_block):
    with blockchain_lock:
        prev_block = blockchain[-1]
        
        # 강화된 유효성 검사
        if is_valid_new_block(new_block, prev_block):
            blockchain.append(new_block)
            print(f"블록 #{new_block.index} 추가 성공")
            return True
        else:
            print("유효하지 않은 블록입니다.")
            return False

def blockchain_to_list():
    with blockchain_lock:
        return [block.to_dict() for block in blockchain]

def replace_chain(new_chain):
    global blockchain
    with blockchain_lock:
        if len(new_chain) > len(blockchain) and is_valid_chain(new_chain):
            blockchain = new_chain
            print("블록체인이 교체되었습니다.")

# 네트워크 통신
async def broadcast_new_block(new_block):
    msg = json.dumps({"type": "NEW_BLOCK", "block": new_block.to_dict()})
    for ws in set(websockets_set):
        try:
            if ws.open:
                await ws.send(msg)
        except:
            websockets_set.discard(ws)

async def sync_chain():
    if not websockets_set:
        gui_task_queue.put(lambda: messagebox.showwarning("경고", "연결된 피어가 없습니다."))
        return
    msg = json.dumps({"type": "SYNC_REQUEST"})
    await as极cio.gather(*(ws.send(msg) for ws in websockets_set if ws.open))
    gui_task_queue.put(lambda: messagebox.showinfo("알림", "체인 동기화 요청을 보냈습니다."))

async def handler(websocket, path):
    print(f"새 피어 접속: {websocket.remote_address}")
    websockets_set.add(websocket)
    try:
        async for message in websocket:
            await msg_queue.put((websocket, message))
    except websockets.ConnectionClosed:
        print("피어 연결 종료")
    finally:
        websockets_set.discard(websocket)

async def process_messages():
    while True:
        websocket, message = await msg_queue.get()
        await handle_message(websocket, message)

class UserAuthDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("사용자 인증")
        self.result = None
        self.parent = parent
        self.grab_set()
        
        ttk.Label(self, text="사용자명:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self, text="비밀번호:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="확인", command=self._submit).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="취소", command=self.destroy).pack(side="left", padx=5)
    
    def _submit(self):
        self.result = {
            'username': self.username_entry.get().strip(),
            'password': self.password_entry.get().strip()
        }
        self.destroy()

# GUI 실행 래퍼
def gui_prompt(func):
    result_queue = queue.Queue()
    def wrapper():
        result_queue.put(func())
    gui_task_queue.put(wrapper)
    return result_queue.get()

async def handle_message(websocket, message):
    try:
        data = json.loads(message)
        if data["type"] == "NEW_BLOCK":
            block_data = data["block"]
            new_block = Block(
                block_data['index'],
                block_data['previous_hash'],
                block_data['timestamp'],
                block_data['data'],
                block_data['hash']
            )
            add_block(new_block)

        elif data["type"] == "SYNC_REQUEST":
            await websocket.send(json.dumps({"type": "SYNC_RESPONSE", "chain": blockchain_to_list()}))

        elif data["type"] == "SYNC_RESPONSE":
            new_chain = [Block(**block_data) for block_data in data["chain"]]
            replace_chain(new_chain)

        elif data["type"] == "CONTRACT_PROPOSAL":
            contract_id = data["contract_id"]
            terms = data["terms"]
            sender_ip = data["sender_ip"]
            
            def show_proposal_dialog():
                return messagebox.askyesno(
                    "거래 제안 도착", 
                    f"발신자: {sender_ip}\n조건: {terms}\n수락하시겠습니까?"
                )
            answer = gui_prompt(show_proposal_dialog)
            
            if answer:
                authenticated = False
                max_attempts = 3
                attempts = 0
                while attempts < max_attempts and not authenticated:
                    def show_auth_dialog():
                        dialog = UserAuthDialog(app_instance)
                        dialog.wait_window()
                        return dialog.result
                    auth_result = gui_prompt(show_auth_dialog)
                    if auth_result:
                        username = auth_result['username']
                        password = auth_result['password']
                        with users_lock:
                            if username in users and users[username] == password:
                                authenticated = True
                                smart_contract.accept(contract_id)
                                # 판매자 이름을 함께 전송
                                await send_contract_response(
                                    sender_ip, contract_id, "ACCEPTED", terms, username
                                )
                                gui_task_queue.put(lambda: messagebox.showinfo("인증 성공", f"{username}님으로 거래 승낙"))
                            else:
                                attempts += 1
                                if attempts < max_attempts:
                                    def show_retry_dialog():
                                        return messagebox.askretrycancel(
                                            "인증 실패", 
                                            f"틀린 사용자명/비밀번호입니다. ({attempts}/{max_attempts})\n다시 시도하시겠습니까?"
                                        )
                                    retry = gui_prompt(show_retry_dialog)
                                    if not retry:
                                        break
                                else:
                                    gui_task_queue.put(lambda: messagebox.showerror("인증 실패", "3회 실패로 거래가 자동 거절됩니다"))
                    else:
                        break
                if not authenticated:
                    smart_contract.reject(contract_id)
                    await send_contract_response(
                        sender_ip, contract_id, "REJECTED", terms
                    )
            else:
                smart_contract.reject(contract_id)
                await send_contract_response(
                    sender_ip, contract_id, "REJECTED", terms
                )

        elif data["type"] == "CONTRACT_RESPONSE":
            contract_id = data["contract_id"]
            if data["status"] == "ACCEPTED":
                print(f"\n거래 제안 {contract_id} 수락됨! 블록에 기록합니다.")
                # 메시지에서 판매자 이름 직접 추출
                seller_username = data.get("seller_username", None)
                if seller_username:
                    await finalize_contract(contract_id, data['terms'], seller_username)
                    gui_task_queue.put(lambda: messagebox.showinfo("거래 수락", f"거래 제안 {contract_id} 수락됨! 블록에 기록합니다."))
                else:
                    gui_task_queue.put(lambda: messagebox.showerror("오류", "판매자 정보를 찾을 수 없습니다"))
            else:
                print(f"\n거래 제안 {contract_id} 거절됨")
                smart_contract.reject(contract_id)
                gui_task_queue.put(lambda: messagebox.showinfo("거래 거절", f"거래 제안 {contract_id} 거절됨"))

    except Exception as e:
        print(f"메시지 처리 오류: {e}")

async def connect_to_peer(peer_uri):
    while True:
        try:
            async with websockets.connect(peer_uri) as websocket:
                websockets_set.add(websocket)
                print(f"{peer_uri} 연결 성공")
                async for message in websocket:
                    await msg_queue.put((websocket, message))
        except Exception as e:
            print(f"{peer_uri} 연결 실패: {str(e)[:50]}")
            await asyncio.sleep(5)

async def send_contract_proposal(receiver_ip, receiver_port, terms):
    contract_id = smart_contract.create("me", receiver_ip, terms)
    msg = json.dumps({
        "type": "CONTRACT_PROPOSAL",
        "contract_id": contract_id,
        "sender_ip": MY_IP,
        "terms": terms,
        "timestamp": datetime.now().isoformat()
    })
    peer_uri = f"ws://{receiver_ip}:{receiver_port}"
    try:
        async with websockets.connect(peer_uri) as ws:
            await ws.send(msg)
            print("거래 제안 발송 완료")
    except Exception as e:
        print(f"거래 제안 발송 실패: {e}")

# 판매자 이름 전송 기능 추가
async def send_contract_response(sender_ip, contract_id, status, terms, seller_username=None):
    msg = {
        "type": "CONTRACT_RESPONSE",
        "contract_id": contract_id,
        "status": status,
        "terms": terms,
        "receiver_ip": MY_IP
    }
    # 거래 수락 시 판매자 이름 포함
    if status == "ACCEPTED" and seller_username:
        msg["seller_username"] = seller_username
    
    try:
        async with websockets.connect(f"ws://{sender_ip}:{MY_PORT}") as ws:
            await ws.send(json.dumps(msg))
    except Exception as e:
        print(f"응답 전송 실패: {e}")

async def finalize_contract(contract_id, terms, seller_username):
    try:
        await sync_chain()
        with blockchain_lock:
            prev_block = blockchain[-1]
        timestamp = int(time.time())
        block_data = {
            'buyer': terms['buyer'],
            'seller': seller_username,
            'amount': terms['amount'],
            'price': terms['price'],
            'timestamp': terms['timestamp'],
            'status': 'completed'
        }
        new_block = Block(
            prev_block.index + 1,
            prev_block.hash,
            timestamp,
            block_data,
            calculate_hash(prev_block.index + 1, prev_block.hash, timestamp, block_data)
        )
        add_block(new_block)
        await broadcast_new_block(new_block)
        print("블록에 거래가 성공적으로 추가됨")
        gui_task_queue.put(lambda: messagebox.showinfo("거래 완료", "거래가 완료되어 블록에 기록되었습니다"))
    except Exception as e:
        print(f"거래 완료 오류: {e}")

class UserRegisterDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("사용자 등록")
        self.result = None

        ttk.Label(self, text="사용자명 (영문/숫자):").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="비밀번호:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="등록", command=self._submit).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="취소", command=self.destroy).pack(side="left", padx=5)

    def _submit(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username.isalnum():
            messagebox.showerror("입력 오류", "사용자명은 영문/숫자만 가능합니다.")
            return
        if not username or not password:
            messagebox.showerror("입력 오류", "모든 항목을 입력하세요.")
            return
        
        with users_lock:
            if username in users:
                messagebox.showerror("중복 오류", "이미 등록된 사용자명입니다.")
                return
            users[username] = password
        
        self.result = {'username': username, 'password': password}
        self.destroy()

class MyTransactionsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("나의 거래 내역")
        self.geometry("900x700")
        self.user = None
        self._authenticate()
        
    def _authenticate(self):
        dialog = UserAuthDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            username = dialog.result['username']
            password = dialog.result['password']
            with users_lock:
                if username in users and users[username] == password:
                    self.user = username
                    self._create_widgets()
                else:
                    messagebox.showerror("인증 실패", "등록된 사용자명과 비밀번호를 정확히 입력하세요.")
                    self.destroy()
        else:
            self.destroy()
    
    def _create_widgets(self):
        self.tree = ttk.Treeview(self, columns=("Index", "Hash", "Timestamp", "Status", "Data"), show="headings")
        self.tree.heading("Index", text="블록 번호")
        self.tree.heading("Hash", text="해시 값")
        self.tree.heading("Timestamp", text="생성 시간")
        self.tree.heading("Status", text="상태")
        self.tree.heading("Data", text="거래 내용")
        self.tree.column("Index", width=80, anchor="center")
        self.tree.column("Hash", width=150)
        self.tree.column("Timestamp", width=150)
        self.tree.column("Status", width=100)
        self.tree.column("Data", width=300)
        
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._show_block_details)
        self._load_data()
    
    def _load_data(self):
        with blockchain_lock:
            for block in blockchain:
                if block.index == 0:
                    continue
                if isinstance(block.data, dict):
                    if block.data.get('buyer') == self.user or block.data.get('seller') == self.user:
                        status = block.data.get('status', 'unknown')
                        self.tree.insert("", "end", values=(
                            block.index,
                            block.hash[:15] + "...",
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block.timestamp)),
                            status,
                            "내 거래 블록"
                        ))
    
    def _show_block_details(self, event):
        item = self.tree.selection()[0]
        block_idx = int(self.tree.item(item, "values")[0])
        with blockchain_lock:
            block = blockchain[block_idx]
        dialog = UserAuthDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            username = dialog.result['username']
            password = dialog.result['password']
            with users_lock:
                if username == self.user and users.get(username) == password:
                    details = f"블록 #{block.index}\n"
                    details += f"해시: {block.hash}\n"
                    details += f"시간: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}\n"
                    details += "거래 내용:\n"
                    details += f"구매자: {block.data.get('buyer', 'N/A')}\n"
                    details += f"판매자: {block.data.get('seller', 'N/A')}\n"
                    details += f"거래량: {block.data.get('amount', 0)} kWh\n"
                    details += f"단가: {block.data.get('price', 0)} 원/kWh\n"
                    details += f"상태: {block.data.get('status', 'unknown')}"
                    messagebox.showinfo("거래 상세 정보", details)
                else:
                    messagebox.showerror("인증 실패", "거래 내용을 볼 권한이 없습니다")

class BlockchainGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("분산 전력 거래 시스템 v10.3")
        self.geometry("1000x700")
        global app_instance
        app_instance = self
        self._create_widgets()
        self.check_gui_queue()

    def _create_widgets(self):
        control_frame = ttk.Frame(self, padding=10)
        control_frame.pack(fill="x")
        buttons = [
            ("새 거래", self.new_transaction),
            ("블록 현황", self.show_blockchain),
            ("나의 거래", self.my_transactions),
            ("피어 연결", self.connect_peer),
            ("동기화", self.sync_chain),
            ("사용자 등록", self.register_user)
        ]
        for text, command in buttons:
            ttk.Button(control_frame, text=text, command=command).pack(side="left", padx=5)
        self.log_area = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_area.config(state=tk.DISABLED)

    def log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def new_transaction(self):
        dialog = TransactionDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self.log(f"새 거래 생성: {dialog.result}")
            if not loop_ready.wait(timeout=5):
                messagebox.showerror("오류", "네트워크 초기화 시간 초과")
                return
            asyncio.run_coroutine_threadsafe(
                send_contract_proposal(dialog.result['ip'], dialog.result['port'], dialog.result['terms']),
                loop_for_network
            )

    def connect_peer(self):
        dialog = PeerDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self.log(f"피어 연결 시도: {dialog.result}")
            if not loop_ready.wait(timeout=5):
                messagebox.showerror("오류", "네트워크 초기화 시간 초과")
                return
            asyncio.run_coroutine_threadsafe(
                connect_to_peer(dialog.result),
                loop_for_network
            )

    def show_blockchain(self):
        viewer = BlockchainViewer(self)

    def sync_chain(self):
        if not loop_ready.wait(timeout极5):
            messagebox.showerror("오류", "네트워크 초기화 시간 초과")
            return
        asyncio.run_coroutine_threadsafe(sync_chain(), loop_for_network)
        self.log("체인 동기화 요청 전송")

    def register_user(self):
        dialog = UserRegisterDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            username = dialog.result['username']
            self.log(f"사용자 '{username}' 등록 완료")

    def my_transactions(self):
        MyTransactionsDialog(self)

    def check_gui_queue(self):
        try:
            while not gui_task_queue.empty():
                task = gui_task_queue.get_nowait()
                task()
        except queue.Empty:
            pass
        self.after(100, self.check_gui_queue)

class PeerDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("피어 연결")
        self.result = None

        ttk.Label(self, text="IP 주소:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Entry(self)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="포트 번호:").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(self)
        self.port_entry.insert(0, "8765")
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="연결", command=self._submit).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="취소", command=self.destroy).pack(side="left", padx=5)

    def _submit(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip() or "8765"
        self.result = f"ws://{ip}:{port}"
        self.destroy()

class TransactionDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("새 거래 생성")
        self.result = None
        fields = [
            ("상대방 IP", "ip"),
            ("포트 번호", "port"),
            ("구매 희망자 성명", "username"),
            ("비밀번호", "password"),
            ("거래량 (kWh)", "amount"),
            ("단가 (원/kWh)", "price")
        ]
        self.entries = {}
        for i, (label, key) in enumerate(fields):
            ttk.Label(self, text=label+":").grid(row=i, column=0, padx=5, pady=5, sticky="e")
            entry = ttk.Entry(self, show="*" if key == "password" else None)
            if key == "port":
                entry.insert(0, "8765")
            self.entries[key] = entry
            entry.grid(row=i, column=1, padx=5, pady=5)
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=len(fields), columnspan=2, pady=10)
        ttk.Button(btn_frame, text="생성", command=self._submit).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="취소", command=self.destroy).pack(side="left", padx=5)

    def _submit(self):
        try:
            username = self.entries["username"].get().strip()
            password = self.entries["password"].get().strip()
            with users_lock:
                if username not in users or users[username] != password:
                    messagebox.showerror("인증 실패", "등록된 사용자명과 비밀번호를 정확히 입력하세요.")
                    return
            self.result = {
                'ip': self.entries['ip'].get().strip(),
                'port': self.entries['port'].get().strip() or "8765",
                'terms': {
                    'buyer': username,
                    'amount': float(self.entries['amount'].get()),
                    'price': float(self.entries['price'].get()),
                    'timestamp': datetime.now().isoformat()
                }
            }
            self.destroy()
        except ValueError:
            messagebox.showerror("입력 오류", "숫자 형식이 올바르지 않습니다")

class BlockchainViewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("블록체인 현황")
        self.geometry("1000x700")
        self.tree = ttk.Treeview(self, columns=("Index", "Hash", "Timestamp", "Data"), show="headings")
        self.tree.heading("Index", text="블록 번호")
        self.tree.heading("Hash", text="해시 값")
        self.tree.heading("Timestamp", text="생성 시간")
        self.tree.heading("Data", text="거래 내용")
        self.tree.column("Index", width=80, anchor="center")
        self.tree.column("Hash", width=200)
        self.tree.column("Timestamp", width=150)
        self.tree.column("Data", width=400)
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._load_data()

    def _load_data(self):
        with blockchain_lock:
            for block in blockchain:
                if block.index == 0:
                    data_display = block.data
                else:
                    data_display = "암호화 된 블록"
                self.tree.insert("", "end", values=(
                    block.index,
                    block.hash[:20] + "...",
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block.timestamp)),
                    data_display
                ))

# 이벤트 루프 초기화 함수
def start_server():
    global loop_for_network
    loop_for_network = asyncio.new_event_loop()
    asyncio.set_event_loop(loop_for_network)
    loop_ready.set()  # 이벤트 루프 준비 완료 신호
    loop_for_network.run_until_complete(main())
    loop_for_network.run_forever()

# 메인 함수
async def main():
    global app_instance
    server = await websockets.serve(handler, "0.0.0.0", MY_PORT)
    print(f"WebSocket 서버가 0.0.0.0:{MY_PORT}에서 시작됨")
    asyncio.create_task(process_messages())
    while True:
        await asyncio.sleep(1)  # 메인 루프 유지

if __name__ == "__main__":
    try:
        Thread(target=start_server, daemon=True).start()
        if not loop_ready.wait(timeout=5):
            print("네트워크 초기화 시간 초과")
        app = BlockchainGUI()
        app.mainloop()
    except KeyboardInterrupt:
        print("프로그램 종료")
