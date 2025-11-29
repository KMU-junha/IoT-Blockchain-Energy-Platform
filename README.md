# ⚡ IoT Blockchain Energy Trading Platform
> **라즈베리파이와 전력 센서를 활용한 실물 기반 블록체인 에너지 거래 프로토타입**

### 🏆 Achievement
* **2025-1학기 공학설계(캡스톤디자인) 프로젝트: A+ 달성**
* 지도교수: 정일엽 교수님

## 1. Project Overview (프로젝트 개요)
* **목표:** 시뮬레이션이 아닌, **실제 전력(Voltage/Current)**을 제어하고 거래 내역을 블록체인에 기록하는 하드웨어 프로토타입 구현.
* **핵심 기능:**
    * 실시간 전력 사용량 모니터링 (INA219 센서).
    * P2P 네트워크를 통한 블록체인 데이터 동기화.
    * 웹/GUI 대시보드를 통한 직관적인 거래 시각화.

## 2. System Architecture (시스템 구조)

*(여기에 라즈베리파이랑 PC가 연결된 그림이나 회로도 사진을 넣으면 좋습니다)*

### 2-1. Edge Node (Raspberry Pi 4)
* **Hardware:** Raspberry Pi, **INA219** (전력 센서), **Relay Module** (전원 제어).
* **Role:**
    1.  I2C 통신으로 실시간 전압/전력 데이터 수집 (`Power Sensing`).
    2.  임계치 초과 시 릴레이(Relay)를 제어하여 전력 차단 (`Physical Control`).
    3.  수집된 데이터를 트랜잭션으로 생성하여 네트워크에 전파.

### 2-2. Server Node (Full Node)
* **Role:** 센서 없이 네트워크의 중추 역할을 수행하며 전체 블록체인 원장(Ledger)을 유지 및 동기화.
* **Feature:** `Websockets`을 이용한 비동기 양방향 통신으로 끊김 없는 데이터 패킷 교환.

## 3. Key Technology & Implementation (핵심 기술)

### A. Advanced Concurrency (비동기 및 멀티스레딩)
단일 프로세스 내에서 3가지 루프를 병렬로 처리하여 시스템 안정성 확보.
1.  **Asyncio Event Loop:** WebSocket 기반의 P2P 메시지(블록/트랜잭션) 처리.
2.  **Sensor Thread (Daemon):** 1초 간격의 전력 데이터 샘플링이 메인 로직을 방해하지 않도록 백그라운드 처리.
3.  **GUI Main Loop (Tkinter):** 사용자가 실시간으로 로그를 확인하고 조작할 수 있는 인터페이스 제공.

### B. Custom Blockchain Core
* 라이브러리에 의존하지 않고 `Block` 클래스와 `SHA-256` 해시 함수를 직접 구현.
* **Consensus:** `Longest Chain Rule`을 적용하여 노드 간 원장 불일치 시 자동 동기화 로직 구현.

### C. Web Visualization (Flask Integration)
* 하드웨어 내부 데이터를 외부에서 쉽게 모니터링할 수 있도록 **REST API** 및 웹 대시보드(Flask) 내장.
* *Code Snippet:* `@flask_app.route('/data')`를 통해 실시간 JSON 데이터 송출.

## 4. Hardware Specs & Environment
* **Language:** Python 3.x
* **Libraries:** `asyncio`, `websockets`, `RPi.GPIO`, `adafruit-circuitpython-ina219`, `flask`, `tkinter`
* **Sensor:** INA219 (High Side DC Current Sensor)

## 5. Result
* 라즈베리파이 GPIO를 통해 전구/모터의 전원을 켜고 끌 때, 해당 상태 변화가 블록체인에 위변조 불가능한 형태로 기록됨을 실증.
* 하드웨어(Physical)와 소프트웨어(Cyber)가 결합된 **Cyber-Physical System(CPS)**의 기초 모델 완성.
