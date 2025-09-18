# IPS 대시보드 시각화 설계서 예시

---

## 목차

1. [현재 시스템 데이터 분석](#현재-시스템-데이터-분석)
2. [시각화 요구사항 상세 분석](#시각화-요구사항-상세-분석)
3. [대시보드 레이아웃 설계](#대시보드-레이아웃-설계)
4. [데이터 소스 및 API 설계](#데이터-소스-및-api-설계)
5. [기술 스택 및 구현 방안](#기술-스택-및-구현-방안)
6. [구현 우선순위 및 일정](#구현-우선순위-및-일정)

---

## 현재 시스템 데이터 분석

###  **현재 대시보드에서 표시되는 정보**

#### **1. 실시간 CLI 대시보드 (IPSAgent_RL.py)**
```python
# 현재 3초마다 업데이트되는 정보
실시간_대시보드_정보 = {
    '시스템_상태': {
        '가동시간': 'HH:MM:SS 형식',
        '운영모드': 'LIGHTWEIGHT/PERFORMANCE',
        '인터페이스': '네트워크 인터페이스명'
    },
    '패킷_캡처_통계': {
        '총_캡처': '누적 패킷 수',
        '초당_패킷': 'packets/second',
        '최고_처리량': 'peak packets/second',
        '큐_크기': '대기 중인 패킷 수',
        '적응형_처리량': '현재 배치 처리 크기'
    },
    '프로토콜_분석': {
        'TCP': '개수 (백분율)',
        'UDP': '개수 (백분율)', 
        'ICMP': '개수 (백분율)',
        'Other': '개수 (백분율)'
    },
    '위협_탐지_현황': {
        '총_분석': '분석된 패킷 수',
        '위협_탐지': '탐지된 위협 수',
        '높음': 'high 위협 수',
        '중간': 'medium 위협 수',
        '낮음': 'low 위협 수',
        '안전': 'safe 패킷 수'
    },
    '방어_조치_현황': {
        '차단된_IP': '차단된 IP 개수',
        '모니터링_중': '모니터링 대상 수',
        '발송_알림': '알림 발송 수'
    },
    'AI_ML_엔진_상태': {
        '예측_수행': '총 예측 횟수',
        '모델_정확도': '현재 모델 정확도',
        '업데이트': '모델 업데이트 횟수',
        '메모리': 'MB (백분율)',
        'CPU': 'CPU 사용률',
        '리소스_상태': '여유/보통/부하'
    }
}
```

#### **2. 캡처된 패킷 데이터 구조**
```python
# captured_packets_*.csv 파일 구조
패킷_데이터_스키마 = {
    'source': 'IP:PORT (출발지)',
    'destination': 'IP:PORT (목적지)', 
    'protocol': '프로토콜 번호 (6=TCP, 17=UDP, 1=ICMP)',
    'length': '패킷 크기 (bytes)',
    'ttl': 'Time To Live',
    'flags': 'TCP 플래그',
    'info': '상세 패킷 정보 (선택적)',
    'timestamp': '캡처 시간 (선택적)'
}

# 실제 데이터 예시
실제_패킷_예시 = [
    "192.168.0.32,104.18.19.125,6,948,0,0",  # TCP 패킷
    "192.168.0.30,224.0.0.251,17,510,0,0",   # UDP 패킷  
    "192.168.0.32,3.209.139.157,6,64294,0,0" # 대용량 TCP 패킷
]
```

---

## 시각화 요구사항 상세 분석 예시

###  **1. 트래픽 분류 결과 시각화**

#### **1-1. 시간대별 트래픽 분류 차트**
```javascript
// 실시간 라인 차트 - 시간축 기반
const trafficClassificationChart = {
    type: 'line',
    data: {
        datasets: [
            {
                label: '정상 트래픽',
                data: [], // [{x: timestamp, y: count}]
                borderColor: '#2ECC71',
                backgroundColor: 'rgba(46, 204, 113, 0.1)',
                tension: 0.4
            },
            {
                label: '공격 트래픽',
                data: [], 
                borderColor: '#E74C3C',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                tension: 0.4
            },
            {
                label: '의심 트래픽',
                data: [],
                borderColor: '#F39C12',
                backgroundColor: 'rgba(243, 156, 18, 0.1)',
                tension: 0.4
            }
        ]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                type: 'time',
                time: {
                    unit: 'minute',
                    displayFormats: { minute: 'HH:mm' }
                },
                title: { display: true, text: '시간' }
            },
            y: {
                beginAtZero: true,
                title: { display: true, text: '패킷 수/분' }
            }
        },
        plugins: {
            legend: { position: 'top' },
            title: { display: true, text: '실시간 트래픽 분류 현황' }
        }
    }
}
```

###  **2. 공격 트래픽 상세 분석**

#### **2-1. 공격 유형별 분류 바 차트**
```javascript
const attackTypeChart = {
    type: 'horizontalBar',
    data: {
        labels: ['DDoS', 'Port Scan', 'Web Attack', 'Infiltration', 'Brute Force'],
        datasets: [{
            label: '탐지 횟수',
            data: [], // 각 공격 유형별 탐지 횟수
            backgroundColor: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7'],
            borderColor: '#2C3E50',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            title: { display: true, text: '공격 유형별 탐지 현황' },
            tooltip: {
                callbacks: {
                    afterLabel: function(context) {
                        return `최근 탐지: ${getLastDetectionTime(context.label)}`;
                    }
                }
            }
        }
    }
}
```

#### **2-2. 공격 빈도 히트맵 (시간 × 공격유형)**
```javascript
const attackFrequencyHeatmap = {
    type: 'heatmap',
    data: {
        datasets: [{
            label: '공격 빈도',
            data: [], // [{x: hour, y: attack_type, v: frequency}]
            backgroundColor: function(context) {
                const value = context.parsed.v;
                const alpha = Math.min(value / 100, 1);
                return `rgba(231, 76, 60, ${alpha})`;
            }
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                type: 'linear',
                min: 0, max: 23,
                title: { display: true, text: '시간 (24시간)' }
            },
            y: {
                type: 'category',
                labels: ['DDoS', 'Port Scan', 'Web Attack', 'Infiltration'],
                title: { display: true, text: '공격 유형' }
            }
        },
        plugins: {
            title: { display: true, text: '시간대별 공격 빈도 히트맵' }
        }
    }
}
```

#### **2-3. 공격 트래픽 상세 정보 테이블**
```javascript
const attackTrafficTable = {
    columns: [
        { field: 'timestamp', title: '탐지 시간', width: 150 },
        { field: 'source_ip', title: '출발 IP', width: 120 },
        { field: 'dest_ip', title: '목적 IP', width: 120 },
        { field: 'protocol', title: '프로토콜', width: 80 },
        { field: 'packet_size', title: '패킷 크기', width: 100 },
        { field: 'attack_type', title: '공격 유형', width: 120 },
        { field: 'threat_level', title: '위험도', width: 80 },
        { field: 'rf_confidence', title: 'RF 신뢰도', width: 100 },
        { field: 'rl_action', title: 'RL 대응', width: 100 },
        { field: 'status', title: '처리 상태', width: 100 }
    ],
    features: {
        pagination: true,
        sorting: true,
        filtering: true,
        export: ['csv', 'excel']
    }
}
```

#### **2-4. 패킷 크기 분포 히스토그램**
```javascript
const packetSizeDistribution = {
    type: 'bar',
    data: {
        labels: ['0-64B', '65-512B', '513-1024B', '1025-1518B', '1519B+'],
        datasets: [
            {
                label: '정상 트래픽',
                data: [], // 각 크기 범위별 정상 패킷 수
                backgroundColor: 'rgba(46, 204, 113, 0.7)'
            },
            {
                label: '공격 트래픽',
                data: [], // 각 크기 범위별 공격 패킷 수
                backgroundColor: 'rgba(231, 76, 60, 0.7)'
            }
        ]
    },
    options: {
        responsive: true,
        plugins: {
            title: { display: true, text: '패킷 크기별 분포 분석' }
        }
    }
}
```

###  **3. 포트스캔 탐지 및 대처 시각화**

#### **3-1. 포트별 공격 대상 분석 예시시**
```javascript
const portTargetAnalysis = {
    type: 'scatter',
    data: {
        datasets: [{
            label: '포트 스캔 공격',
            data: [], // [{x: port_number, y: attack_count, r: severity}]
            backgroundColor: function(context) {
                const severity = context.parsed.r;
                if (severity > 0.8) return 'rgba(231, 76, 60, 0.8)';   // 높음
                if (severity > 0.5) return 'rgba(243, 156, 18, 0.8)';  // 중간
                return 'rgba(52, 152, 219, 0.8)';                     // 낮음
            },
            pointRadius: function(context) {
                return Math.max(5, context.parsed.r * 15); // 심각도에 따른 크기
            }
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                type: 'linear',
                min: 0, max: 65535,
                title: { display: true, text: '포트 번호' }
            },
            y: {
                beginAtZero: true,
                title: { display: true, text: '공격 횟수' }
            }
        },
        plugins: {
            title: { display: true, text: '포트별 스캔 공격 분석' }
        }
    }
}
```

###  **4. RF 및 RL 학습 결과 시각화**

#### **4-1. RF 모델 성능 지표 대시보드 예시**
```javascript
const rfPerformanceMetrics = {
    f1_score: {
        type: 'gauge',
        value: 0.95, // KISTI RF F1 Score
        min: 0, max: 1,
        thresholds: [
            { value: 0.7, color: '#E74C3C' },
            { value: 0.85, color: '#F39C12' },
            { value: 1.0, color: '#2ECC71' }
        ],
        title: 'F1 Score'
    },
    pr_auc: {
        type: 'gauge', 
        value: 0.9946, // KISTI RF PR-AUC
        min: 0, max: 1,
        title: 'PR-AUC'
    },
    mcc: {
        type: 'gauge',
        value: 0.7326, // KISTI RF MCC
        min: -1, max: 1,
        title: 'Matthews Correlation Coefficient'
    }
}
```

#### **4-2. RL 대응 결과 및 보상 분석**
```javascript
const rlResponseAnalysis = {
    actionFrequency: {
        type: 'pie',
        data: {
            labels: ['허용', '임시차단', '영구차단', '레이트제한', '추가검사', '격리'],
            datasets: [{
                data: [], // 각 액션 선택 횟수
                backgroundColor: [
                    '#95A5A6', '#3498DB', '#E74C3C', 
                    '#F39C12', '#9B59B6', '#1ABC9C'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'RL 대응 액션 선택 분포' }
            }
        }
    }
}
```

---

## 대시보드 레이아웃 설계 예시

###  **메인 대시보드 레이아웃**

```html
<!DOCTYPE html>
<html>
<head>
    <title>IPS 실시간 모니터링 대시보드</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <!-- 헤더 영역 -->
    <header class="dashboard-header">
        <div class="system-status">
            <h1>🛡️ IPS 실시간 모니터링 대시보드</h1>
            <div class="status-indicators">
                <span class="uptime">⏱️ 가동시간: <span id="uptime">00:00:00</span></span>
                <span class="mode">🛡️ 모드: <span id="mode">LIGHTWEIGHT</span></span>
                <span class="interface">📡 인터페이스: <span id="interface">WiFi</span></span>
            </div>
        </div>
    </header>

    <!-- 메인 컨텐츠 그리드 -->
    <main class="dashboard-grid">
        <!-- 1행: 실시간 통계 카드들 -->
        <section class="stats-cards">
            <div class="stat-card packets">
                <h3>📦 패킷 캡처</h3>
                <div class="metric">
                    <span class="value" id="total-packets">0</span>
                    <span class="unit">개</span>
                </div>
                <div class="sub-metrics">
                    <span>초당: <span id="packets-per-sec">0</span>/s</span>
                    <span>최고: <span id="peak-pps">0</span>/s</span>
                </div>
            </div>
            
            <div class="stat-card threats">
                <h3>🚨 위협 탐지</h3>
                <div class="metric">
                    <span class="value" id="threat-count">0</span>
                    <span class="unit">개</span>
                </div>
                <div class="threat-levels">
                    <span class="high">🔴 <span id="high-threats">0</span></span>
                    <span class="medium">🟡 <span id="medium-threats">0</span></span>
                    <span class="low">🟢 <span id="low-threats">0</span></span>
                </div>
            </div>
        </section>

        <!-- 2행: 주요 차트 영역 -->
        <section class="main-charts">
            <div class="chart-container large">
                <canvas id="traffic-classification-chart"></canvas>
            </div>
            <div class="chart-container medium">
                <canvas id="threat-level-chart"></canvas>
            </div>
        </section>
    </main>
</body>
</html>
```

---

## 데이터 소스 및 API 설계

###  **실시간 데이터 API**

#### **WebSocket 엔드포인트**
```python
websocket_endpoints = {
    '/ws/realtime-stats': {
        'update_interval': 3,  # 3초마다 업데이트
        'data_structure': {
            'timestamp': 'ISO 8601 형식',
            'packet_stats': {
                'total_captured': '누적 패킷 수',
                'packets_per_second': '초당 패킷 수',
                'peak_pps': '최고 처리량'
            },
            'threat_stats': {
                'total_analyzed': '분석된 패킷 수',
                'by_level': {'high': 0, 'medium': 0, 'low': 0, 'safe': 0}
            },
            'protocol_stats': {
                'TCP': {'count': 0, 'percentage': 0.0},
                'UDP': {'count': 0, 'percentage': 0.0},
                'ICMP': {'count': 0, 'percentage': 0.0}
            }
        }
    }
}
```

#### **REST API 엔드포인트**
```python
rest_endpoints = {
    'GET /api/traffic/history': {
        'params': {
            'start_time': 'ISO 8601',
            'end_time': 'ISO 8601', 
            'classification': 'normal/attack/suspicious/all'
        },
        'response': {
            'data': [
                {
                    'timestamp': 'ISO 8601',
                    'source': 'IP:PORT',
                    'destination': 'IP:PORT',
                    'protocol': '프로토콜명',
                    'length': '패킷 크기',
                    'classification': 'normal/attack',
                    'threat_level': 'high/medium/low/safe'
                }
            ]
        }
    }
}
```

---

## 기술 스택 및 구현 방안 예시시

###  **프론트엔드 기술 스택**

```json
{
    "dependencies": {
        "react": "^18.2.0",
        "chart.js": "^4.4.0",
        "react-chartjs-2": "^5.2.0",
        "socket.io-client": "^4.7.0",
        "axios": "^1.5.0",
        "moment": "^2.29.0",
        "ag-grid-react": "^30.2.0"
    }
}
```

###  **백엔드 API 서버**

```python
# Flask 기반 실시간 API
from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

class IPSDataManager:
    def __init__(self):
        self.realtime_stats = {}
        self.attack_history = []
        
    def update_realtime_stats(self, stats_data):
        self.realtime_stats = stats_data
        socketio.emit('stats_update', stats_data)
```

---

## 구현 우선순위 및 일정 예시시

###  **Phase 1: 기본 실시간 대시보드**

#### **Week 1: 백엔드 API 구축**
- [ ] Flask 기반 API 서버 구현
- [ ] WebSocket 실시간 데이터 스트리밍
- [ ] 캡처된 패킷 파일 파싱 시스템
- [ ] IPSAgent_RL.py와 데이터 연동

#### **Week 2: 프론트엔드 기본 차트**
- [ ] React 기반 대시보드 구조
- [ ] 실시간 트래픽 분류 라인 차트
- [ ] 위협 수준별 도넛 차트
- [ ] 프로토콜 분석 바 차트

###  **Phase 2: 고급 분석 차트**

#### **Week 3: 공격 분석 시각화**
- [ ] 공격 유형별 분류 차트
- [ ] 패킷 크기 분포 히스토그램
- [ ] 공격 빈도 히트맵
- [ ] 실시간 공격 트래픽 테이블

#### **Week 4: 포트 보안 분석**
- [ ] 포트별 공격 대상 스캐터 차트
- [ ] 포트 보안 매트릭스
- [ ] 포트별 통계 레이더 차트

### Phase 3: AI/ML 성능 분석 

#### **Week 5: ML 성능 시각화**
- [ ] RF 성능 지표 게이지들
- [ ] 혼동 행렬 히트맵
- [ ] RL 학습 곡선 차트
- [ ] RL 대응 적절성 분석

---

## 예상 구현 결과

### 📱 **최종 대시보드 미리보기**
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ IPS 실시간 모니터링 대시보드 │
│ ⏱️ 가동시간: 02:15:30 | 🛡️ 모드: PERFORMANCE | 📡 인터페이스: WiFi │
├─────────────────────────────────────────────────────────────────────────────┤
│ [📦 패킷:15,240] [🚨 위협:45] [🛡️ 차단:12] [🤖 정확도:95%] │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌─[실시간 트래픽 분류]─────────┐ ┌─[위협 수준 분포]─┐ ┌─[프로토콜 분석]─┐ │
│ │ 📈 라인 차트 │ │ 🍩 도넛 차트 │ │ 📊 바 차트 │ │
│ │ ┌───────────────────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────┐ │ │
│ │ │ 정상: ████████████████ │ │ │ │ 안전: 85% │ │ │ │TCP: ████ 60%│ │ │
│ │ │ 공격: ██████ │ │ │ │ 낮음: 10% │ │ │ │UDP: ██ 25% │ │ │
│ │ │ 의심: ████ │ │ │ │ 중간: 4% │ │ │ │ICMP: █ 15% │ │ │
│ │ │ │ │ │ │ 높음: 1% │ │ │ │ │ │ │
│ │ └───────────────────────────┘ │ │ └─────────────┘ │ │ └─────────────┘ │ │
│ └─────────────────────────────────┘ └─────────────────┘ └─────────────────┘ │
│ │
│ ┌─[공격 유형별 분석]───────────────────┐ ┌─[패킷 크기 분포]─┐ │
│ │ 📊 수평 바 차트 │ │ 📊 히스토그램 │ │
│ │ DDoS ████████████ 45% │ │ 0-64B ████ │ │
│ │ Port Scan ████████ 30% │ │ 65-512B ████████ │ │
│ │ Web Attack ████ 15% │ │ 513-1K ██████ │ │
│ │ Brute Force ██ 10% │ │ 1K-1.5K ████ │ │
│ └─────────────────────────────────────┘ │ 1.5K+ ██ │ │
│ └─────────────────┘ │
│ │
│ ┌─[실시간 공격 트래픽 테이블]─────────────────────────────────────────────────┐ │
│ │ 시간 │출발IP │목적IP │프로토콜│크기 │유형 │위험도│RL대응 │ │
│ │ 14:25:30 │192.168.1.100│10.0.0.1 │TCP │1460 │DDoS │높음 │영구차단│ │
│ │ 14:25:28 │203.0.113.5 │10.0.0.1 │TCP │64 │Port Scan│중간 │임시차단│ │
│ │ 14:25:25 │198.51.100.3 │10.0.0.1 │UDP │512 │Flood │낮음 │레이트제한│ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
