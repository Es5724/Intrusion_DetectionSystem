# IPS 대시보드 시각화 설계서

> **문서 버전**: v1.0  
> **작성일**: 2025-09-16  
> **담당자**: IPS 시각화팀  
> **목적**: 현재 IPS 시스템의 데이터를 기반으로 한 종합적 시각화 대시보드 설계

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

### 📊 **현재 대시보드에서 표시되는 정보**

#### **1. 실시간 CLI 대시보드 (IPSAgent_RL.py)**
```python
# 현재 3초마다 업데이트되는 정보
실시간_대시보드_정보 = {
    '시스템_상태': {
        '가동시간': 'HH:MM:SS 형식',
        '운영모드': 'LIGHTWEIGHT/PERFORMANCE',
        '인터페이스': '네트워크 인터페이스명',
        '지연_로딩_상태': '등록/로딩된 모듈 수'
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
        '모델_정확도': 'KISTI RF 정확도',
        '업데이트': '모델 업데이트 횟수',
        '메모리': 'MB (백분율)',
        'CPU': 'CPU 사용률',
        '리소스_상태': '여유/보통/부하',
        '지연_로딩_통계': '모듈/모델 로딩 상태'
    }
}
```

#### **2. 캡처된 패킷 데이터 구조**
```python
# captured_packets_*.csv 파일 구조 (실제 확인됨)
패킷_데이터_스키마 = {
    'source': 'IP:PORT (출발지) - 예: 192.168.0.32',
    'destination': 'IP:PORT (목적지) - 예: 104.18.19.125', 
    'protocol': '프로토콜 번호 (6=TCP, 17=UDP, 1=ICMP)',
    'length': '패킷 크기 (bytes) - 예: 948, 64294',
    'ttl': 'Time To Live - 현재 대부분 0',
    'flags': 'TCP 플래그 - 현재 대부분 0'
}

# 실제 캡처된 데이터 예시 (captured_packets_20250916_013156.csv)
실제_패킷_예시 = [
    "192.168.0.32,104.18.19.125,6,948,0,0",     # 일반 TCP 패킷
    "192.168.0.30,224.0.0.251,17,510,0,0",      # UDP 멀티캐스트
    "192.168.0.32,3.209.139.157,6,64294,0,0",   # 대용량 TCP 패킷 (의심)
    "118.214.79.16,192.168.0.32,6,1514,0,0"     # 외부 IP 접근
]
```

#### **3. KISTI 데이터 분석 결과 (사용 가능)**
```python
# processed_data/에서 사용 가능한 분석 데이터
KISTI_분석_데이터 = {
    'kisti_data_analysis.png': '전체 데이터 분포 차트',
    'kisti_detailed_analysis.png': '상세 공격 유형 분석', 
    'kisti_network_behavior.png': '네트워크 행동 패턴',
    'kisti_statistics_report.txt': '통계 보고서',
    'rf_evaluation_results.json': 'RF 모델 성능 지표 (F1=0.95, PR-AUC=0.9946)',
    'kisti_quick_train.csv': 'KISTI 훈련 데이터',
    'kisti_quick_test.csv': 'KISTI 테스트 데이터'
}
```

---

## 시각화 요구사항 상세 분석

### 🎯 **1. 트래픽 분류 결과 시각화**

#### **1-1. 시간대별 트래픽 분류 라인 차트**
```javascript
// 실시간 라인 차트 - 3초마다 업데이트
const trafficClassificationChart = {
    type: 'line',
    data: {
        datasets: [
            {
                label: '정상 트래픽 (Safe)',
                data: [], // threat_stats['safe'] 데이터
                borderColor: '#2ECC71',
                backgroundColor: 'rgba(46, 204, 113, 0.1)',
                tension: 0.4
            },
            {
                label: '공격 트래픽 (High+Medium)',
                data: [], // threat_stats['high'] + threat_stats['medium']
                borderColor: '#E74C3C',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                tension: 0.4
            },
            {
                label: '의심 트래픽 (Low)',
                data: [], // threat_stats['low'] 데이터
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
            title: { display: true, text: '실시간 트래픽 분류 현황 (3초 업데이트)' },
            streaming: {
                duration: 300000, // 5분간 데이터 유지
                refresh: 3000,    // 3초마다 새로고침
                delay: 1000       // 1초 지연
            }
        }
    }
}
```

#### **1-2. 위협 수준별 분포 도넛 차트**
```javascript
const threatLevelChart = {
    type: 'doughnut',
    data: {
        labels: ['안전', '낮음', '중간', '높음'],
        datasets: [{
            data: [], // [threat_stats.safe, .low, .medium, .high]
            backgroundColor: [
                '#95A5A6',  // 안전 - 회색
                '#2ECC71',  // 낮음 - 초록
                '#F39C12',  // 중간 - 주황  
                '#E74C3C'   // 높음 - 빨강
            ],
            borderWidth: 2,
            borderColor: '#34495E'
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { position: 'right' },
            title: { display: true, text: '위협 수준별 실시간 분포' },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        const total = context.dataset.data.reduce((a,b) => a+b, 0);
                        const percentage = ((context.parsed / total) * 100).toFixed(1);
                        return `${context.label}: ${context.parsed.toLocaleString()}개 (${percentage}%)`;
                    }
                }
            }
        }
    }
}
```

### 🚨 **2. 공격 트래픽 상세 분석**

#### **2-1. 공격 유형별 분류 바 차트**
```javascript
// analyze_threat_level() 함수 결과 기반
const attackTypeChart = {
    type: 'horizontalBar',
    data: {
        labels: ['SYN 플러드', '대용량 패킷', '의심 포트', '외부 접근', '기타'],
        datasets: [{
            label: '탐지 횟수',
            data: [], // 각 공격 유형별 탐지 횟수
            backgroundColor: [
                '#FF6B6B', // SYN 플러드
                '#4ECDC4', // 대용량 패킷
                '#45B7D1', // 의심 포트
                '#96CEB4', // 외부 접근
                '#FFEAA7'  // 기타
            ],
            borderColor: '#2C3E50',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                beginAtZero: true,
                title: { display: true, text: '탐지 횟수' }
            }
        },
        plugins: {
            title: { display: true, text: '공격 유형별 탐지 현황' },
            tooltip: {
                callbacks: {
                    afterLabel: function(context) {
                        return `위험도: ${getAttackSeverity(context.label)}`;
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
    type: 'matrix',
    data: {
        datasets: [{
            label: '공격 빈도',
            data: [], // [{x: hour, y: attack_type, v: frequency}]
            backgroundColor: function(context) {
                const value = context.parsed.v;
                const maxValue = 50; // 최대 예상 공격 수
                const alpha = Math.min(value / maxValue, 1);
                return `rgba(231, 76, 60, ${alpha})`;
            },
            borderColor: '#34495E',
            borderWidth: 1,
            width: ({chart}) => (chart.chartArea || {}).width / 24,
            height: ({chart}) => (chart.chartArea || {}).height / 5
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                type: 'linear',
                position: 'bottom',
                min: 0,
                max: 23,
                ticks: {
                    stepSize: 1,
                    callback: function(value) {
                        return value + '시';
                    }
                },
                title: { display: true, text: '시간 (24시간)' }
            },
            y: {
                type: 'category',
                labels: ['SYN 플러드', '대용량 패킷', '의심 포트', '외부 접근', '기타'],
                title: { display: true, text: '공격 유형' }
            }
        },
        plugins: {
            title: { display: true, text: '시간대별 공격 빈도 히트맵' },
            tooltip: {
                callbacks: {
                    title: function(context) {
                        return `${context[0].parsed.x}시 - ${context[0].label}`;
                    },
                    label: function(context) {
                        return `공격 횟수: ${context.parsed.v}회`;
                    }
                }
            }
        }
    }
}
```

#### **2-3. 공격 트래픽 상세 정보 테이블**
```javascript
// 실시간 공격 트래픽 테이블 (AG-Grid 사용)
const attackTrafficTable = {
    columnDefs: [
        { 
            field: 'timestamp', 
            headerName: '탐지 시간', 
            width: 150,
            cellRenderer: function(params) {
                return new Date(params.value).toLocaleTimeString();
            }
        },
        { 
            field: 'source_ip', 
            headerName: '출발 IP', 
            width: 120,
            cellStyle: function(params) {
                // 외부 IP는 빨간색으로 표시
                if (!params.value.startsWith('192.168.')) {
                    return { color: '#E74C3C', fontWeight: 'bold' };
                }
                return null;
            }
        },
        { field: 'dest_ip', headerName: '목적 IP', width: 120 },
        { 
            field: 'protocol', 
            headerName: '프로토콜', 
            width: 80,
            valueFormatter: function(params) {
                const protocolMap = { '6': 'TCP', '17': 'UDP', '1': 'ICMP' };
                return protocolMap[params.value] || params.value;
            }
        },
        { 
            field: 'packet_size', 
            headerName: '패킷 크기', 
            width: 100,
            cellStyle: function(params) {
                // 대용량 패킷은 주황색으로 표시
                if (params.value > 5000) {
                    return { color: '#F39C12', fontWeight: 'bold' };
                }
                return null;
            },
            valueFormatter: function(params) {
                return `${params.value.toLocaleString()} B`;
            }
        },
        { 
            field: 'attack_type', 
            headerName: '공격 유형', 
            width: 120,
            cellStyle: { color: '#E74C3C' }
        },
        { 
            field: 'threat_level', 
            headerName: '위험도', 
            width: 80,
            cellRenderer: function(params) {
                const levelIcons = {
                    'high': '🔴',
                    'medium': '🟡', 
                    'low': '🟢',
                    'safe': '⚪'
                };
                return `${levelIcons[params.value]} ${params.value}`;
            }
        },
        { 
            field: 'rf_confidence', 
            headerName: 'RF 신뢰도', 
            width: 100,
            valueFormatter: function(params) {
                return `${(params.value * 100).toFixed(1)}%`;
            }
        },
        { 
            field: 'rl_action', 
            headerName: 'RL 대응', 
            width: 100,
            cellRenderer: function(params) {
                const actionIcons = {
                    'allow': '✅', 'block_temporary': '⏰',
                    'block_permanent': '🚫', 'rate_limit': '⚡',
                    'deep_inspection': '🔍', 'isolate_session': '🔒'
                };
                return `${actionIcons[params.value]} ${params.value}`;
            }
        },
        { 
            field: 'status', 
            headerName: '처리 상태', 
            width: 100,
            cellStyle: function(params) {
                return params.value === 'blocked' ? 
                    { color: '#E74C3C' } : { color: '#2ECC71' };
            }
        }
    ],
    defaultColDef: {
        sortable: true,
        filter: true,
        resizable: true
    },
    pagination: true,
    paginationPageSize: 20,
    enableRangeSelection: true,
    enableCellTextSelection: true
}
```

#### **2-4. 패킷 크기 분포 히스토그램**
```javascript
// captured_packets_*.csv의 length 필드 기반
const packetSizeDistribution = {
    type: 'bar',
    data: {
        labels: ['0-64B', '65-512B', '513-1024B', '1025-1518B', '1519-5000B', '5000B+'],
        datasets: [
            {
                label: '정상 트래픽',
                data: [], // 각 크기 범위별 정상 패킷 수
                backgroundColor: 'rgba(46, 204, 113, 0.7)',
                borderColor: '#27AE60',
                borderWidth: 1
            },
            {
                label: '공격 트래픽',
                data: [], // 각 크기 범위별 공격 패킷 수
                backgroundColor: 'rgba(231, 76, 60, 0.7)',
                borderColor: '#C0392B',
                borderWidth: 1
            }
        ]
    },
    options: {
        responsive: true,
        scales: {
            x: { title: { display: true, text: '패킷 크기 범위' } },
            y: { 
                beginAtZero: true,
                title: { display: true, text: '패킷 수' }
            }
        },
        plugins: {
            title: { display: true, text: '패킷 크기별 분포 분석' },
            tooltip: {
                mode: 'index',
                intersect: false,
                callbacks: {
                    afterLabel: function(context) {
                        const total = context.dataset.data.reduce((a,b) => a+b, 0);
                        const percentage = ((context.parsed.y / total) * 100).toFixed(1);
                        return `전체의 ${percentage}%`;
                    }
                }
            }
        }
    }
}
```

### 🔍 **3. 포트스캔 탐지 및 대처 시각화**

#### **3-1. 포트별 공격 대상 스캐터 차트**
```javascript
// port_scan_detector.py 결과 기반
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
            },
            pointHoverRadius: function(context) {
                return Math.max(8, context.parsed.r * 20);
            }
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                type: 'linear',
                position: 'bottom',
                min: 0,
                max: 65535,
                title: { display: true, text: '포트 번호' },
                ticks: {
                    callback: function(value) {
                        // 주요 포트 표시
                        const majorPorts = {
                            22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
                            21: 'FTP', 25: 'SMTP', 53: 'DNS'
                        };
                        return majorPorts[value] || value;
                    }
                }
            },
            y: {
                beginAtZero: true,
                title: { display: true, text: '공격 횟수' }
            }
        },
        plugins: {
            title: { display: true, text: '포트별 스캔 공격 분석' },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        const portServices = {
                            22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
                            21: 'FTP', 25: 'SMTP', 53: 'DNS'
                        };
                        const service = portServices[context.parsed.x] || '알 수 없음';
                        return [
                            `포트: ${context.parsed.x} (${service})`,
                            `공격 횟수: ${context.parsed.y}회`,
                            `위험도: ${(context.parsed.r * 100).toFixed(1)}%`
                        ];
                    }
                }
            }
        }
    }
}
```

#### **3-2. 열린 포트 vs 공격 대상 매트릭스**
```javascript
const portSecurityMatrix = {
    type: 'matrix',
    data: {
        datasets: [{
            label: '포트 보안 상태',
            data: [], // [{x: port, y: status, v: attack_count}]
            backgroundColor: function(context) {
                const status = context.parsed.y; // 0=닫힘, 1=열림
                const attacks = context.parsed.v;
                
                if (status === 1 && attacks > 0) return '#E74C3C'; // 열린 포트 + 공격
                if (status === 1 && attacks === 0) return '#F39C12'; // 열린 포트 + 공격없음
                if (status === 0 && attacks > 0) return '#3498DB'; // 닫힌 포트 + 공격시도
                return '#95A5A6'; // 닫힌 포트 + 공격없음
            },
            borderColor: '#2C3E50',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            title: { display: true, text: '포트 상태 vs 공격 현황 매트릭스' },
            legend: {
                display: true,
                labels: {
                    generateLabels: function() {
                        return [
                            { text: '🔴 열린 포트 + 공격받음', fillStyle: '#E74C3C' },
                            { text: '🟡 열린 포트 + 안전', fillStyle: '#F39C12' },
                            { text: '🔵 닫힌 포트 + 공격시도', fillStyle: '#3498DB' },
                            { text: '⚪ 닫힌 포트 + 안전', fillStyle: '#95A5A6' }
                        ];
                    }
                }
            },
            tooltip: {
                callbacks: {
                    title: function(context) {
                        const port = context[0].parsed.x;
                        const status = context[0].parsed.y === 1 ? '열림' : '닫힘';
                        return `포트 ${port} (${status})`;
                    },
                    label: function(context) {
                        return `공격 시도: ${context.parsed.v}회`;
                    }
                }
            }
        }
    }
}
```

#### **3-3. 포트별 스캔 통계 레이더 차트**
```javascript
const portScanStatistics = {
    type: 'radar',
    data: {
        labels: ['HTTP(80)', 'HTTPS(443)', 'SSH(22)', 'FTP(21)', 'Telnet(23)', 'SMTP(25)', 'DNS(53)', 'Custom'],
        datasets: [
            {
                label: '스캔 시도 횟수',
                data: [], // 각 포트별 스캔 횟수
                backgroundColor: 'rgba(231, 76, 60, 0.2)',
                borderColor: '#E74C3C',
                borderWidth: 2,
                pointBackgroundColor: '#E74C3C',
                pointBorderColor: '#fff',
                pointBorderWidth: 2
            },
            {
                label: '성공적 차단',
                data: [], // 각 포트별 차단 성공 횟수
                backgroundColor: 'rgba(46, 204, 113, 0.2)',
                borderColor: '#2ECC71',
                borderWidth: 2,
                pointBackgroundColor: '#2ECC71',
                pointBorderColor: '#fff',
                pointBorderWidth: 2
            }
        ]
    },
    options: {
        responsive: true,
        scales: {
            r: {
                beginAtZero: true,
                title: { display: true, text: '공격/차단 횟수' },
                ticks: {
                    stepSize: 10
                }
            }
        },
        plugins: {
            title: { display: true, text: '주요 포트별 스캔 공격 및 차단 현황' },
            legend: { position: 'top' }
        }
    }
}
```

### 🤖 **4. RF 및 RL 학습 결과 시각화**

#### **4-1. RF 모델 성능 지표 대시보드**
```javascript
// KISTI RF 모델 성능 지표 (실제 값 반영)
const rfPerformanceMetrics = {
    f1_score: {
        type: 'gauge',
        value: 0.95, // KISTI RF 실제 F1 Score
        min: 0,
        max: 1,
        thresholds: [
            { value: 0.7, color: '#E74C3C' },
            { value: 0.85, color: '#F39C12' },
            { value: 1.0, color: '#2ECC71' }
        ],
        title: 'F1 Score',
        subtitle: 'KISTI-IDS-2022 기반'
    },
    pr_auc: {
        type: 'gauge', 
        value: 0.9946, // KISTI RF 실제 PR-AUC
        min: 0,
        max: 1,
        thresholds: [
            { value: 0.8, color: '#E74C3C' },
            { value: 0.9, color: '#F39C12' },
            { value: 1.0, color: '#2ECC71' }
        ],
        title: 'PR-AUC',
        subtitle: '정밀도-재현율 곡선 하 면적'
    },
    mcc: {
        type: 'gauge',
        value: 0.7326, // KISTI RF 실제 MCC
        min: -1,
        max: 1,
        thresholds: [
            { value: 0.3, color: '#E74C3C' },
            { value: 0.6, color: '#F39C12' },
            { value: 1.0, color: '#2ECC71' }
        ],
        title: 'MCC',
        subtitle: 'Matthews Correlation Coefficient'
    },
    class_distribution: {
        type: 'pie',
        data: {
            labels: ['정상 트래픽', '공격 트래픽'],
            datasets: [{
                data: [80, 20], // KISTI 실제 클래스 분포 80:20
                backgroundColor: ['#2ECC71', '#E74C3C']
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: 'KISTI 데이터셋 클래스 분포' }
            }
        }
    }
}
```

#### **4-2. RL 대응 결과 및 보상 분석**
```javascript
const rlResponseAnalysis = {
    // RL 액션별 선택 빈도
    actionFrequency: {
        type: 'pie',
        data: {
            labels: ['허용', '임시차단', '영구차단', '레이트제한', '추가검사', '격리'],
            datasets: [{
                data: [], // Conservative RL Agent의 각 액션 선택 횟수
                backgroundColor: [
                    '#95A5A6', // 허용 - 회색
                    '#3498DB', // 임시차단 - 파랑
                    '#E74C3C', // 영구차단 - 빨강
                    '#F39C12', // 레이트제한 - 주황
                    '#9B59B6', // 추가검사 - 보라
                    '#1ABC9C'  // 격리 - 청록
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Conservative RL 대응 액션 선택 분포' },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a,b) => a+b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed}회 (${percentage}%)`;
                        }
                    }
                }
            }
        }
    },
    
    // 위험도별 RL 대응 적절성 분석
    responseAppropriatenessMatrix: {
        type: 'bar',
        data: {
            labels: ['높음(0.9+)', '중간(0.7-0.9)', '낮음(0.5-0.7)', '안전(0.5-)'],
            datasets: [
                {
                    label: '적절한 대응',
                    data: [], // 각 위험도별 적절한 대응 횟수
                    backgroundColor: '#2ECC71'
                },
                {
                    label: '과도한 대응',
                    data: [], // 각 위험도별 과도한 대응 횟수  
                    backgroundColor: '#E74C3C'
                },
                {
                    label: '부족한 대응',
                    data: [], // 각 위험도별 부족한 대응 횟수
                    backgroundColor: '#F39C12'
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                x: { title: { display: true, text: 'RF 위험도 범위' } },
                y: { 
                    beginAtZero: true,
                    title: { display: true, text: '대응 횟수' }
                }
            },
            plugins: {
                title: { display: true, text: 'RF 위험도별 RL 대응 적절성 분석' },
                tooltip: {
                    callbacks: {
                        afterLabel: function(context) {
                            // 적절성 평가 기준 설명
                            const criteria = {
                                '적절한 대응': '위험도에 맞는 적절한 수준의 대응',
                                '과도한 대응': '위험도 대비 과도한 차단/제재',
                                '부족한 대응': '위험도 대비 부족한 대응'
                            };
                            return criteria[context.dataset.label];
                        }
                    }
                }
            }
        }
    }
}
```

#### **4-3. RL 보상 추이 및 학습 곡선**
```javascript
const rlLearningCurve = {
    type: 'line',
    data: {
        datasets: [
            {
                label: '에피소드별 평균 보상',
                data: [], // [{x: episode, y: avg_reward}]
                borderColor: '#3498DB',
                backgroundColor: 'rgba(52, 152, 219, 0.1)',
                yAxisID: 'y',
                tension: 0.3
            },
            {
                label: '누적 보상',
                data: [], // [{x: episode, y: cumulative_reward}]
                borderColor: '#2ECC71',
                backgroundColor: 'rgba(46, 204, 113, 0.1)',
                yAxisID: 'y1',
                tension: 0.3
            },
            {
                label: 'Epsilon (탐험률)',
                data: [], // [{x: episode, y: epsilon}]
                borderColor: '#F39C12',
                backgroundColor: 'rgba(243, 156, 18, 0.1)',
                yAxisID: 'y2',
                borderDash: [5, 5]
            },
            {
                label: 'Conservative 페널티',
                data: [], // [{x: episode, y: conservative_penalty}]
                borderColor: '#9B59B6',
                backgroundColor: 'rgba(155, 89, 182, 0.1)',
                yAxisID: 'y',
                borderDash: [10, 5]
            }
        ]
    },
    options: {
        responsive: true,
        interaction: {
            mode: 'index',
            intersect: false
        },
        scales: {
            x: { 
                title: { display: true, text: '에피소드' }
            },
            y: { 
                type: 'linear',
                display: true,
                position: 'left',
                title: { display: true, text: '평균 보상' }
            },
            y1: {
                type: 'linear',
                display: true,
                position: 'right',
                title: { display: true, text: '누적 보상' },
                grid: { drawOnChartArea: false }
            },
            y2: {
                type: 'linear',
                display: false,
                min: 0,
                max: 1
            }
        },
        plugins: {
            title: { display: true, text: 'Conservative RL 학습 진행 곡선' },
            tooltip: {
                callbacks: {
                    afterBody: function(context) {
                        return [
                            '',
                            'Conservative Q-Learning 특징:',
                            '- 낮은 탐험률 (0.1 시작)',
                            '- Conservative 페널티로 안전한 학습',
                            '- 높은 할인율 (0.99)로 장기 안정성'
                        ];
                    }
                }
            }
        }
    }
}
```

---

## 대시보드 레이아웃 설계

### 🖥️ **메인 대시보드 레이아웃 (React 컴포넌트)**

```jsx
// MainDashboard.jsx
import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import {
    Chart as ChartJS,
    CategoryScale, LinearScale, PointElement, LineElement,
    Title, Tooltip, Legend, ArcElement, BarElement
} from 'chart.js';
import { Line, Doughnut, Bar, Scatter, Pie } from 'react-chartjs-2';

ChartJS.register(
    CategoryScale, LinearScale, PointElement, LineElement,
    Title, Tooltip, Legend, ArcElement, BarElement
);

const MainDashboard = () => {
    const [realtimeStats, setRealtimeStats] = useState({});
    const [socket, setSocket] = useState(null);

    useEffect(() => {
        // WebSocket 연결
        const newSocket = io('ws://localhost:5000');
        setSocket(newSocket);

        // 실시간 데이터 수신
        newSocket.on('stats_update', (data) => {
            setRealtimeStats(data);
        });

        // 공격 알림 수신
        newSocket.on('attack_alert', (attackData) => {
            showAttackAlert(attackData);
        });

        return () => newSocket.close();
    }, []);

    return (
        <div className="dashboard-container">
            {/* 헤더 영역 */}
            <header className="dashboard-header">
                <div className="system-status">
                    <h1>🛡️ IPS 실시간 모니터링 대시보드</h1>
                    <div className="status-indicators">
                        <StatusIndicator 
                            icon="⏱️" 
                            label="가동시간" 
                            value={realtimeStats.uptime || "00:00:00"} 
                        />
                        <StatusIndicator 
                            icon="🛡️" 
                            label="모드" 
                            value={realtimeStats.mode || "LIGHTWEIGHT"} 
                        />
                        <StatusIndicator 
                            icon="📡" 
                            label="인터페이스" 
                            value={realtimeStats.interface || "WiFi"} 
                        />
                    </div>
                </div>
            </header>

            {/* 메인 컨텐츠 그리드 */}
            <main className="dashboard-grid">
                {/* 1행: 실시간 통계 카드들 */}
                <section className="stats-cards">
                    <StatCard
                        title="📦 패킷 캡처"
                        value={realtimeStats.total_packets || 0}
                        unit="개"
                        subMetrics={[
                            `초당: ${realtimeStats.packets_per_sec || 0}/s`,
                            `최고: ${realtimeStats.peak_pps || 0}/s`
                        ]}
                        color="#3498DB"
                    />
                    
                    <StatCard
                        title="🚨 위협 탐지"
                        value={realtimeStats.threat_count || 0}
                        unit="개"
                        subMetrics={[
                            `🔴 ${realtimeStats.high_threats || 0}`,
                            `🟡 ${realtimeStats.medium_threats || 0}`,
                            `🟢 ${realtimeStats.low_threats || 0}`
                        ]}
                        color="#E74C3C"
                    />
                    
                    <StatCard
                        title="🛡️ 방어 조치"
                        value={realtimeStats.blocked_ips || 0}
                        unit="개 차단"
                        subMetrics={[
                            `모니터링: ${realtimeStats.monitoring || 0}`,
                            `알림: ${realtimeStats.alerts || 0}`
                        ]}
                        color="#9B59B6"
                    />
                    
                    <StatCard
                        title="🤖 AI/ML 엔진"
                        value={`${(realtimeStats.ml_accuracy * 100 || 0).toFixed(1)}%`}
                        unit="정확도"
                        subMetrics={[
                            `예측: ${realtimeStats.predictions || 0}회`,
                            `메모리: ${realtimeStats.memory_usage || 0}MB`
                        ]}
                        color="#2ECC71"
                    />
                </section>

                {/* 2행: 주요 차트 영역 */}
                <section className="main-charts">
                    <div className="chart-container large">
                        <Line 
                            data={trafficClassificationData}
                            options={trafficClassificationOptions}
                        />
                    </div>
                    
                    <div className="chart-container medium">
                        <Doughnut 
                            data={threatLevelData}
                            options={threatLevelOptions}
                        />
                    </div>
                    
                    <div className="chart-container medium">
                        <Bar 
                            data={protocolAnalysisData}
                            options={protocolAnalysisOptions}
                        />
                    </div>
                </section>

                {/* 3행: 공격 분석 영역 */}
                <section className="attack-analysis">
                    <div className="chart-container large">
                        <Bar 
                            data={attackTypeData}
                            options={attackTypeOptions}
                        />
                    </div>
                    
                    <div className="chart-container medium">
                        <Bar 
                            data={packetSizeData}
                            options={packetSizeOptions}
                        />
                    </div>
                    
                    <div className="chart-container medium">
                        {/* 공격 빈도 히트맵 */}
                        <HeatmapChart data={attackFrequencyData} />
                    </div>
                </section>

                {/* 4행: 포트 보안 분석 */}
                <section className="port-security">
                    <div className="chart-container large">
                        <Scatter 
                            data={portTargetData}
                            options={portTargetOptions}
                        />
                    </div>
                    
                    <div className="chart-container medium">
                        {/* 포트 보안 매트릭스 */}
                        <MatrixChart data={portSecurityData} />
                    </div>
                    
                    <div className="chart-container medium">
                        <Radar 
                            data={portScanData}
                            options={portScanOptions}
                        />
                    </div>
                </section>

                {/* 5행: AI/ML 성능 분석 */}
                <section className="ai-ml-performance">
                    <div className="chart-container large">
                        <div className="metrics-grid">
                            <GaugeChart {...rfPerformanceMetrics.f1_score} />
                            <GaugeChart {...rfPerformanceMetrics.pr_auc} />
                            <GaugeChart {...rfPerformanceMetrics.mcc} />
                        </div>
                    </div>
                    
                    <div className="chart-container large">
                        <Line 
                            data={rlLearningCurveData}
                            options={rlLearningCurveOptions}
                        />
                    </div>
                </section>

                {/* 6행: 상세 정보 테이블 */}
                <section className="detailed-tables">
                    <div className="table-container">
                        <h3>🚨 실시간 공격 트래픽</h3>
                        <AttackTrafficTable data={attackTrafficData} />
                    </div>
                    
                    <div className="table-container">
                        <h3>🤖 RL 대응 이력</h3>
                        <RLResponseTable data={rlResponseData} />
                    </div>
                </section>
            </main>

            {/* 사이드 패널 */}
            <aside className="side-panel">
                <div className="control-panel">
                    <h3>🎛️ 시스템 제어</h3>
                    <button onClick={toggleMode}>모드 전환</button>
                    <button onClick={exportData}>데이터 내보내기</button>
                    <button onClick={showSystemStatus}>시스템 상태</button>
                </div>
                
                <div className="alert-panel">
                    <h3>🚨 실시간 알림</h3>
                    <RealtimeAlerts alerts={realtimeAlerts} />
                </div>
                
                <div className="blocked-ips">
                    <h3>🚫 차단된 IP</h3>
                    <BlockedIPList ips={blockedIPs} />
                </div>
                
                <div className="lazy-loading-status">
                    <h3>🔥 지연 로딩 상태</h3>
                    <LazyLoadingStatus stats={realtimeStats.lazy_stats} />
                </div>
            </aside>
        </div>
    );
};

export default MainDashboard;
```

---

## 데이터 소스 및 API 설계

### 📡 **실시간 데이터 수집 시스템**

#### **IPSAgent_RL.py 연동 데이터 수집기**
```python
# realtime_data_bridge.py
import threading
import time
import json
from datetime import datetime
import glob
import pandas as pd

class IPSDataBridge:
    """IPSAgent_RL.py와 웹 대시보드 간 데이터 브릿지"""
    
    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
        self.is_running = False
        self.collection_thread = None
        
        # 데이터 캐시
        self.packet_cache = []
        self.attack_cache = []
        self.port_scan_cache = []
        
    def start_data_collection(self):
        """데이터 수집 시작"""
        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collection_loop)
        self.collection_thread.daemon = True
        self.collection_thread.start()
    
    def _collection_loop(self):
        """실시간 데이터 수집 루프"""
        while self.is_running:
            try:
                # 1. 실시간 통계 수집
                current_stats = self._extract_realtime_stats()
                self.socketio.emit('stats_update', current_stats)
                
                # 2. 새로운 패킷 파일 확인
                new_packets = self._check_new_packet_files()
                if new_packets:
                    self._process_new_packets(new_packets)
                
                # 3. 공격 이벤트 확인
                new_attacks = self._detect_attack_events()
                for attack in new_attacks:
                    self.socketio.emit('attack_alert', attack)
                
                # 4. 포트 스캔 이벤트 확인
                new_port_scans = self._detect_port_scan_events()
                for scan in new_port_scans:
                    self.socketio.emit('port_scan_alert', scan)
                
            except Exception as e:
                print(f"데이터 수집 오류: {e}")
            
            time.sleep(3)  # 3초마다 수집
    
    def _extract_realtime_stats(self):
        """IPSAgent_RL.py의 전역 변수에서 실시간 통계 추출"""
        # 실제 구현에서는 IPSAgent_RL.py의 전역 변수들에 접근
        # 또는 로그 파일 파싱, 공유 메모리 사용 등
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system_stats': {
                'uptime': self._get_system_uptime(),
                'mode': self._get_current_mode(),
                'interface': self._get_network_interface()
            },
            'packet_stats': {
                'total_captured': self._get_total_packets(),
                'packets_per_second': self._get_packets_per_second(),
                'peak_pps': self._get_peak_pps(),
                'queue_size': self._get_queue_size()
            },
            'protocol_stats': self._get_protocol_distribution(),
            'threat_stats': self._get_threat_distribution(),
            'defense_stats': self._get_defense_statistics(),
            'ml_stats': self._get_ml_statistics(),
            'lazy_loading_stats': self._get_lazy_loading_stats()
        }
    
    def _check_new_packet_files(self):
        """새로운 패킷 파일 확인"""
        packet_files = glob.glob('IDS/captured_packets_*.csv')
        new_files = []
        
        for file_path in packet_files:
            file_mtime = os.path.getmtime(file_path)
            if file_mtime > self.last_check_time:
                new_files.append(file_path)
        
        self.last_check_time = time.time()
        return new_files
    
    def _process_new_packets(self, file_paths):
        """새로운 패킷 파일 처리"""
        for file_path in file_paths:
            try:
                df = pd.read_csv(file_path)
                
                # 패킷 분류 및 분석
                for _, row in df.iterrows():
                    packet_analysis = self._analyze_packet(row)
                    
                    if packet_analysis['is_attack']:
                        self.attack_cache.append(packet_analysis)
                    
                    if packet_analysis['is_port_scan']:
                        self.port_scan_cache.append(packet_analysis)
                
            except Exception as e:
                print(f"패킷 파일 처리 오류 {file_path}: {e}")
```

---

## 기술 스택 및 구현 방안

### 🛠️ **프론트엔드 기술 스택**

```json
{
    "name": "ips-dashboard",
    "version": "1.0.0",
    "dependencies": {
        "react": "^18.2.0",
        "react-dom": "^18.2.0",
        "chart.js": "^4.4.0",
        "react-chartjs-2": "^5.2.0",
        "socket.io-client": "^4.7.0",
        "axios": "^1.5.0",
        "moment": "^2.29.0",
        "ag-grid-react": "^30.2.0",
        "ag-grid-community": "^30.2.0",
        "styled-components": "^6.0.0",
        "chartjs-adapter-moment": "^1.0.1",
        "chartjs-plugin-streaming": "^2.0.0",
        "chartjs-chart-matrix": "^2.0.1"
    },
    "devDependencies": {
        "vite": "^4.4.0",
        "@vitejs/plugin-react": "^4.0.0",
        "typescript": "^5.0.0",
        "@types/react": "^18.2.0"
    }
}
```

### 🔧 **백엔드 API 서버**

```python
# app.py - Flask 기반 실시간 API 서버
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import pandas as pd
import threading
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ips-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# 전역 데이터 브릿지
data_bridge = None

@app.route('/api/health')
def health_check():
    """API 서버 상태 확인"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/traffic/history')
def get_traffic_history():
    """트래픽 히스토리 조회"""
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    classification = request.args.get('classification', 'all')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 100)), 1000)
    
    # 캡처된 패킷 파일들에서 데이터 로드
    traffic_data = load_captured_packets(start_time, end_time, classification)
    
    # 페이지네이션
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_data = traffic_data[start_idx:end_idx]
    
    return jsonify({
        'data': paginated_data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': len(traffic_data),
            'has_next': end_idx < len(traffic_data)
        }
    })

@app.route('/api/attacks/types')
def get_attack_types():
    """공격 유형별 통계"""
    time_range = request.args.get('time_range', '24h')
    
    # 공격 유형별 분석 결과 반환
    attack_analysis = analyze_attack_types(time_range)
    
    return jsonify(attack_analysis)

@app.route('/api/ports/scan-analysis')
def get_port_scan_analysis():
    """포트 스캔 분석 결과"""
    time_range = request.args.get('time_range', '24h')
    target_ip = request.args.get('target_ip')
    
    port_analysis = analyze_port_scans(time_range, target_ip)
    
    return jsonify(port_analysis)

@app.route('/api/ml/performance')
def get_ml_performance():
    """ML 모델 성능 지표"""
    try:
        # RF 평가 결과 로드
        with open('IDS/processed_data/rf_evaluation_results.json', 'r') as f:
            rf_metrics = json.load(f)
        
        # RL 학습 결과 로드
        rl_metrics = load_rl_training_results()
        
        return jsonify({
            'rf_metrics': {
                'model_type': 'KISTI RandomForest',
                'f1_score': 0.95,
                'pr_auc': 0.9946,
                'mcc': 0.7326,
                'class_distribution': {'normal': 80, 'attack': 20},
                'last_updated': datetime.now().isoformat()
            },
            'rl_metrics': rl_metrics
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """클라이언트 연결 시"""
    emit('connected', {'status': 'success'})
    
    # 현재 통계 즉시 전송
    if data_bridge:
        current_stats = data_bridge._extract_realtime_stats()
        emit('stats_update', current_stats)

@socketio.on('request_system_status')
def handle_system_status_request():
    """시스템 상태 요청"""
    system_status = {
        'ips_agent_running': check_ips_agent_status(),
        'lazy_loading_stats': get_lazy_loading_status(),
        'memory_optimization': get_memory_optimization_stats(),
        'model_status': get_model_loading_status()
    }
    emit('system_status_response', system_status)

if __name__ == '__main__':
    # 데이터 브릿지 시작
    data_bridge = IPSDataBridge(socketio)
    data_bridge.start_data_collection()
    
    # Flask 서버 시작
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
```

---

## 구현 우선순위 및 일정

### 🥇 **Phase 1: 기본 실시간 대시보드 (2주)**

#### **Week 1: 백엔드 API 구축**
- [ ] Flask + Socket.IO 기반 API 서버 구현
- [ ] IPSAgent_RL.py와 실시간 데이터 연동
- [ ] captured_packets_*.csv 파일 파싱 시스템
- [ ] WebSocket 실시간 데이터 스트리밍
- [ ] 지연 로딩 상태 모니터링 API

#### **Week 2: 프론트엔드 기본 차트**
- [ ] React + TypeScript 기반 대시보드 구조
- [ ] 실시간 트래픽 분류 라인 차트
- [ ] 위협 수준별 도넛 차트  
- [ ] 프로토콜 분석 바 차트
- [ ] 기본 통계 카드들
- [ ] 지연 로딩 상태 표시 컴포넌트

### 🥈 **Phase 2: 고급 분석 차트 (2주)**

#### **Week 3: 공격 분석 시각화**
- [ ] 공격 유형별 분류 차트 (analyze_threat_level 기반)
- [ ] 패킷 크기 분포 히스토그램
- [ ] 공격 빈도 히트맵 (시간 × 공격유형)
- [ ] 실시간 공격 트래픽 테이블 (AG-Grid)

#### **Week 4: 포트 보안 분석**
- [ ] 포트별 공격 대상 스캐터 차트
- [ ] 포트 보안 매트릭스 (열린포트 vs 공격)
- [ ] 포트별 통계 레이더 차트
- [ ] 포트 스캔 이벤트 타임라인

### 🥉 **Phase 3: AI/ML 성능 분석 (1주)**

#### **Week 5: ML 성능 시각화**
- [ ] KISTI RF 성능 지표 게이지들 (F1=0.95, PR-AUC=0.9946, MCC=0.7326)
- [ ] 혼동 행렬 히트맵
- [ ] Conservative RL 학습 곡선 차트
- [ ] RL 대응 적절성 분석 매트릭스
- [ ] 보상 추이 및 액션 분포 차트

### 🏆 **Phase 4: 고급 기능 및 최적화 (1주)**

#### **Week 6: 고급 기능**
- [ ] 실시간 알림 시스템 (공격 탐지 시 즉시 알림)
- [ ] 데이터 내보내기 기능 (CSV, Excel, PDF)
- [ ] 대시보드 커스터마이징 (차트 배치, 색상 테마)
- [ ] 모바일 반응형 최적화
- [ ] 성능 최적화 및 캐싱 (지연 로딩 연동)

---

## 예상 구현 결과

### 📱 **최종 대시보드 미리보기**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ IPS 실시간 모니터링 대시보드 (지연 로딩: 125-195MB 절약)                      │
│ ⏱️ 가동시간: 02:15:30 | 🛡️ 모드: PERFORMANCE | 📡 인터페이스: WiFi          │
├─────────────────────────────────────────────────────────────────────────────┤
│ [📦 패킷:15,240] [🚨 위협:45] [🛡️ 차단:12] [🤖 KISTI RF:95%]                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ ┌─[실시간 트래픽 분류]─────────┐ ┌─[위협 수준 분포]─┐ ┌─[프로토콜 분석]─┐   │
│ │     📈 라인 차트              │ │   🍩 도넛 차트    │ │  📊 바 차트     │   │
│ │ ┌───────────────────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────┐ │   │
│ │ │ 정상: ████████████████    │ │ │ │ 안전: 85%   │ │ │ │TCP: ████ 60%│ │   │
│ │ │ 공격: ██████              │ │ │ │ 낮음: 10%   │ │ │ │UDP: ██ 25%  │ │   │
│ │ │ 의심: ████                │ │ │ │ 중간: 4%    │ │ │ │ICMP: █ 15%  │ │   │
│ │ │                           │ │ │ │ 높음: 1%    │ │ │ │             │ │   │
│ │ └───────────────────────────┘ │ │ └─────────────┘ │ │ └─────────────┘ │   │
│ └─────────────────────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                             │
│ ┌─[공격 유형별 분석]───────────────────┐ ┌─[패킷 크기 분포]─┐                │
│ │     📊 수평 바 차트                   │ │   📊 히스토그램   │                │
│ │ SYN 플러드  ████████████ 45%        │ │ 0-64B   ████     │                │
│ │ 대용량패킷  ████████ 30%            │ │ 65-512B ████████ │                │
│ │ 의심포트    ████ 15%                │ │ 513-1K  ██████   │                │
│ │ 외부접근    ██ 10%                  │ │ 1K-1.5K ████     │                │
│ └─────────────────────────────────────┘ │ 1.5K+   ██       │                │
│                                         └─────────────────┘                │
│                                                                             │
│ ┌─[포트 스캔 분석]─────────────────────┐ ┌─[RL 대응 분석]───┐                │
│ │     �� 스캐터 차트                    │ │   🥧 파이 차트    │                │
│ │ ┌───────────────────────────────────┐ │ │ 허용: 70%        │                │
│ │ │ 포트 22: ●●● (SSH 공격 다수)      │ │ │ 임시차단: 15%    │                │
│ │ │ 포트 80: ●●● (HTTP 스캔)          │ │ │ 영구차단: 5%     │                │
│ │ │ 포트 443: ●● (HTTPS 탐지)         │ │ │ 레이트제한: 8%   │                │
│ │ └───────────────────────────────────┘ │ │ 기타: 2%         │                │
│ └─────────────────────────────────────┘ └─────────────────┘                │
│                                                                             │
│ ┌─[KISTI RF 성능 지표]─────────────────┐ ┌─[Conservative RL 학습]──────────┐ │
│ │ F1: 0.95 ████████████████████████   │ │     📈 학습 곡선                 │ │
│ │ PR-AUC: 0.9946 ███████████████████  │ │ ┌─────────────────────────────┐ │ │
│ │ MCC: 0.7326 ██████████████████      │ │ │ 평균보상: ↗️ 상승            │ │ │
│ └─────────────────────────────────────┘ │ │ Epsilon: ↘️ 감소 (0.1→0.01) │ │ │
│                                         │ │ 페널티: 안정적               │ │ │
│ ┌─[실시간 공격 트래픽 테이블]─────────────┐ │ └─────────────────────────────┘ │ │
│ │ 시간     │출발IP        │유형    │RL대응│ └─────────────────────────────────┘ │
│ │ 14:25:30 │118.214.79.16│외부접근│차단  │                                   │
│ │ 14:25:28 │192.168.0.32 │대용량  │제한  │ 🔥 지연 로딩 상태:                │
│ │ 14:25:25 │203.0.113.5  │포트스캔│검사  │ 등록 모듈: 3개 | 로딩: 1개        │
│ └─────────────────────────────────────────┘ 등록 모델: 2개 | 로딩: 1개        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 핵심 성공 지표

### 🎯 **사용자 경험 목표**
- **로딩 시간**: 초기 로딩 3초 이내 (지연 로딩 활용)
- **업데이트 지연**: 실시간 데이터 3초 이내 반영
- **반응성**: 사용자 액션 1초 이내 응답
- **안정성**: 24/7 연속 운영 가능

### 📊 **기술적 목표**
- **메모리 사용량**: 클라이언트 100MB 이하
- **네트워크 대역폭**: 실시간 업데이트 1Mbps 이하
- **동시 접속**: 최대 10명 관리자 동시 모니터링
- **데이터 보관**: 최근 7일간 상세 데이터 유지

---

**📌 다음 단계**: 이 설계서를 바탕으로 프론트엔드 개발팀과 백엔드 API 구현을 시작할 수 있습니다. 특히 현재 시스템의 지연 로딩 시스템을 활용하여 대시보드도 메모리 효율적으로 구현할 수 있습니다.
