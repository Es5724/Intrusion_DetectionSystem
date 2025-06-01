# 메모리 최적화 전략

이 문서는 C 언어로 전환 시 적용할 수 있는 상세한 메모리 최적화 전략을 설명합니다.

## 메모리 사용량 현황 분석

현재 파이썬 구현의 주요 메모리 사용 영역:

| 모듈 | 추정 메모리 사용량 | 주요 사용 원인 |
|------|------------------|--------------|
| 패킷 캡처 | 20-30MB | 패킷 버퍼, 인터프리터 오버헤드 |
| 방어 메커니즘 | 10-15MB | 방어 로직, 히스토리 로깅 |
| ML/RL 모델 | 40-50MB | 모델 가중치, 경험 리플레이 버퍼 |
| 전체 시스템 | 70-100MB | 인터프리터 포함 |

## C 언어 전환 시 메모리 최적화 기법

### 1. 패킷 처리 최적화

#### 메모리 풀링 구현
```c
// 고정 크기 메모리 풀 구현
#define PACKET_POOL_SIZE 1000
#define MAX_PACKET_SIZE 1500

typedef struct {
    char data[MAX_PACKET_SIZE];
    size_t size;
    int in_use;
} PacketBuffer;

typedef struct {
    PacketBuffer buffers[PACKET_POOL_SIZE];
    int next_free;
} PacketPool;

PacketPool pool;

// 초기화
void init_packet_pool() {
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
        pool.buffers[i].in_use = 0;
    }
    pool.next_free = 0;
}

// 버퍼 할당
PacketBuffer* get_packet_buffer() {
    // 사용 가능한 버퍼 찾기
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
        int idx = (pool.next_free + i) % PACKET_POOL_SIZE;
        if (!pool.buffers[idx].in_use) {
            pool.buffers[idx].in_use = 1;
            pool.next_free = (idx + 1) % PACKET_POOL_SIZE;
            return &pool.buffers[idx];
        }
    }
    return NULL; // 사용 가능한 버퍼 없음
}

// 버퍼 반환
void release_packet_buffer(PacketBuffer* buffer) {
    if (buffer && buffer >= pool.buffers && 
        buffer < pool.buffers + PACKET_POOL_SIZE) {
        buffer->in_use = 0;
    }
}
```

#### 제로 복사 패킷 처리
```c
// libpcap을 사용한 제로 복사 패킷 처리
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // 패킷 데이터를 복사하지 않고 직접 분석
    analyze_packet_inplace(bytes, h->len);
    
    // 필요한 메타데이터만 복사
    packet_metadata metadata;
    extract_metadata(bytes, h->len, &metadata);
    
    // 메타데이터 기반 의사결정
    handle_packet_metadata(&metadata);
}
```

### 2. 데이터 구조 최적화

#### 비트 필드 사용
```c
// 구조체 크기 최적화
typedef struct {
    uint32_t ip;              // 4바이트
    uint16_t port;            // 2바이트
    uint8_t protocol;         // 1바이트
    
    // 비트 필드 사용 (1바이트)
    uint8_t is_threat : 1;    // 1비트
    uint8_t action_taken : 3; // 3비트
    uint8_t severity : 4;     // 4비트
    
    // 전체 구조체 크기: 8바이트
} PacketInfo;

// 파이썬에서는 동일 정보가 최소 28-40바이트 사용
```

#### 정렬 최적화 구조체
```c
// 메모리 정렬 고려한 구조체
typedef struct {
    // 8바이트 경계에 맞춤
    uint64_t timestamp;   // 8바이트
    uint32_t ip_src;      // 4바이트
    uint32_t ip_dst;      // 4바이트
    
    // 4바이트 경계에 맞춤
    uint32_t packet_size; // 4바이트
    uint16_t port_src;    // 2바이트
    uint16_t port_dst;    // 2바이트
    
    // 패딩 없이 연속 배치
    uint8_t protocol;     // 1바이트
    uint8_t flags;        // 1바이트
    uint8_t ttl;          // 1바이트
    uint8_t reserved;     // 1바이트 (패딩 대신 사용)
} AlignedPacketInfo;      // 총 28바이트
```

### 3. 백그라운드 처리 최적화

#### 비동기 로깅 구현
```c
#define LOG_BUFFER_SIZE 4096
#define MAX_LOG_ENTRY 256

typedef struct {
    char entries[LOG_BUFFER_SIZE][MAX_LOG_ENTRY];
    int write_idx;
    int read_idx;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int shutdown;
} LogBuffer;

LogBuffer log_buffer;

// 로그 스레드
void* log_thread_func(void* arg) {
    FILE* log_file = fopen("defense_log.txt", "a");
    if (!log_file) return NULL;
    
    while (!log_buffer.shutdown) {
        pthread_mutex_lock(&log_buffer.mutex);
        
        // 로그 데이터 대기
        while (log_buffer.read_idx == log_buffer.write_idx && !log_buffer.shutdown) {
            pthread_cond_wait(&log_buffer.cond, &log_buffer.mutex);
        }
        
        // 로그 기록 처리
        while (log_buffer.read_idx != log_buffer.write_idx) {
            fprintf(log_file, "%s\n", log_buffer.entries[log_buffer.read_idx]);
            log_buffer.read_idx = (log_buffer.read_idx + 1) % LOG_BUFFER_SIZE;
        }
        
        fflush(log_file);
        pthread_mutex_unlock(&log_buffer.mutex);
    }
    
    fclose(log_file);
    return NULL;
}

// 로그 추가
void add_log(const char* format, ...) {
    pthread_mutex_lock(&log_buffer.mutex);
    
    // 버퍼 가득 찬 경우 처리
    if ((log_buffer.write_idx + 1) % LOG_BUFFER_SIZE == log_buffer.read_idx) {
        // 버퍼 가득 참 - 가장 오래된 로그 덮어쓰기
        log_buffer.read_idx = (log_buffer.read_idx + 1) % LOG_BUFFER_SIZE;
    }
    
    // 로그 메시지 포맷팅
    va_list args;
    va_start(args, format);
    vsnprintf(log_buffer.entries[log_buffer.write_idx], MAX_LOG_ENTRY, format, args);
    va_end(args);
    
    // 인덱스 업데이트 및 시그널
    log_buffer.write_idx = (log_buffer.write_idx + 1) % LOG_BUFFER_SIZE;
    pthread_cond_signal(&log_buffer.cond);
    
    pthread_mutex_unlock(&log_buffer.mutex);
}
```

## 4. Python/C 인터페이스 최적화

### NumPy 배열 직접 접근
```c
// 파이썬/C 인터페이스에서 NumPy 배열 직접 접근
static PyObject* process_features(PyObject* self, PyObject* args) {
    PyArrayObject *features_array;
    
    if (!PyArg_ParseTuple(args, "O!", &PyArray_Type, &features_array))
        return NULL;
    
    // NumPy 배열 데이터에 직접 접근
    float* data = (float*)PyArray_DATA(features_array);
    npy_intp* dims = PyArray_DIMS(features_array);
    
    // 데이터 직접 처리 (복사 없음)
    for (int i = 0; i < dims[0]; i++) {
        for (int j = 0; j < dims[1]; j++) {
            float val = data[i * dims[1] + j];
            // 데이터 처리...
        }
    }
    
    // 결과 반환
    return Py_BuildValue("i", 1);
}
```

## 5. 메모리 소비 모니터링

```c
// 메모리 사용량 모니터링 및 디버깅
typedef struct {
    const char* allocation_site;
    size_t current_bytes;
    size_t peak_bytes;
    size_t total_allocations;
} MemoryStats;

// 모듈별 메모리 통계
MemoryStats memory_stats[10] = {
    {"packet_capture", 0, 0, 0},
    {"defense_mechanism", 0, 0, 0},
    // ...
};

// 메모리 할당 추적
void* tracked_malloc(size_t size, int module_id) {
    void* ptr = malloc(size);
    if (ptr) {
        memory_stats[module_id].current_bytes += size;
        memory_stats[module_id].total_allocations++;
        
        if (memory_stats[module_id].current_bytes > memory_stats[module_id].peak_bytes)
            memory_stats[module_id].peak_bytes = memory_stats[module_id].current_bytes;
    }
    return ptr;
}

void tracked_free(void* ptr, size_t size, int module_id) {
    if (ptr) {
        memory_stats[module_id].current_bytes -= size;
        free(ptr);
    }
}

// 메모리 사용량 보고
void print_memory_stats() {
    printf("Memory Usage Statistics:\n");
    printf("------------------------\n");
    
    for (int i = 0; i < 10; i++) {
        if (memory_stats[i].allocation_site) {
            printf("Module: %s\n", memory_stats[i].allocation_site);
            printf("  Current: %zu bytes\n", memory_stats[i].current_bytes);
            printf("  Peak: %zu bytes\n", memory_stats[i].peak_bytes);
            printf("  Allocations: %zu\n", memory_stats[i].total_allocations);
            printf("\n");
        }
    }
}
```

## 예상 메모리 절감 효과

| 최적화 기법 | 예상 절감 효과 | 구현 복잡도 |
|------------|--------------|------------|
| 메모리 풀링 | 30-40% | 중간 |
| 구조체 최적화 | 50-60% | 낮음 |
| 제로 복사 기법 | 20-30% | 높음 |
| 비동기 로깅 | 10-15% | 중간 |
| NumPy 직접 접근 | 25-35% | 중간 |

## 백그라운드 실행 최적화

서비스로 백그라운드에서 실행 시 추가 최적화 방안:

1. **UI 관련 코드 제거 또는 조건부 컴파일**
   - 터미널 출력 관련 코드 분리
   - 대시보드 UI 컴포넌트 분리

2. **로깅 최적화**
   - 로그 레벨 조정 (INFO → WARNING)
   - 로그 버퍼링 및 비동기 쓰기
   - 주기적 로그 순환 (로그 파일 크기 제한)

3. **이벤트 기반 아키텍처**
   - 폴링 대신 이벤트 기반 설계
   - 시스템 콜 최소화

4. **서비스 모드 설정**
   - 시스템 서비스로 등록 및 자동 시작
   - 낮은 우선순위로 실행 (nice 값 조정) 