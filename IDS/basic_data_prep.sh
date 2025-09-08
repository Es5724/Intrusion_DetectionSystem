#!/bin/bash
# CIC-IDS-2017 기본 데이터 전처리 (Python 없이)

echo "=== CIC-IDS-2017 기본 전처리 시작 ==="

# 작업 디렉토리 생성
mkdir -p processed_data

# 데이터 파일 경로
DATA_DIR="../CIC-IDS- 2017"

echo "1. 데이터 파일 확인 중..."
for file in "$DATA_DIR"/*.csv; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        filesize=$(du -h "$file" | cut -f1)
        linecount=$(wc -l < "$file")
        echo "  $filename: $filesize, $linecount lines"
    fi
done

echo -e "\n2. 레이블 분포 분석 중..."
for file in "$DATA_DIR"/*.csv; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "=== $filename ==="
        
        # 레이블 컬럼 (마지막 컬럼) 분포 확인
        awk -F',' 'NR>1 {print $NF}' "$file" | sort | uniq -c | sort -nr
        echo ""
    fi
done

echo "3. 시간 기반 분리 계획:"
echo "  Train 세트 (70%):"
echo "    - Monday-WorkingHours.pcap_ISCX.csv"
echo "    - Tuesday-WorkingHours.pcap_ISCX.csv" 
echo "    - Wednesday-workingHours.pcap_ISCX.csv"
echo ""
echo "  Validation 세트 (10%):"
echo "    - Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
echo ""
echo "  Test 세트 (20%):"
echo "    - Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
echo "    - Friday-WorkingHours-Morning.pcap_ISCX.csv"
echo "    - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
echo "    - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

echo -e "\n4. 공격 유형 매핑 계획:"
echo "  BENIGN → is_malicious=0, attack_type=normal"
echo "  DDoS → is_malicious=1, attack_type=ddos"
echo "  PortScan → is_malicious=1, attack_type=port_scan"
echo "  DoS * → is_malicious=1, attack_type=dos"
echo "  *-Patator → is_malicious=1, attack_type=brute_force"
echo "  Web Attack → is_malicious=1, attack_type=web_attack"
echo "  Infiltration → is_malicious=1, attack_type=infiltration"
echo "  Bot → is_malicious=1, attack_type=botnet"
echo "  Heartbleed → is_malicious=1, attack_type=vulnerability"

echo -e "\n5. 예상 처리 결과:"

# 전체 샘플 수 계산
total_samples=0
for file in "$DATA_DIR"/*.csv; do
    if [ -f "$file" ]; then
        linecount=$(wc -l < "$file")
        total_samples=$((total_samples + linecount - 1))  # 헤더 제외
    fi
done

train_samples=$((total_samples * 70 / 100))
val_samples=$((total_samples * 10 / 100))
test_samples=$((total_samples * 20 / 100))

echo "  총 샘플: $total_samples 개"
echo "  Train: $train_samples 개 (70%)"
echo "  Validation: $val_samples 개 (10%)"
echo "  Test: $test_samples 개 (20%)"

echo -e "\n6. 필요 시스템 자원:"
echo "  RAM: 최소 8GB (권장 16GB)"
echo "  Storage: 5GB 여유공간"
echo "  예상 시간: 30-90분 (시스템 성능에 따라)"

echo -e "\n=== 기본 분석 완료 ==="
echo "다음 단계: Python 환경에서 cic_data_processor.py 실행"

