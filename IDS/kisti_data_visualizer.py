#!/usr/bin/env python3
"""
KISTI-IDS-2022 데이터 시각화 분석기
학습 전 데이터 특성 시각적 분석
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os

# 한글 폰트 설정
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.unicode_minus'] = False

class KISTIDataVisualizer:
    """KISTI 데이터 시각화 분석기"""
    
    def __init__(self):
        self.output_dir = "processed_data"
        print("KISTI 데이터 시각화 분석기 초기화 완료")
    
    def create_comprehensive_analysis(self):
        """종합적 데이터 분석 및 시각화"""
        print("=== KISTI-IDS-2022 데이터 시각화 분석 시작 ===")
        
        try:
            # 1. 데이터 로드
            train_df = pd.read_csv("processed_data/kisti_quick_train.csv")
            val_df = pd.read_csv("processed_data/kisti_quick_val.csv")
            test_df = pd.read_csv("processed_data/kisti_quick_test.csv")
            
            print(f"데이터 로드 완료:")
            print(f"  Train: {len(train_df):,}행")
            print(f"  Val: {len(val_df):,}행")
            print(f"  Test: {len(test_df):,}행")
            
            # 전체 데이터 통합 (시각화용)
            full_df = pd.concat([train_df, val_df, test_df], ignore_index=True)
            print(f"  전체: {len(full_df):,}행")
            
            # 2. 시각화 생성
            self._create_visualizations(full_df)
            
            # 3. 통계 분석
            self._create_statistical_analysis(train_df, val_df, test_df)
            
            print("\n=== 시각화 분석 완료 ===")
            print("생성된 파일:")
            print("  - processed_data/kisti_data_analysis.png")
            print("  - processed_data/kisti_statistics_report.txt")
            
        except Exception as e:
            print(f"시각화 실패: {e}")
            import traceback
            traceback.print_exc()
    
    def _create_visualizations(self, df):
        """데이터 시각화 생성"""
        print("\n시각화 생성 중...")
        
        # 그림 설정
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('KISTI-IDS-2022 Dataset Analysis', fontsize=16, fontweight='bold')
        
        # 1. 클래스 분포 (파이 차트)
        class_counts = df['is_malicious'].value_counts()
        labels = ['Normal', 'Attack']
        colors = ['lightgreen', 'lightcoral']
        
        axes[0, 0].pie(class_counts.values, labels=labels, autopct='%1.1f%%', 
                      colors=colors, startangle=90)
        axes[0, 0].set_title('Class Distribution\n(Normal vs Attack)')
        
        # 2. 공격 유형 분포 (막대 그래프)
        attack_types = df['attack_type'].value_counts().head(10)
        axes[0, 1].bar(range(len(attack_types)), attack_types.values, color='skyblue')
        axes[0, 1].set_title('Attack Type Distribution')
        axes[0, 1].set_xlabel('Attack Types')
        axes[0, 1].set_ylabel('Count')
        axes[0, 1].set_xticks(range(len(attack_types)))
        axes[0, 1].set_xticklabels(attack_types.index, rotation=45, ha='right')
        
        # 3. 프로토콜 분포 (도넛 차트)
        protocol_counts = df['protocol'].value_counts().head(8)
        axes[0, 2].pie(protocol_counts.values, labels=protocol_counts.index, 
                      autopct='%1.1f%%', startangle=90)
        axes[0, 2].set_title('Protocol Distribution')
        
        # 4. 패킷 크기 분포 (히스토그램)
        packet_sizes = df['packet_size'][df['packet_size'] < 10000]  # 이상값 제거
        axes[1, 0].hist(packet_sizes, bins=50, alpha=0.7, color='purple', edgecolor='black')
        axes[1, 0].set_title('Packet Size Distribution')
        axes[1, 0].set_xlabel('Packet Size (bytes)')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].axvline(packet_sizes.mean(), color='red', linestyle='--', 
                          label=f'Mean: {packet_sizes.mean():.0f}')
        axes[1, 0].legend()
        
        # 5. 포트 분포 (상위 20개)
        port_analysis = pd.concat([df['source_port'], df['dest_port']])
        port_counts = port_analysis.value_counts().head(20)
        
        axes[1, 1].bar(range(len(port_counts)), port_counts.values, color='orange')
        axes[1, 1].set_title('Top 20 Port Numbers')
        axes[1, 1].set_xlabel('Ports (Top 20)')
        axes[1, 1].set_ylabel('Count')
        axes[1, 1].set_xticks(range(0, len(port_counts), 2))
        axes[1, 1].set_xticklabels([str(port_counts.index[i]) for i in range(0, len(port_counts), 2)], 
                                  rotation=45)
        
        # 6. 클래스별 패킷 크기 비교 (박스 플롯)
        normal_packets = df[df['is_malicious'] == 0]['packet_size']
        attack_packets = df[df['is_malicious'] == 1]['packet_size']
        
        # 이상값 제거 (상위 95% 이하)
        normal_packets = normal_packets[normal_packets <= normal_packets.quantile(0.95)]
        attack_packets = attack_packets[attack_packets <= attack_packets.quantile(0.95)]
        
        box_data = [normal_packets, attack_packets]
        axes[1, 2].boxplot(box_data, labels=['Normal', 'Attack'])
        axes[1, 2].set_title('Packet Size by Class')
        axes[1, 2].set_ylabel('Packet Size (bytes)')
        
        # 레이아웃 조정
        plt.tight_layout()
        
        # 저장
        output_path = os.path.join(self.output_dir, "kisti_data_analysis.png")
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  시각화 저장: {output_path}")
    
    def _create_statistical_analysis(self, train_df, val_df, test_df):
        """통계적 분석 보고서 생성"""
        print("통계 분석 보고서 생성 중...")
        
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("KISTI-IDS-2022 데이터셋 통계 분석 보고서")
        report_lines.append("=" * 60)
        report_lines.append(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # 전체 데이터 통계
        full_df = pd.concat([train_df, val_df, test_df], ignore_index=True)
        
        report_lines.append("1. 데이터셋 기본 정보")
        report_lines.append("-" * 30)
        report_lines.append(f"전체 샘플 수: {len(full_df):,}개")
        report_lines.append(f"특성 수: {len(full_df.columns)-2}개 (is_malicious, attack_type 제외)")
        report_lines.append(f"Train/Val/Test: {len(train_df):,} / {len(val_df):,} / {len(test_df):,}")
        report_lines.append("")
        
        # 클래스 분포 분석
        report_lines.append("2. 클래스 분포 분석")
        report_lines.append("-" * 30)
        
        for name, dataset in [('Train', train_df), ('Validation', val_df), ('Test', test_df)]:
            normal_count = (dataset['is_malicious'] == 0).sum()
            attack_count = (dataset['is_malicious'] == 1).sum()
            attack_ratio = attack_count / len(dataset)
            
            report_lines.append(f"{name}:")
            report_lines.append(f"  정상: {normal_count:,}개 ({(1-attack_ratio)*100:.1f}%)")
            report_lines.append(f"  공격: {attack_count:,}개 ({attack_ratio*100:.1f}%)")
            report_lines.append(f"  불균형 비율: {(1-attack_ratio)/attack_ratio:.2f}:1")
        
        report_lines.append("")
        
        # 공격 유형 분석
        report_lines.append("3. 공격 유형 분석")
        report_lines.append("-" * 30)
        attack_type_dist = full_df['attack_type'].value_counts()
        
        for attack_type, count in attack_type_dist.items():
            percentage = (count / len(full_df)) * 100
            report_lines.append(f"  {attack_type}: {count:,}개 ({percentage:.2f}%)")
        
        report_lines.append("")
        
        # 네트워크 특성 분석
        report_lines.append("4. 네트워크 특성 분석")
        report_lines.append("-" * 30)
        
        # 프로토콜 분포
        protocol_dist = full_df['protocol'].value_counts().head(5)
        report_lines.append("주요 프로토콜:")
        for protocol, count in protocol_dist.items():
            percentage = (count / len(full_df)) * 100
            report_lines.append(f"  {protocol}: {count:,}개 ({percentage:.1f}%)")
        
        # 패킷 크기 통계
        packet_stats = full_df['packet_size'].describe()
        report_lines.append(f"\n패킷 크기 통계:")
        report_lines.append(f"  평균: {packet_stats['mean']:.1f} bytes")
        report_lines.append(f"  중앙값: {packet_stats['50%']:.1f} bytes")
        report_lines.append(f"  표준편차: {packet_stats['std']:.1f} bytes")
        report_lines.append(f"  최대: {packet_stats['max']:.0f} bytes")
        report_lines.append(f"  최소: {packet_stats['min']:.0f} bytes")
        
        # 포트 분석
        port_analysis = pd.concat([full_df['source_port'], full_df['dest_port']])
        common_ports = port_analysis.value_counts().head(10)
        report_lines.append(f"\n주요 포트 (상위 10개):")
        for port, count in common_ports.items():
            percentage = (count / len(port_analysis)) * 100
            report_lines.append(f"  {port}: {count:,}개 ({percentage:.1f}%)")
        
        report_lines.append("")
        
        # 호스트 및 네트워크 패턴 분석
        report_lines.append("5. 호스트 및 네트워크 패턴 분석")
        report_lines.append("-" * 30)
        
        # 고유 IP 분석
        unique_src_ips = full_df['source'].nunique()
        unique_dst_ips = full_df['destination'].nunique()
        report_lines.append(f"고유 IP 주소:")
        report_lines.append(f"  Source IP: {unique_src_ips:,}개")
        report_lines.append(f"  Destination IP: {unique_dst_ips:,}개")
        
        # 통신 패턴 분석
        top_src_ips = full_df['source'].value_counts().head(5)
        top_dst_ips = full_df['destination'].value_counts().head(5)
        
        report_lines.append(f"\n주요 Source IP (상위 5개):")
        for ip, count in top_src_ips.items():
            percentage = (count / len(full_df)) * 100
            report_lines.append(f"  {ip}: {count:,}개 ({percentage:.1f}%)")
        
        report_lines.append(f"\n주요 Destination IP (상위 5개):")
        for ip, count in top_dst_ips.items():
            percentage = (count / len(full_df)) * 100
            report_lines.append(f"  {ip}: {count:,}개 ({percentage:.1f}%)")
        
        # 시간 패턴 분석 (가능한 경우)
        if 'detectStart' in full_df.columns:
            report_lines.append(f"\n시간 패턴 분석:")
            report_lines.append(f"  시간 기반 분리 가능: ✅")
        else:
            report_lines.append(f"\n시간 패턴 분석:")
            report_lines.append(f"  시간 기반 분리: ❌ (시간 정보 없음)")
        
        report_lines.append("")
        
        # RF 학습 권장사항
        report_lines.append("6. RF 학습 권장사항")
        report_lines.append("-" * 30)
        report_lines.append("클래스 불균형 처리:")
        report_lines.append(f"  불균형 비율: 1:4 (정상:공격)")
        report_lines.append(f"  권장 방법: class_weight='balanced' 또는 가중치 {1-full_df['is_malicious'].mean():.2f}:{full_df['is_malicious'].mean():.2f}")
        
        report_lines.append("\n특성 엔지니어링:")
        report_lines.append("  주요 특성: source_port, dest_port, protocol, packet_size")
        report_lines.append("  추가 고려: 포트 조합, 프로토콜별 패킷 크기 패턴")
        
        report_lines.append("\n예상 성능:")
        report_lines.append("  PR-AUC: 0.75-0.90 (클래스 불균형 고려)")
        report_lines.append("  F1-Score: 0.80-0.95 (현실적 성능)")
        report_lines.append("  Balanced Accuracy: 0.85-0.95")
        
        # 보고서 저장
        report_path = os.path.join(self.output_dir, "kisti_statistics_report.txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        print(f"  통계 보고서 저장: {report_path}")
    
    def create_detailed_charts(self, df):
        """상세 차트 생성"""
        print("상세 차트 생성 중...")
        
        # 추가 시각화
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('KISTI-IDS-2022 Detailed Analysis', fontsize=14)
        
        # 1. 클래스별 포트 분포
        normal_ports = df[df['is_malicious'] == 0]['dest_port'].value_counts().head(10)
        attack_ports = df[df['is_malicious'] == 1]['dest_port'].value_counts().head(10)
        
        x = np.arange(len(normal_ports))
        width = 0.35
        
        axes[0, 0].bar(x - width/2, normal_ports.values, width, label='Normal', alpha=0.7)
        axes[0, 0].bar(x + width/2, attack_ports.values, width, label='Attack', alpha=0.7)
        axes[0, 0].set_title('Top Destination Ports by Class')
        axes[0, 0].set_xlabel('Port Rank')
        axes[0, 0].set_ylabel('Count')
        axes[0, 0].legend()
        
        # 2. 패킷 크기 vs 클래스 (산점도)
        sample_for_scatter = df.sample(n=5000)  # 시각화용 샘플
        normal_mask = sample_for_scatter['is_malicious'] == 0
        attack_mask = sample_for_scatter['is_malicious'] == 1
        
        axes[0, 1].scatter(sample_for_scatter[normal_mask]['source_port'], 
                          sample_for_scatter[normal_mask]['packet_size'],
                          alpha=0.6, label='Normal', s=10)
        axes[0, 1].scatter(sample_for_scatter[attack_mask]['source_port'], 
                          sample_for_scatter[attack_mask]['packet_size'],
                          alpha=0.6, label='Attack', s=10)
        axes[0, 1].set_title('Source Port vs Packet Size')
        axes[0, 1].set_xlabel('Source Port')
        axes[0, 1].set_ylabel('Packet Size')
        axes[0, 1].legend()
        
        # 3. 클래스별 프로토콜 분포 (누적 막대)
        protocol_class = pd.crosstab(df['protocol'], df['is_malicious'])
        protocol_class.plot(kind='bar', stacked=True, ax=axes[1, 0], 
                           color=['lightgreen', 'lightcoral'])
        axes[1, 0].set_title('Protocol Distribution by Class')
        axes[1, 0].set_xlabel('Protocol')
        axes[1, 0].set_ylabel('Count')
        axes[1, 0].legend(['Normal', 'Attack'])
        axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 4. 데이터 품질 히트맵
        # 수치형 특성들의 상관관계
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        corr_matrix = df[numeric_cols].corr()
        
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0,
                   square=True, ax=axes[1, 1], cbar_kws={'shrink': 0.8})
        axes[1, 1].set_title('Feature Correlation Matrix')
        
        plt.tight_layout()
        
        # 저장
        detail_path = os.path.join(self.output_dir, "kisti_detailed_analysis.png")
        plt.savefig(detail_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  상세 차트 저장: {detail_path}")
    
    def create_network_behavior_analysis(self, df):
        """네트워크 행동 패턴 분석"""
        print("네트워크 행동 패턴 분석 중...")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('KISTI-IDS-2022 Network Behavior Analysis', fontsize=14)
        
        # 1. IP 주소 분포 패턴
        src_ip_counts = df['source'].value_counts()
        dst_ip_counts = df['destination'].value_counts()
        
        # 상위 20개 IP의 활동량 분포
        top_src = src_ip_counts.head(20)
        axes[0, 0].bar(range(len(top_src)), top_src.values, color='lightblue')
        axes[0, 0].set_title('Top 20 Source IP Activity')
        axes[0, 0].set_xlabel('IP Rank')
        axes[0, 0].set_ylabel('Connection Count')
        
        # 2. 포트 사용 패턴 (정상 vs 공격)
        normal_data = df[df['is_malicious'] == 0]
        attack_data = df[df['is_malicious'] == 1]
        
        normal_dest_ports = normal_data['dest_port'].value_counts().head(15)
        attack_dest_ports = attack_data['dest_port'].value_counts().head(15)
        
        # 공통 포트들 찾기
        common_ports = set(normal_dest_ports.index) & set(attack_dest_ports.index)
        common_ports = list(common_ports)[:10]
        
        if common_ports:
            normal_counts = [normal_dest_ports.get(port, 0) for port in common_ports]
            attack_counts = [attack_dest_ports.get(port, 0) for port in common_ports]
            
            x = np.arange(len(common_ports))
            width = 0.35
            
            axes[0, 1].bar(x - width/2, normal_counts, width, label='Normal', alpha=0.7)
            axes[0, 1].bar(x + width/2, attack_counts, width, label='Attack', alpha=0.7)
            axes[0, 1].set_title('Port Usage: Normal vs Attack')
            axes[0, 1].set_xlabel('Port Numbers')
            axes[0, 1].set_ylabel('Usage Count')
            axes[0, 1].set_xticks(x)
            axes[0, 1].set_xticklabels(common_ports, rotation=45)
            axes[0, 1].legend()
        
        # 3. 패킷 크기 패턴 분석
        # 클래스별 패킷 크기 분포 (로그 스케일)
        normal_sizes = normal_data['packet_size']
        attack_sizes = attack_data['packet_size']
        
        # 이상값 제거 (99% 이하)
        normal_sizes = normal_sizes[normal_sizes <= normal_sizes.quantile(0.99)]
        attack_sizes = attack_sizes[attack_sizes <= attack_sizes.quantile(0.99)]
        
        axes[1, 0].hist(normal_sizes, bins=50, alpha=0.6, label='Normal', color='green', density=True)
        axes[1, 0].hist(attack_sizes, bins=50, alpha=0.6, label='Attack', color='red', density=True)
        axes[1, 0].set_title('Packet Size Distribution (Normalized)')
        axes[1, 0].set_xlabel('Packet Size (bytes)')
        axes[1, 0].set_ylabel('Density')
        axes[1, 0].legend()
        axes[1, 0].set_yscale('log')
        
        # 4. 트래픽 강도 분석 (IP별 활동량)
        # Source IP별 패킷 수 분포
        ip_activity = src_ip_counts.values
        
        # 활동량 구간별 분포 (안전한 bins 생성)
        max_activity = max(ip_activity)
        activity_bins = [1, 10, 100, 1000, max(10001, max_activity + 1)]
        activity_labels = ['1-9', '10-99', '100-999', f'1K-{max_activity}']
        
        binned_activity = pd.cut(ip_activity, bins=activity_bins, labels=activity_labels, include_lowest=True)
        activity_dist = binned_activity.value_counts()
        
        axes[1, 1].bar(range(len(activity_dist)), activity_dist.values, color='orange')
        axes[1, 1].set_title('IP Activity Level Distribution')
        axes[1, 1].set_xlabel('Activity Level (packets/IP)')
        axes[1, 1].set_ylabel('Number of IPs')
        axes[1, 1].set_xticks(range(len(activity_dist)))
        axes[1, 1].set_xticklabels(activity_dist.index, rotation=45)
        
        plt.tight_layout()
        
        # 저장
        behavior_path = os.path.join(self.output_dir, "kisti_network_behavior.png")
        plt.savefig(behavior_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  네트워크 행동 분석 저장: {behavior_path}")

def main():
    """메인 실행"""
    try:
        visualizer = KISTIDataVisualizer()
        
        # 종합 분석
        visualizer.create_comprehensive_analysis()
        
        # 상세 차트
        full_df = pd.concat([
            pd.read_csv("processed_data/kisti_quick_train.csv"),
            pd.read_csv("processed_data/kisti_quick_val.csv"),
            pd.read_csv("processed_data/kisti_quick_test.csv")
        ], ignore_index=True)
        
        visualizer.create_detailed_charts(full_df)
        
        # 네트워크 행동 분석
        visualizer.create_network_behavior_analysis(full_df)
        
        print("\n🎉 KISTI 데이터 시각화 분석 완료!")
        print("📊 생성된 시각화:")
        print("  - kisti_data_analysis.png (기본 분석)")
        print("  - kisti_detailed_analysis.png (상세 분석)")
        print("  - kisti_network_behavior.png (네트워크 행동 패턴)")
        print("  - kisti_statistics_report.txt (통계 보고서)")
        
    except Exception as e:
        print(f"시각화 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
