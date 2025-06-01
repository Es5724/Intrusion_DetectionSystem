# 반응형 취약점 차단 AI 에이전트

<div align="center">
  <img src="https://img.shields.io/badge/Language-Python-blue" alt="Language">
  <img src="https://img.shields.io/badge/Language-C-yellow" alt="Language">
  <img src="https://img.shields.io/badge/Framework-PyTorch-orange" alt="Framework">
  <img src="https://img.shields.io/badge/AI-Reinforcement%20Learning-brightgreen" alt="AI">
</div>

## 0. 📑목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [팀원 정보](#2-팀원-정보)
3. [프로젝트 구조](#️3-프로젝트-구조)
4. [사용된 모듈](#️4-사용된-모듈)
5. [AI 에이전트 작동 방식](#-ai-에이전트-작동-방식)
6. [하이브리드 접근 방식의 특징](#-하이브리드-접근-방식의-특징)
7. [주요 시스템 구성 요소](#-주요-시스템-구성-요소)
8. [강화학습 관련 클래스 및 메서드](#-강화학습-관련-클래스-및-메서드)
9. [모듈 간 통합 및 데이터 흐름](#-모듈-간-통합-및-데이터-흐름)
10. [전체 시스템 아키텍처](#️-전체-시스템-아키텍처)
11. [프로그램 작동법](#-프로그램-작동법)
12. [메모리 최적화 전략](#-메모리-최적화-전략)
13. [운영 모드](#-운영-모드)
14. [향후 개발 계획](#-향후-개발-계획)

## 1. 📌프로젝트 개요

실시간으로 네트워크 보안 취약점을 탐지하고 자동으로 대응하는 AI 기반 침입 탐지 시스템입니다.   
랜덤 포레스트와 강화학습의 장점을 결합한 하이브리드 접근 방식을 통해 기존 방식보다 높은 정확도와 적응성을 제공 합니다..

## 2. 👥팀원 정보

- **안상수[팀장]**: 시스템 설계, 메인프로그래밍
- **신명재[팀원]**: 데이터 학습, 문서작업, 피드백 및 시각화 웹앱 제작
- **민인영[팀원]**: 데이터 학습, 이미지 시각화, 피드백 및 시각화 웹앱 제작
- **최준형[팀원]**: 데이터 학습, 피드백 및 시각화 웹앱 제작

## 3. 🏗️프로젝트 구조

```
📁 Intrusion_DetectionSystem/
│
├── 📄 IDSAgent_RL.py                    # 메인 에이전트 (시스템 핵심)
│
├── 📁 scripts/                          # 실행 스크립트
│   ├── 📄 data_preparation.py           # 데이터 준비 인터페이스
│   │
│   └── 📁 components/                   # UI 컴포넌트
│       ├── 📄 packet_collector.py       # 패킷 수집 모듈
│       ├── 📄 TrafficGeneratorApp.py    # 트래픽 생성기
│       └── 📄 DataPreprocessingApp.py   # 데이터 전처리 앱
│
└── 📁 modules/                          # 핵심 기능 모듈
    ├── 📄 reinforcement_learning.py     # 강화학습 구현
    ├── 📄 ml_models.py                  # 머신러닝 모델
    ├── 📄 packet_capture.py             # 패킷 캡처 기능
    ├── 📄 defense_mechanism.py          # 방어 메커니즘 모듈
    ├── 📄 suricata_manager.py           # 수리카타 통합 관리 모듈
    └── 📄 utils.py                      # 유틸리티 함수
```

### IDS 구현 구조
```
📁 IDS/
├── IDSAgent_RL.py          # 메인 에이전트 파일
├── 📁 modules/
│   ├── defense_mechanism.py # 방어 메커니즘 모듈
│   ├── suricata_manager.py  # 수리카타 통합 관리 모듈
│   ├── utils.py             # 유틸리티 함수
│   ├── packet_capture.py    # 패킷 캡처 모듈 
│   ├── reinforcement_learning.py # 강화학습 모듈
│   └── ml_models.py         # 머신러닝 모델 모듈
├── 📁 logs/                    # 로그 디렉토리
├── 📁 data_set/                # 학습 데이터 세트
├── 📁 config/                  # 설정 파일
└── 📁 rules/                   # 수리카타 규칙 파일
```

// ... existing code ...
