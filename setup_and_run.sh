#!/bin/bash

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "================================================================"
echo "       IDS Agent 설치 및 실행 도구  "
echo "================================================================"
echo -e "${NC}"

# 관리자 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED} 관리자(root) 권한이 필요합니다.${NC}"
    echo -e "${YELLOW}sudo 명령어로 실행해주세요: sudo $0${NC}"
    exit 1
fi

echo -e "${GREEN} 관리자 권한으로 실행 중입니다.${NC}"

echo
echo -e "${BLUE} Python 설치 확인 중...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo -e "${GREEN} Python이 설치되어 있습니다: $PYTHON_VERSION${NC}"
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version 2>&1)
    echo -e "${GREEN} Python이 설치되어 있습니다: $PYTHON_VERSION${NC}"
    PYTHON_CMD="python"
else
    echo -e "${RED} Python이 설치되어 있지 않습니다.${NC}"
    echo -e "${YELLOW}Python 3.8 이상을 설치해주세요.${NC}"
    exit 1
fi

echo
echo -e "${BLUE} 필요한 패키지 설치 중...${NC}"

# pip 업그레이드
echo -e "${BLUE} pip 업그레이드 중...${NC}"
$PYTHON_CMD -m pip install --upgrade pip

# requirements.txt가 있는지 확인하고 설치
if [ -f "requirements.txt" ]; then
    echo -e "${BLUE} requirements.txt에서 패키지 설치 중...${NC}"
    $PYTHON_CMD -m pip install -r requirements.txt
else
    echo -e "${BLUE} 필수 패키지 개별 설치 중...${NC}"
    $PYTHON_CMD -m pip install colorama pandas numpy scikit-learn torch joblib scapy matplotlib seaborn tqdm psutil
fi

echo
echo -e "${GREEN}✅ 패키지 설치 완료!${NC}"

# 로그 디렉토리 생성
if [ ! -d "logs" ]; then
    mkdir logs
fi
echo -e "${GREEN} 로그 디렉토리 생성 완료${NC}"

# 수리카타 설치 확인 및 설치 옵션
echo
echo -e "${CYAN}"
echo "================================================================"
echo "      수리카타(Suricata) 설치 확인 및 설정"
echo "================================================================"
echo -e "${NC}"

# 수리카타 설치 확인
if command -v suricata &> /dev/null; then
    echo -e "${GREEN}✅ 수리카타가 이미 설치되어 있습니다.${NC}"
    suricata --version
    SURICATA_INSTALLED=1
else
    echo -e "${RED} 수리카타가 설치되어 있지 않습니다.${NC}"
    echo -e "${YELLOW} 수리카타는 고성능 모드에 필요한 선택사항입니다.${NC}"
    echo
    read -p "수리카타를 지금 설치하시겠습니까? (y/n): " install_suricata
    
    if [[ $install_suricata =~ ^[Yy]$ ]]; then
        install_suricata_func
    else
        echo -e "${YELLOW}  수리카타 없이 계속 진행합니다. 경량 모드만 사용 가능합니다.${NC}"
        SURICATA_INSTALLED=0
    fi
fi

echo
echo -e "${CYAN}"
echo "================================================================"
echo "      IDS Agent 실행 옵션"
echo "================================================================"
echo -e "${NC}"

echo "1. 일반 실행 (모드 선택 메뉴 표시)"
echo "2. 경량 모드로 바로 실행"
if [ "$SURICATA_INSTALLED" = "1" ]; then
    echo -e "3. 고성능 모드로 바로 실행 ${RED}${NC}"
else
    echo "3. 고성능 모드 (수리카타 필요 - 현재 사용 불가)"
fi
echo "4. 디버그 모드로 실행"
echo "5. 종료"
echo

while true; do
    read -p "선택하세요 (1-5): " choice
    
    case $choice in
        1)
            echo -e "${BLUE} 일반 모드로 실행 중...${NC}"
            cd IDS
            $PYTHON_CMD IPSAgent_RL.py
            break
            ;;
        2)
            echo -e "${GREEN} 경량 모드로 실행 중...${NC}"
            cd IDS
            $PYTHON_CMD IPSAgent_RL.py --mode lightweight --no-menu
            break
            ;;
        3)
            if [ "$SURICATA_INSTALLED" = "1" ]; then
                echo -e "${RED} 고성능 모드로 실행 중...${NC}"
                cd IDS
                $PYTHON_CMD IPSAgent_RL.py --mode performance --no-menu
                break
            else
                echo -e "${RED}❌ 수리카타가 설치되지 않아 고성능 모드를 사용할 수 없습니다.${NC}"
                echo -e "${YELLOW}스크립트를 다시 실행하여 수리카타를 설치해주세요.${NC}"
                continue
            fi
            ;;
        4)
            echo -e "${PURPLE} 디버그 모드로 실행 중...${NC}"
            cd IDS
            $PYTHON_CMD IPSAgent_RL.py --debug
            break
            ;;
        5)
            echo -e "${YELLOW} 종료합니다.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ 잘못된 선택입니다. 1-5 중에서 선택해주세요.${NC}"
            continue
            ;;
    esac
done

echo
echo "프로그램이 종료되었습니다."
read -p "아무 키나 누르세요..."

install_suricata_func() {
    echo
    echo -e "${CYAN}"
    echo "================================================================"
    echo "      수리카타 자동 설치 시작"
    echo "================================================================"
    echo -e "${NC}"
    
    # 운영체제 감지
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        echo -e "${BLUE}🐧 Linux 시스템 감지${NC}"
        
        # 배포판 감지
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu
            echo -e "${BLUE}📦 Ubuntu/Debian에서 수리카타 설치 중...${NC}"
            apt-get update
            apt-get install -y suricata suricata-update
            
            # 규칙 업데이트
            echo -e "${BLUE}📋 수리카타 규칙 업데이트 중...${NC}"
            suricata-update
            
        elif [ -f /etc/redhat-release ]; then
            # CentOS/RHEL/Fedora
            echo -e "${BLUE} CentOS/RHEL/Fedora에서 수리카타 설치 중...${NC}"
            
            # EPEL 저장소 설치 (CentOS/RHEL)
            if command -v yum &> /dev/null; then
                yum install -y epel-release
                yum install -y suricata
            elif command -v dnf &> /dev/null; then
                dnf install -y suricata
            fi
            
        else
            echo -e "${YELLOW}  지원하지 않는 Linux 배포판입니다.${NC}"
            echo -e "${YELLOW} 수동 설치 방법:${NC}"
            echo "   - 패키지 관리자를 사용하여 suricata를 설치하세요"
            echo "   - 또는 https://suricata.io/download/ 에서 소스를 다운로드하세요"
            SURICATA_INSTALLED=0
            return
        fi
        
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo -e "${BLUE} macOS 시스템 감지${NC}"
        
        # Homebrew 확인
        if command -v brew &> /dev/null; then
            echo -e "${BLUE} Homebrew로 수리카타 설치 중...${NC}"
            brew install suricata
        else
            echo -e "${RED}❌ Homebrew가 설치되지 않았습니다.${NC}"
            echo -e "${YELLOW} 수동 설치 방법:${NC}"
            echo "   1. Homebrew 설치: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            echo "   2. Suricata 설치: brew install suricata"
            echo "   3. 이 스크립트를 다시 실행"
            SURICATA_INSTALLED=0
            return
        fi
        
    else
        echo -e "${RED}❌ 지원하지 않는 운영체제입니다.${NC}"
        SURICATA_INSTALLED=0
        return
    fi
    
    # 설치 확인
    echo
    echo -e "${BLUE}🔍 설치 확인 중...${NC}"
    sleep 2
    
    if command -v suricata &> /dev/null; then
        echo -e "${GREEN}✅ 수리카타 설치 및 설정 완료!${NC}"
        suricata --version
        SURICATA_INSTALLED=1
        
        echo
        echo -e "${GREEN} 축하합니다! 이제 고성능 모드를 사용할 수 있습니다.${NC}"
        
        # 서비스 시작 안내
        if systemctl list-unit-files | grep -q suricata; then
            echo -e "${BLUE} 수리카타 서비스를 시작하려면: sudo systemctl start suricata${NC}"
        fi
        
    else
        echo -e "${RED}❌ 설치는 완료되었지만 설정에 문제가 있습니다.${NC}"
        echo -e "${YELLOW} 시스템을 재시작한 후 다시 시도해주세요.${NC}"
        SURICATA_INSTALLED=0
    fi
    
    echo
    read -p "아무 키나 누르세요..."
} 