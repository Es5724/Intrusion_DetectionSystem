# 수리카타(Suricata) 설치 및 설정 가이드

이 가이드는 IDS 시스템의 고성능 모드에 필요한 수리카타(Suricata) 엔진의 설치 및 설정 방법을 안내합니다.

## 자동 설치 (Windows)

1. 제공된 `install_suricata.bat` 파일을 **관리자 권한**으로 실행합니다.
2. 설치가 완료될 때까지 기다립니다.
3. 설치 후 프로그램을 재시작하여 고성능 모드로 전환합니다.

## 수동 설치 (Windows)

1. [수리카타 공식 다운로드 페이지](https://suricata.io/download/)에서 최신 Windows 버전을 다운로드합니다.
2. 다운로드한 설치 파일(예: `Suricata-7.0.1-1-64bit.msi`)을 실행합니다.
3. 설치 마법사의 지시에 따라 설치를 완료합니다. 기본 설치 경로를 사용하는 것이 좋습니다.
4. 설치 후 환경 변수 설정:
   - 시스템 속성 → 고급 → 환경 변수 → 시스템 변수에서 '새로 만들기' 클릭
   - 변수 이름: `SURICATA_PATH`
   - 변수 값: `C:\Program Files\Suricata\suricata.exe` (설치 경로에 따라 다를 수 있음)

## 수동 설치 (Linux)

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install suricata
```

CentOS/RHEL:
```bash
sudo yum install epel-release
sudo yum install suricata
```

### 기본 규칙 설정 (Linux)

```bash
sudo suricata-update
```

## 설치 확인

설치가 제대로 되었는지 확인하려면:

1. 명령 프롬프트(Windows) 또는 터미널(Linux)을 열고 다음 명령어를 실행합니다:

   ```
   suricata --version
   ```

2. 버전 정보가 표시되면 설치가 성공적으로 완료된 것입니다.

## 문제 해결

1. **'suricata' 명령을 찾을 수 없는 경우**
   - Windows: 설치 경로가 시스템 PATH에 추가되지 않았을 수 있습니다. 환경 변수 설정을 확인하세요.
   - Linux: `which suricata` 명령으로 설치 경로를 확인하세요.

2. **설치 후에도 고성능 모드로 전환되지 않는 경우**
   - 로그 파일 (`defense_actions.log`)을 확인하여 오류 메시지를 확인하세요.
   - `SURICATA_PATH` 환경 변수가 올바르게 설정되었는지 확인하세요.
   - 프로그램을 재시작하세요.

3. **수리카타 규칙 관련 오류**
   - 기본 규칙이 자동으로 생성되지만, 더 많은 규칙이 필요하다면:
     - Windows: Suricata 설치 폴더의 rules 디렉토리에 규칙 파일을 추가하세요.
     - Linux: `/etc/suricata/rules/` 디렉토리에 규칙 파일을 추가하세요.

## 고성능 모드 테스트

수리카타 설치 후:

1. 프로그램을 관리자 권한으로 실행합니다.
2. 모드 선택 메뉴에서 '2. 고성능 모드'를 선택합니다.
3. 프로그램 실행 중 '수리카타 통합 모듈 초기화 완료' 메시지가 표시되는지 확인합니다.
4. 작업 관리자를 통해 메모리 사용량이 경량 모드보다 증가했는지 확인합니다. 