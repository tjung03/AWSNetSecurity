# AWS 보안 그룹 인바운드 규칙 점검 예제

AWS CLI `describe-security-groups` JSON을 입력으로 받아 보안 그룹의 인바운드 규칙을 로컬에서 점검하는 예제입니다. IPv4 `0.0.0.0/0` 또는 IPv6 `::/0`에 SSH(22), RDP(3389), 모든 프로토콜을 허용하는 규칙을 찾습니다. 합성 입력을 사용하며 실제 AWS 환경에서 수집하거나 검증한 결과는 포함하지 않습니다.

## 실행

Python 3.12에서 표준 라이브러리만 사용합니다. 예제 입력은 실제 계정에서 가져온 값이 아닌 합성 데이터입니다.

```bash
python3 audit_ingress.py examples/security-groups.json
python3 -m unittest discover -s tests -v
```

예제 입력에는 모든 IPv4 주소에 SSH를 허용하는 그룹 하나와, 특정 사설 주소에만 관리 포트를 허용하는 그룹 하나가 있습니다. 첫 명령은 아래처럼 위험 후보 한 건을 출력하고 종료 코드 `1`을 반환합니다.

```text
sg-example-open: 0.0.0.0/0 permits tcp/22
```

탐지 항목이 없으면 `0`, 파일·JSON 형식 오류가 나면 `2`를 반환합니다. 실제 데이터를 점검하려면 필요한 조회 권한이 있는 환경에서 `aws ec2 describe-security-groups` 결과를 **로컬 파일**로 저장해 입력합니다. 계정 ID, 공인 IP, 보안 그룹 설명 등에 내부 정보가 포함될 수 있으므로 원본 JSON은 공개 저장소에 올리지 않습니다. 이 도구는 AWS에 접속하거나 규칙을 수정하지 않습니다.

## 점검 범위와 한계

| 범위 | 판단 |
|---|---|
| 인바운드 `IpPermissions` | IPv4·IPv6 전체 주소를 소스로 지정한 TCP 22/3389 또는 모든 프로토콜 규칙을 보고합니다. 포트 범위가 22나 3389를 포함해도 보고합니다. |
| 그 밖의 소스 | 특정 CIDR·보안 그룹 참조·프리픽스 목록은 이 점검의 경고 대상이 아닙니다. |
| 아웃바운드와 다른 보안 계층 | `IpPermissionsEgress`, 네트워크 ACL, 라우팅, 인스턴스 연결 상태, OS 방화벽은 분석하지 않습니다. |

결과는 **검토할 규칙 후보**이지 인스턴스가 인터넷에서 실제 도달 가능하다는 증거가 아닙니다. 보안 그룹이 리소스에 연결됐는지, 공개 IP·경로·다른 방어 계층이 무엇인지는 별도로 확인해야 합니다. HTTP/HTTPS 전체 공개 등은 서비스 목적에 따라 달라질 수 있어 이 예제의 고정 경고 항목에 넣지 않았습니다.

입력 구조와 규칙 의미는 AWS의 [CLI `describe-security-groups` 응답](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html) 및 [보안 그룹 규칙](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)을 기준으로 삼았습니다. 실제 적용 정책은 조직의 요구와 현재 서비스 문서를 확인해야 합니다.
