# IOC 정규화

`threatgraph.ioc`는 Domain, IPAddress, URL, Hash를 canonical form으로 바꾸고 stable
identity key를 생성합니다. 같은 workspace에서 표기가 달라도 같은 canonical value는 하나의
identity로 deduplicate할 수 있습니다.

정규화 규칙:

- 도메인: 소문자, 마지막 점 제거, IDNA 변환
- IP: IPv4/IPv6 파싱 후 compressed form
- URL: HTTP(S)만 허용, 호스트 소문자·IDNA, 기본 포트 제거, fragment 제거
- Hash: 지원 길이(MD5/SHA-1/SHA-256/SHA-384/SHA-512)의 hexadecimal만 허용

민감 값 마스킹은 identity에는 영향을 주지 않고 표시 값만 가립니다. 따라서 그래프의
중복 제거와 Evidence 연결은 canonical identity로 유지하면서 UI·로그에는 마스킹 값을
제공할 수 있습니다. 원본 STIX Indicator의 ID가 달라도 같은 IOC 값을 가리키면 동일한
deterministic graph ID와 identity key를 사용합니다.
