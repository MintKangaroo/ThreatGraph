# ThreatGraph 인수인계

현재 브랜치: `feat/stix-ingestion` (PR 대상 `develop`)

완료: Graph schema/repository, STIX 2.1 importer/exporter, workspace별 원본 보존, Indicator
매핑, 관계별 Evidence, TAXII 비동기 입력 경계, IOC canonical identity·중복 제거·민감 값
마스킹. 세부사항은 [docs/stix.md](docs/stix.md)를 참고합니다.

검증: Python 3.12 Docker 환경에서 ruff, mypy, pytest 43개, 커버리지 100% 통과.

다음 세션은 `develop`에서 `feat/attack-mapping`을 만들고 MITRE ATT&CK STIX 지식 import,
Technique identity, STIX relationship/Sigma 매핑을 구현합니다. 커밋은
`feat(attack): add ATT&CK knowledge mapping`, PR 대상은 `develop`입니다.

브랜치 규칙: `main`은 안정 릴리스, `develop`은 통합, 기능은 `feat/<기능명>`, 수정은
`fix/<문제명>`, 문서는 `docs/<문서명>`입니다. 모든 관계는 동일 workspace의 Evidence를
요구하고 새 query API에는 limit·pagination을 적용합니다.
